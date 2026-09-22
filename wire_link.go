package iec104

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	// ErrWireLinkClosed reports that a link no longer accepts operations.
	ErrWireLinkClosed = errors.New("IEC 104 link is closed")
	// ErrWireLinkInactive reports an attempted ASDU send before STARTDT.
	ErrWireLinkInactive = errors.New("IEC 104 data transfer is not active")
	// ErrWireLinkBackpressure reports a full internal control-event queue.
	ErrWireLinkBackpressure = errors.New("IEC 104 link control-event backpressure")
)

// WireLinkOptions configures IEC 60870-5-104 acknowledgement and idle timers
// and the send and receive windows.
type WireLinkOptions struct {
	T1 time.Duration
	T2 time.Duration
	T3 time.Duration
	K  int
	W  int
}

// WireLinkStats is an instantaneous concurrency-safe link snapshot.
type WireLinkStats struct {
	SendSequence          uint16
	ReceiveSequence       uint16
	AcknowledgedSequence  uint16
	UnacknowledgedReceive int
	Active                bool
	Closed                bool
}

// WireLink owns one already-established IEC 104 TCP connection.
type WireLink struct {
	conn      net.Conn
	server    bool
	options   WireLinkOptions
	handler   func(context.Context, WireTypedASDU) error
	onActive  func(bool)
	ctx       context.Context
	cancel    context.CancelFunc
	writeMu   sync.Mutex
	sendMu    sync.Mutex
	mu        sync.Mutex
	sendSeq   uint16
	recvSeq   uint16
	ackedSeq  uint16
	unackedRx int
	firstTx   time.Time
	firstRx   time.Time
	lastRx    time.Time
	testSent  time.Time
	active    bool
	closed    bool
	wake      chan struct{}
	uEvents   chan byte
	startOnce sync.Once
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

// NewWireLink validates the link options and takes ownership of conn. Start
// launches processing; client links then call Activate to complete STARTDT.
func NewWireLink(parent context.Context, conn net.Conn, server bool, options WireLinkOptions, handler func(context.Context, WireTypedASDU) error, onActive func(bool)) (*WireLink, error) {
	if parent == nil {
		return nil, errors.New("IEC 104 link parent context is nil")
	}
	if conn == nil {
		return nil, errors.New("IEC 104 link connection is nil")
	}
	if options.T1 <= 0 || options.T2 <= 0 || options.T3 <= 0 {
		return nil, errors.New("IEC 104 link timers must be positive")
	}
	if options.K < 1 || options.K > 0x7fff || options.W < 1 || options.W > 0x7fff {
		return nil, errors.New("IEC 104 link windows must be between 1 and 32767")
	}
	ctx, cancel := context.WithCancel(parent)
	return &WireLink{
		conn: conn, server: server, options: options, handler: handler,
		onActive: onActive, ctx: ctx, cancel: cancel, lastRx: time.Now(),
		wake: make(chan struct{}, 1), uEvents: make(chan byte, 8),
	}, nil
}

// Start launches the reader and timer workers once.
func (link *WireLink) Start() {
	link.startOnce.Do(func() {
		link.wg.Add(2)
		go link.readLoop()
		go link.timerLoop()
	})
}

// Activate sends STARTDT activation and waits for confirmation on a client
// link.
func (link *WireLink) Activate(ctx context.Context) error {
	if link.server {
		return errors.New("IEC 104 server links cannot initiate STARTDT")
	}
	frame, err := EncodeWireFrame(WireFrame{Kind: WireFrameU, Function: WireUStartActivation})
	if err != nil {
		return err
	}
	if err := link.writeFrame(ctx, frame); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-link.ctx.Done():
			return link.closedError()
		case event := <-link.uEvents:
			if event == WireUStartConfirmation {
				link.setActive(true)
				return nil
			}
		}
	}
}

// Send transmits one typed ASDU after STARTDT and waits for K-window capacity.
func (link *WireLink) Send(ctx context.Context, asdu WireTypedASDU) error {
	link.sendMu.Lock()
	defer link.sendMu.Unlock()
	encoded, err := EncodeWireTypedASDU(asdu)
	if err != nil {
		return err
	}
	for {
		link.mu.Lock()
		if link.closed {
			link.mu.Unlock()
			return link.closedError()
		}
		if !link.active {
			link.mu.Unlock()
			return ErrWireLinkInactive
		}
		outstanding := WireSequenceDistance(link.ackedSeq, link.sendSeq)
		if outstanding < link.options.K {
			send, receive := link.sendSeq, link.recvSeq
			link.sendSeq = NextWireSequence(link.sendSeq)
			if outstanding == 0 {
				link.firstTx = time.Now()
			}
			link.mu.Unlock()
			frame, frameErr := EncodeWireFrame(WireFrame{
				Kind: WireFrameI, SendSequence: send, ReceiveSequence: receive, ASDU: encoded,
			})
			if frameErr != nil {
				return frameErr
			}
			if err := link.writeFrame(ctx, frame); err != nil {
				link.stop(err)
				return err
			}
			return nil
		}
		link.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-link.ctx.Done():
			return link.closedError()
		case <-link.wake:
		}
	}
}

// Stats returns current sequence, window, and lifecycle state.
func (link *WireLink) Stats() WireLinkStats {
	link.mu.Lock()
	defer link.mu.Unlock()
	return WireLinkStats{
		SendSequence: link.sendSeq, ReceiveSequence: link.recvSeq,
		AcknowledgedSequence: link.ackedSeq, UnacknowledgedReceive: link.unackedRx,
		Active: link.active, Closed: link.closed,
	}
}

// Done is closed when the link reaches its terminal state.
func (link *WireLink) Done() <-chan struct{} {
	return link.ctx.Done()
}

func (link *WireLink) readLoop() {
	defer link.wg.Done()
	for {
		frame, err := ReadWireFrame(link.ctx, link.conn)
		if err != nil {
			link.stop(err)
			return
		}
		link.mu.Lock()
		link.lastRx = time.Now()
		link.testSent = time.Time{}
		link.mu.Unlock()
		switch frame.Kind {
		case WireFrameI:
			err = link.handleIFrame(frame)
		case WireFrameS:
			err = link.acknowledge(frame.ReceiveSequence)
		case WireFrameU:
			err = link.handleUFrame(frame.Function)
		default:
			err = errors.New("unknown IEC 104 frame kind")
		}
		if err != nil {
			link.stop(err)
			return
		}
	}
}

func (link *WireLink) handleIFrame(frame WireFrame) error {
	if err := link.acknowledge(frame.ReceiveSequence); err != nil {
		return err
	}
	link.mu.Lock()
	if !link.active {
		link.mu.Unlock()
		return errors.New("IEC 104 I frame received while data transfer is inactive")
	}
	if frame.SendSequence != link.recvSeq {
		expected := link.recvSeq
		link.mu.Unlock()
		return fmt.Errorf("IEC 104 receive sequence mismatch: got %d want %d", frame.SendSequence, expected)
	}
	link.recvSeq = NextWireSequence(link.recvSeq)
	if link.unackedRx == 0 {
		link.firstRx = time.Now()
	}
	link.unackedRx++
	receive := link.recvSeq
	ackNow := link.unackedRx >= link.options.W
	if ackNow {
		link.unackedRx = 0
		link.firstRx = time.Time{}
	}
	link.mu.Unlock()
	if ackNow {
		frame, err := EncodeWireFrame(WireFrame{Kind: WireFrameS, ReceiveSequence: receive})
		if err != nil {
			return err
		}
		if err := link.writeFrame(link.ctx, frame); err != nil {
			return err
		}
	}
	asdu, err := DecodeWireTypedASDU(frame.ASDU)
	if err != nil {
		return err
	}
	if link.handler != nil {
		return link.handler(link.ctx, asdu)
	}
	return nil
}

func (link *WireLink) handleUFrame(function byte) error {
	switch function {
	case WireUStartActivation:
		if !link.server {
			return errors.New("IEC 104 client received unexpected STARTDT activation")
		}
		if err := link.writeUFrame(WireUStartConfirmation); err != nil {
			return err
		}
		link.setActive(true)
	case WireUStartConfirmation:
		if link.server {
			return errors.New("IEC 104 server received unexpected STARTDT confirmation")
		}
		select {
		case link.uEvents <- function:
		default:
			return ErrWireLinkBackpressure
		}
	case WireUStopActivation:
		if err := link.writeUFrame(WireUStopConfirmation); err != nil {
			return err
		}
		link.setActive(false)
	case WireUStopConfirmation:
		link.setActive(false)
		select {
		case link.uEvents <- function:
		default:
		}
	case WireUTestActivation:
		return link.writeUFrame(WireUTestConfirmation)
	case WireUTestConfirmation:
		select {
		case link.uEvents <- function:
		default:
		}
	default:
		return errors.New("unsupported IEC 104 U frame")
	}
	return nil
}

func (link *WireLink) writeUFrame(function byte) error {
	frame, err := EncodeWireFrame(WireFrame{Kind: WireFrameU, Function: function})
	if err != nil {
		return err
	}
	return link.writeFrame(link.ctx, frame)
}

func (link *WireLink) acknowledge(receiveSequence uint16) error {
	link.mu.Lock()
	defer link.mu.Unlock()
	outstanding := WireSequenceDistance(link.ackedSeq, link.sendSeq)
	advance := WireSequenceDistance(link.ackedSeq, receiveSequence)
	if advance > outstanding {
		return fmt.Errorf("IEC 104 acknowledgement %d exceeds sent sequence %d", receiveSequence, link.sendSeq)
	}
	if advance == 0 {
		return nil
	}
	link.ackedSeq = receiveSequence
	if receiveSequence == link.sendSeq {
		link.firstTx = time.Time{}
	} else {
		link.firstTx = time.Now()
	}
	link.signalWake()
	return nil
}

func (link *WireLink) timerLoop() {
	defer link.wg.Done()
	interval := minimumWireDuration(link.options.T1, link.options.T2, link.options.T3) / 4
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	if interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-link.ctx.Done():
			return
		case now := <-ticker.C:
			link.mu.Lock()
			if !link.firstTx.IsZero() && now.Sub(link.firstTx) >= link.options.T1 {
				link.mu.Unlock()
				link.stop(errors.New("IEC 104 T1 acknowledgement timeout"))
				return
			}
			if link.unackedRx > 0 && now.Sub(link.firstRx) >= link.options.T2 {
				receive := link.recvSeq
				link.unackedRx = 0
				link.firstRx = time.Time{}
				link.mu.Unlock()
				frame, err := EncodeWireFrame(WireFrame{Kind: WireFrameS, ReceiveSequence: receive})
				if err == nil {
					err = link.writeFrame(link.ctx, frame)
				}
				if err != nil {
					link.stop(err)
					return
				}
				continue
			}
			if link.testSent.IsZero() && now.Sub(link.lastRx) >= link.options.T3 {
				link.testSent = now
				link.mu.Unlock()
				if err := link.writeUFrame(WireUTestActivation); err != nil {
					link.stop(err)
					return
				}
				continue
			}
			if !link.testSent.IsZero() && now.Sub(link.testSent) >= link.options.T1 {
				link.mu.Unlock()
				link.stop(errors.New("IEC 104 TESTFR confirmation timeout"))
				return
			}
			link.mu.Unlock()
		}
	}
}

func (link *WireLink) setActive(active bool) {
	link.mu.Lock()
	changed := link.active != active
	link.active = active
	link.mu.Unlock()
	if changed && link.onActive != nil {
		link.onActive(active)
	}
}

func (link *WireLink) writeFrame(ctx context.Context, frame []byte) error {
	link.writeMu.Lock()
	defer link.writeMu.Unlock()
	deadline := time.Now().Add(link.options.T1)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := link.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	defer func() { _ = link.conn.SetWriteDeadline(time.Time{}) }()
	for written := 0; written < len(frame); {
		count, err := link.conn.Write(frame[written:])
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrUnexpectedEOF
		}
		written += count
	}
	return nil
}

func (link *WireLink) stop(cause error) {
	link.closeOnce.Do(func() {
		link.mu.Lock()
		link.closed = true
		link.closeErr = cause
		wasActive := link.active
		link.active = false
		link.mu.Unlock()
		link.cancel()
		_ = link.conn.Close()
		link.signalWake()
		if wasActive && link.onActive != nil {
			link.onActive(false)
		}
	})
}

// Stop initiates non-blocking terminal shutdown with the supplied cause.
// Close should be used afterwards when the caller must join link workers.
func (link *WireLink) Stop(cause error) {
	if cause == nil {
		cause = ErrWireLinkClosed
	}
	link.stop(cause)
}

// Close cancels the link, closes its connection, and joins started workers.
func (link *WireLink) Close(ctx context.Context) error {
	link.stop(ErrWireLinkClosed)
	done := make(chan struct{})
	go func() {
		link.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Err returns the terminal link cause, if any.
func (link *WireLink) Err() error {
	link.mu.Lock()
	defer link.mu.Unlock()
	return link.closeErr
}

func (link *WireLink) closedError() error {
	link.mu.Lock()
	cause := link.closeErr
	link.mu.Unlock()
	if cause == nil || errors.Is(cause, context.Canceled) || errors.Is(cause, net.ErrClosed) || errors.Is(cause, io.EOF) {
		return ErrWireLinkClosed
	}
	return cause
}

func (link *WireLink) signalWake() {
	select {
	case link.wake <- struct{}{}:
	default:
	}
}

// ReadWireFrame reads and strictly decodes one complete APDU from conn.
func ReadWireFrame(ctx context.Context, conn net.Conn) (WireFrame, error) {
	header := make([]byte, 2)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	if _, err := io.ReadFull(conn, header); err != nil {
		return WireFrame{}, err
	}
	if header[0] != startByte || header[1] < 4 || header[1] > 253 {
		return WireFrame{}, errors.New("invalid IEC 104 APDU header")
	}
	data := make([]byte, int(header[1])+2)
	copy(data, header)
	if _, err := io.ReadFull(conn, data[2:]); err != nil {
		return WireFrame{}, err
	}
	return DecodeWireFrame(data)
}

// NextWireSequence increments one 15-bit sequence number with wraparound.
func NextWireSequence(sequence uint16) uint16 {
	return (sequence + 1) & 0x7fff
}

// WireSequenceDistance returns the forward 15-bit modular distance.
func WireSequenceDistance(from, to uint16) int {
	return int((to - from) & 0x7fff)
}

func minimumWireDuration(first, second, third time.Duration) time.Duration {
	result := first
	if second < result {
		result = second
	}
	if third < result {
		result = third
	}
	return result
}
