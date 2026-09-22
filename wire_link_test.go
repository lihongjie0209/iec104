package iec104

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestWireLinkSTARTDTAndBidirectionalASDU(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	options := WireLinkOptions{T1: time.Second, T2: 50 * time.Millisecond, T3: time.Hour, K: 12, W: 1}
	clientData := make(chan WireTypedASDU, 1)
	serverData := make(chan WireTypedASDU, 1)
	clientActive := make(chan bool, 2)
	serverActive := make(chan bool, 2)
	client, err := NewWireLink(context.Background(), clientConn, false, options, func(_ context.Context, asdu WireTypedASDU) error {
		clientData <- asdu
		return nil
	}, func(active bool) { clientActive <- active })
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWireLink(context.Background(), serverConn, true, options, func(_ context.Context, asdu WireTypedASDU) error {
		serverData <- asdu
		return nil
	}, func(active bool) { serverActive <- active })
	if err != nil {
		t.Fatal(err)
	}
	client.Start()
	server.Start()
	defer closeWireTestLinks(t, client, server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	assertWireActiveEvent(t, ctx, clientActive)
	assertWireActiveEvent(t, ctx, serverActive)
	fromClient := WireTypedASDU{TypeID: 100, Cause: 6, CommonAddress: 1, Objects: []WireInformationObject{{Value: uint8(20)}}}
	if err := client.Send(ctx, fromClient); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-serverData:
		if actual.TypeID != 100 || actual.CommonAddress != 1 {
			t.Fatalf("ASDU=%#v", actual)
		}
	case <-ctx.Done():
		t.Fatal("server did not receive ASDU")
	}
	fromServer := WireTypedASDU{TypeID: 1, Cause: 3, CommonAddress: 1, Objects: []WireInformationObject{{Address: 7, Value: true}}}
	if err := server.Send(ctx, fromServer); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-clientData:
		if actual.TypeID != 1 || actual.Objects[0].Value != true {
			t.Fatalf("ASDU=%#v", actual)
		}
	case <-ctx.Done():
		t.Fatal("client did not receive ASDU")
	}
}

func TestWireLinkT2AcknowledgesBelowWindow(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	options := WireLinkOptions{T1: time.Second, T2: 20 * time.Millisecond, T3: time.Hour, K: 12, W: 8}
	client, err := NewWireLink(context.Background(), clientConn, false, options, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWireLink(context.Background(), serverConn, true, options, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Start()
	server.Start()
	defer closeWireTestLinks(t, client, server)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.Send(ctx, WireTypedASDU{TypeID: 100, Cause: 6, CommonAddress: 1, Objects: []WireInformationObject{{Value: uint8(20)}}}); err != nil {
		t.Fatal(err)
	}
	for {
		if client.Stats().AcknowledgedSequence == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("stats=%#v", client.Stats())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestWireLinkSequenceHelpers(t *testing.T) {
	t.Parallel()
	if next := NextWireSequence(0x7fff); next != 0 {
		t.Fatalf("next=%d", next)
	}
	if distance := WireSequenceDistance(0x7ffe, 1); distance != 3 {
		t.Fatalf("distance=%d", distance)
	}
}

func TestWireLinkRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	for _, options := range []WireLinkOptions{
		{},
		{T1: time.Second, T2: time.Second, T3: time.Second, K: 0, W: 1},
		{T1: time.Second, T2: time.Second, T3: time.Second, K: 1, W: 0},
	} {
		left, right := net.Pipe()
		_, err := NewWireLink(context.Background(), left, false, options, nil, nil)
		_ = left.Close()
		_ = right.Close()
		if err == nil {
			t.Fatalf("accepted %#v", options)
		}
	}
}

func assertWireActiveEvent(t *testing.T, ctx context.Context, events <-chan bool) {
	t.Helper()
	select {
	case active := <-events:
		if !active {
			t.Fatal("link was not activated")
		}
	case <-ctx.Done():
		t.Fatal("activation callback missing")
	}
}

func closeWireTestLinks(t *testing.T, links ...*WireLink) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, link := range links {
		if err := link.Close(ctx); err != nil {
			t.Errorf("close link: %v", err)
		}
		select {
		case <-link.Done():
		default:
			t.Error("link Done channel is still open after Close")
		}
	}
}
