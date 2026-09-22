package iec104

import (
	"encoding/binary"
	"errors"
)

// WireFrameKind identifies one IEC 104 APCI frame format.
type WireFrameKind uint8

const (
	WireFrameUnknown WireFrameKind = iota
	WireFrameI
	WireFrameS
	WireFrameU
)

const (
	WireUStartActivation   byte = 0x07
	WireUStartConfirmation byte = 0x0b
	WireUStopActivation    byte = 0x13
	WireUStopConfirmation  byte = 0x23
	WireUTestActivation    byte = 0x43
	WireUTestConfirmation  byte = 0x83
)

// WireFrame is the strict, transport-facing representation of one APDU.
type WireFrame struct {
	Kind            WireFrameKind
	SendSequence    uint16
	ReceiveSequence uint16
	Function        byte
	ASDU            []byte
}

// EncodeWireFrame encodes one complete APDU including start and length bytes.
func EncodeWireFrame(frame WireFrame) ([]byte, error) {
	if frame.SendSequence > 0x7fff || frame.ReceiveSequence > 0x7fff {
		return nil, errors.New("IEC 104 sequence number exceeds 32767")
	}
	switch frame.Kind {
	case WireFrameI:
		if len(frame.ASDU) < AsduHeaderLen || len(frame.ASDU) > 249 {
			return nil, errors.New("IEC 104 I frame requires a 6..249 byte ASDU")
		}
		wire := make([]byte, 6+len(frame.ASDU))
		wire[0], wire[1] = startByte, byte(4+len(frame.ASDU))
		binary.LittleEndian.PutUint16(wire[2:4], frame.SendSequence<<1)
		binary.LittleEndian.PutUint16(wire[4:6], frame.ReceiveSequence<<1)
		copy(wire[6:], frame.ASDU)
		return wire, nil
	case WireFrameS:
		if len(frame.ASDU) != 0 || frame.SendSequence != 0 || frame.Function != 0 {
			return nil, errors.New("invalid IEC 104 S frame fields")
		}
		wire := []byte{startByte, 4, 1, 0, 0, 0}
		binary.LittleEndian.PutUint16(wire[4:], frame.ReceiveSequence<<1)
		return wire, nil
	case WireFrameU:
		if len(frame.ASDU) != 0 || frame.SendSequence != 0 || frame.ReceiveSequence != 0 || !validWireUFunction(frame.Function) {
			return nil, errors.New("invalid IEC 104 U frame fields")
		}
		return []byte{startByte, 4, frame.Function, 0, 0, 0}, nil
	default:
		return nil, errors.New("unknown IEC 104 frame kind")
	}
}

// DecodeWireFrame strictly decodes one complete APDU and owns its ASDU bytes.
func DecodeWireFrame(wire []byte) (WireFrame, error) {
	if len(wire) < 6 || wire[0] != startByte || wire[1] < 4 || wire[1] > 253 || int(wire[1])+2 != len(wire) {
		return WireFrame{}, errors.New("invalid IEC 104 APDU framing")
	}
	control := wire[2:6]
	if control[0]&1 == 0 {
		sendRaw := binary.LittleEndian.Uint16(control[:2])
		receiveRaw := binary.LittleEndian.Uint16(control[2:])
		if sendRaw&1 != 0 || receiveRaw&1 != 0 || len(wire)-6 < AsduHeaderLen {
			return WireFrame{}, errors.New("invalid IEC 104 I frame")
		}
		return WireFrame{Kind: WireFrameI, SendSequence: sendRaw >> 1,
			ReceiveSequence: receiveRaw >> 1, ASDU: append([]byte(nil), wire[6:]...)}, nil
	}
	if control[0]&3 == 1 {
		if control[0] != 1 || control[1] != 0 || binary.LittleEndian.Uint16(control[2:])&1 != 0 || len(wire) != 6 {
			return WireFrame{}, errors.New("invalid IEC 104 S frame")
		}
		return WireFrame{Kind: WireFrameS, ReceiveSequence: binary.LittleEndian.Uint16(control[2:]) >> 1}, nil
	}
	if control[0]&3 == 3 {
		if len(wire) != 6 || control[1] != 0 || control[2] != 0 || control[3] != 0 || !validWireUFunction(control[0]) {
			return WireFrame{}, errors.New("invalid IEC 104 U frame")
		}
		return WireFrame{Kind: WireFrameU, Function: control[0]}, nil
	}
	return WireFrame{}, errors.New("unknown IEC 104 frame kind")
}

func validWireUFunction(value byte) bool {
	switch value {
	case WireUStartActivation, WireUStartConfirmation, WireUStopActivation,
		WireUStopConfirmation, WireUTestActivation, WireUTestConfirmation:
		return true
	default:
		return false
	}
}
