package iec104

import (
	"encoding/binary"
	"errors"
)

// WireASDU is the strict transport-facing ASDU envelope. Payload contains the
// encoded information objects following the six-byte identifier.
type WireASDU struct {
	TypeID        byte
	Sequence      bool
	ObjectCount   uint8
	Cause         byte
	Negative      bool
	Test          bool
	Originator    byte
	CommonAddress uint16
	Payload       []byte
}

// EncodeWireASDU encodes an ASDU identifier and opaque information objects.
func EncodeWireASDU(value WireASDU) ([]byte, error) {
	if value.ObjectCount == 0 || value.ObjectCount > 127 {
		return nil, errors.New("IEC 104 ASDU object count must be 1..127")
	}
	if value.Cause > 63 {
		return nil, errors.New("IEC 104 cause must be 0..63")
	}
	if len(value.Payload) == 0 || len(value.Payload) > 243 {
		return nil, errors.New("IEC 104 ASDU payload length is invalid")
	}
	wire := make([]byte, 6+len(value.Payload))
	wire[0] = value.TypeID
	wire[1] = value.ObjectCount
	if value.Sequence {
		wire[1] |= 0x80
	}
	wire[2] = value.Cause
	if value.Negative {
		wire[2] |= 0x40
	}
	if value.Test {
		wire[2] |= 0x80
	}
	wire[3] = value.Originator
	binary.LittleEndian.PutUint16(wire[4:6], value.CommonAddress)
	copy(wire[6:], value.Payload)
	return wire, nil
}

// DecodeWireASDU decodes the fixed ASDU identifier and owns its payload.
func DecodeWireASDU(wire []byte) (WireASDU, error) {
	if len(wire) < 7 || len(wire) > 249 {
		return WireASDU{}, errors.New("invalid IEC 104 ASDU length")
	}
	count := wire[1] & 0x7f
	if count == 0 {
		return WireASDU{}, errors.New("IEC 104 ASDU object count is zero")
	}
	return WireASDU{
		TypeID: wire[0], Sequence: wire[1]&0x80 != 0, ObjectCount: count,
		Cause: wire[2] & 0x3f, Negative: wire[2]&0x40 != 0, Test: wire[2]&0x80 != 0,
		Originator: wire[3], CommonAddress: binary.LittleEndian.Uint16(wire[4:6]),
		Payload: append([]byte(nil), wire[6:]...),
	}, nil
}
