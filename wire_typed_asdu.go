package iec104

import (
	"errors"
	"fmt"
)

const maximumWireInformationObjectAddress = 0xffffff

// WireTypedASDU is a complete ASDU whose information elements are represented
// as typed values rather than an opaque payload.
type WireTypedASDU struct {
	TypeID        byte
	Sequence      bool
	Cause         byte
	Negative      bool
	Test          bool
	Originator    byte
	CommonAddress uint16
	Objects       []WireInformationObject
}

// EncodeWireTypedASDU encodes a complete ASDU, including SQ or explicit
// information-object addressing.
func EncodeWireTypedASDU(value WireTypedASDU) ([]byte, error) {
	if len(value.Objects) == 0 || len(value.Objects) > 127 {
		return nil, errors.New("IEC 104 ASDU must contain 1..127 objects")
	}
	payload := make([]byte, 0)
	var firstAddress uint32
	for index, object := range value.Objects {
		if object.Address > maximumWireInformationObjectAddress {
			return nil, errors.New("IEC 104 information object address exceeds 24 bits")
		}
		if value.Sequence {
			if index == 0 {
				firstAddress = object.Address
				payload = appendWireInformationObjectAddress(payload, object.Address)
			} else if object.Address != firstAddress+uint32(index) {
				return nil, errors.New("IEC 104 sequential object addresses must be contiguous")
			}
		} else {
			payload = appendWireInformationObjectAddress(payload, object.Address)
		}
		encoded, err := EncodeWireInformationElement(value.TypeID, object)
		if err != nil {
			return nil, fmt.Errorf("encoding IEC 104 object %d: %w", index, err)
		}
		payload = append(payload, encoded...)
	}
	return EncodeWireASDU(WireASDU{
		TypeID:        value.TypeID,
		Sequence:      value.Sequence,
		ObjectCount:   uint8(len(value.Objects)),
		Cause:         value.Cause,
		Negative:      value.Negative,
		Test:          value.Test,
		Originator:    value.Originator,
		CommonAddress: value.CommonAddress,
		Payload:       payload,
	})
}

// DecodeWireTypedASDU strictly decodes a complete ASDU and rejects trailing,
// truncated, unsupported, and overflowing information objects.
func DecodeWireTypedASDU(data []byte) (WireTypedASDU, error) {
	wire, err := DecodeWireASDU(data)
	if err != nil {
		return WireTypedASDU{}, err
	}
	value := WireTypedASDU{
		TypeID:        wire.TypeID,
		Sequence:      wire.Sequence,
		Cause:         wire.Cause,
		Negative:      wire.Negative,
		Test:          wire.Test,
		Originator:    wire.Originator,
		CommonAddress: wire.CommonAddress,
		Objects:       make([]WireInformationObject, 0, wire.ObjectCount),
	}
	offset := 0
	var firstAddress uint32
	for index := 0; index < int(wire.ObjectCount); index++ {
		if !wire.Sequence || index == 0 {
			if offset+3 > len(wire.Payload) {
				return WireTypedASDU{}, errors.New("truncated IEC 104 information object address")
			}
			firstAddress = decodeWireInformationObjectAddress(wire.Payload[offset : offset+3])
			offset += 3
		}
		object, consumed, err := DecodeWireInformationElement(wire.TypeID, wire.Payload[offset:])
		if err != nil {
			return WireTypedASDU{}, fmt.Errorf("decoding IEC 104 object %d: %w", index, err)
		}
		object.Address = firstAddress
		if wire.Sequence {
			object.Address += uint32(index)
		}
		if object.Address > maximumWireInformationObjectAddress {
			return WireTypedASDU{}, errors.New("IEC 104 sequential address exceeds 24 bits")
		}
		value.Objects = append(value.Objects, object)
		offset += consumed
	}
	if offset != len(wire.Payload) {
		return WireTypedASDU{}, errors.New("IEC 104 ASDU contains trailing bytes")
	}
	return value, nil
}

func appendWireInformationObjectAddress(data []byte, address uint32) []byte {
	return append(data, byte(address), byte(address>>8), byte(address>>16))
}

func decodeWireInformationObjectAddress(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
}
