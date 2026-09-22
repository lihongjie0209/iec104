package iec104

import (
	"reflect"
	"testing"
)

func TestWireTypedASDURoundTrip(t *testing.T) {
	t.Parallel()
	for _, value := range []WireTypedASDU{
		{
			TypeID: 1, Cause: 3, Originator: 2, CommonAddress: 17,
			Objects: []WireInformationObject{
				{Address: 0x123456, Value: true, Quality: 0x10},
				{Address: 0x654321, Value: false, Quality: 0x20},
			},
		},
		{
			TypeID: 3, Sequence: true, Cause: 20, Negative: true, Test: true, CommonAddress: 1,
			Objects: []WireInformationObject{
				{Address: 100, Value: uint8(1)},
				{Address: 101, Value: uint8(2)},
				{Address: 102, Value: uint8(3)},
			},
		},
	} {
		value := value
		wire, err := EncodeWireTypedASDU(value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeWireTypedASDU(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, value) {
			t.Fatalf("got=%#v want=%#v", got, value)
		}
	}
}

func TestWireTypedASDURejectsMalformedObjects(t *testing.T) {
	t.Parallel()
	for _, value := range []WireTypedASDU{
		{},
		{TypeID: 1, Objects: []WireInformationObject{{Address: 0x1000000, Value: true}}},
		{TypeID: 1, Sequence: true, Objects: []WireInformationObject{{Address: 1, Value: true}, {Address: 3, Value: false}}},
	} {
		if _, err := EncodeWireTypedASDU(value); err == nil {
			t.Fatalf("accepted %#v", value)
		}
	}
	for _, wire := range [][]byte{
		{1, 1, 3, 0, 1, 0, 1, 2},
		{1, 1, 3, 0, 1, 0, 1, 0, 0, 1, 0xff},
		{1, 2, 3, 0, 1, 0, 1, 0, 0, 1},
	} {
		if _, err := DecodeWireTypedASDU(wire); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
}
