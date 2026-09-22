package iec104

import (
	"bytes"
	"reflect"
	"testing"
)

func TestWireASDUCodec(t *testing.T) {
	want := WireASDU{TypeID: 1, Sequence: true, ObjectCount: 2, Cause: 3,
		Negative: true, Test: true, Originator: 4, CommonAddress: 0x1234,
		Payload: []byte{1, 2, 3, 4},
	}
	wire, err := EncodeWireASDU(want)
	if err != nil {
		t.Fatal(err)
	}
	wantWire := []byte{1, 0x82, 0xc3, 4, 0x34, 0x12, 1, 2, 3, 4}
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("wire=%x want=%x", wire, wantWire)
	}
	got, err := DecodeWireASDU(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
	wire[6] = 0xff
	if got.Payload[0] != 1 {
		t.Fatal("decoded payload aliases input")
	}
}

func TestWireASDURejectsMalformed(t *testing.T) {
	for _, wire := range [][]byte{{}, {1, 1, 3, 0, 1, 0}, {1, 0, 3, 0, 1, 0, 0}} {
		if _, err := DecodeWireASDU(wire); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
	for _, value := range []WireASDU{
		{}, {ObjectCount: 128, Payload: []byte{1}}, {ObjectCount: 1, Cause: 64, Payload: []byte{1}},
		{ObjectCount: 1}, {ObjectCount: 1, Payload: make([]byte, 244)},
	} {
		if _, err := EncodeWireASDU(value); err == nil {
			t.Fatalf("accepted %+v", value)
		}
	}
}
