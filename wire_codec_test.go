package iec104

import (
	"bytes"
	"testing"
)

func TestWireFrameCodec(t *testing.T) {
	tests := []struct {
		name  string
		frame WireFrame
		wire  []byte
	}{
		{name: "I", frame: WireFrame{Kind: WireFrameI, SendSequence: 3, ReceiveSequence: 1, ASDU: []byte{1, 1, 3, 0, 1, 0, 0}},
			wire: []byte{0x68, 11, 6, 0, 2, 0, 1, 1, 3, 0, 1, 0, 0}},
		{name: "S", frame: WireFrame{Kind: WireFrameS, ReceiveSequence: 1},
			wire: []byte{0x68, 4, 1, 0, 2, 0}},
		{name: "U", frame: WireFrame{Kind: WireFrameU, Function: WireUStartActivation},
			wire: []byte{0x68, 4, 7, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := EncodeWireFrame(tt.frame)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, tt.wire) {
				t.Fatalf("wire=%x want=%x", wire, tt.wire)
			}
			decoded, err := DecodeWireFrame(wire)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Kind != tt.frame.Kind || decoded.SendSequence != tt.frame.SendSequence ||
				decoded.ReceiveSequence != tt.frame.ReceiveSequence || decoded.Function != tt.frame.Function ||
				!bytes.Equal(decoded.ASDU, tt.frame.ASDU) {
				t.Fatalf("decoded=%+v want=%+v", decoded, tt.frame)
			}
		})
	}
}

func TestDecodeWireFrameRejectsMalformed(t *testing.T) {
	tests := [][]byte{
		{}, {0x68, 4, 1}, {0x67, 4, 1, 0, 0, 0}, {0x68, 5, 1, 0, 0, 0},
		{0x68, 4, 0, 0, 0, 0}, {0x68, 4, 1, 1, 0, 0},
		{0x68, 4, 3, 0, 0, 0}, {0x68, 4, 0xff, 0, 0, 0},
	}
	for _, wire := range tests {
		if _, err := DecodeWireFrame(wire); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
}
