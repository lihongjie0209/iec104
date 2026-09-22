package iec104

import (
	"math"
	"reflect"
	"testing"
	"time"
)

func TestWireInformationElementRoundTrip(t *testing.T) {
	t.Parallel()
	timestamp := time.Date(2026, time.September, 23, 6, 7, 8, 9_000_000, time.UTC)
	tests := []struct {
		name   string
		typeID byte
		value  WireInformationObject
	}{
		{"single", 1, WireInformationObject{Value: true, Quality: 0x10}},
		{"double", 3, WireInformationObject{Value: uint8(2), Quality: 0x20}},
		{"step", 5, WireInformationObject{Value: int8(-12), Quality: 0x81, Transient: true}},
		{"bitstring", 7, WireInformationObject{Value: uint32(0x89abcdef), Quality: 0x40}},
		{"normalized", 9, WireInformationObject{Value: int16(-1234), Quality: 0x01}},
		{"scaled", 11, WireInformationObject{Value: int16(2345), Quality: 0x10}},
		{"float", 13, WireInformationObject{Value: float32(12.5), Quality: 0x20}},
		{"total", 15, WireInformationObject{Value: int32(-99), Quality: 0x81}},
		{"single timed", 30, WireInformationObject{Value: false, Quality: 0x40, Timestamp: &timestamp}},
		{"double timed", 31, WireInformationObject{Value: uint8(1), Quality: 0x10, Timestamp: &timestamp}},
		{"step timed", 32, WireInformationObject{Value: int8(63), Timestamp: &timestamp}},
		{"bitstring timed", 33, WireInformationObject{Value: uint32(7), Quality: 0x80, Timestamp: &timestamp}},
		{"normalized timed", 34, WireInformationObject{Value: int16(math.MinInt16), Timestamp: &timestamp}},
		{"scaled timed", 35, WireInformationObject{Value: int16(math.MaxInt16), Quality: 0x10, Timestamp: &timestamp}},
		{"float timed", 36, WireInformationObject{Value: float32(-0.25), Quality: 0x20, Timestamp: &timestamp}},
		{"total timed", 37, WireInformationObject{Value: int32(123456), Quality: 0x41, Timestamp: &timestamp}},
		{"single command", 45, WireInformationObject{Value: true, Qualifier: 7, Select: true}},
		{"double command", 46, WireInformationObject{Value: uint8(2), Qualifier: 3}},
		{"regulating command", 47, WireInformationObject{Value: uint8(1), Qualifier: 1}},
		{"normalized command", 48, WireInformationObject{Value: int16(-123), Qualifier: 2}},
		{"scaled command", 49, WireInformationObject{Value: int16(456), Qualifier: 2}},
		{"float command", 50, WireInformationObject{Value: float32(1.5), Qualifier: 2}},
		{"bitstring command", 51, WireInformationObject{Value: uint32(0x12345678), Qualifier: 2}},
		{"single timed command", 58, WireInformationObject{Value: false, Qualifier: 4, Timestamp: &timestamp}},
		{"double timed command", 59, WireInformationObject{Value: uint8(2), Qualifier: 3, Timestamp: &timestamp}},
		{"regulating timed command", 60, WireInformationObject{Value: uint8(1), Qualifier: 1, Timestamp: &timestamp}},
		{"normalized timed command", 61, WireInformationObject{Value: int16(-123), Qualifier: 2, Timestamp: &timestamp}},
		{"scaled timed command", 62, WireInformationObject{Value: int16(456), Qualifier: 2, Timestamp: &timestamp}},
		{"float timed command", 63, WireInformationObject{Value: float32(1.5), Qualifier: 2, Timestamp: &timestamp}},
		{"bitstring timed command", 64, WireInformationObject{Value: uint32(9), Qualifier: 2, Timestamp: &timestamp}},
		{"end initialization", 70, WireInformationObject{Value: uint8(1)}},
		{"general interrogation", 100, WireInformationObject{Value: uint8(20)}},
		{"counter interrogation", 101, WireInformationObject{Value: uint8(5)}},
		{"read", 102, WireInformationObject{}},
		{"clock synchronization", 103, WireInformationObject{Value: timestamp}},
	}
	for _, tt := range tests {
		test := tt
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			wire, err := EncodeWireInformationElement(test.typeID, test.value)
			if err != nil {
				t.Fatal(err)
			}
			got, consumed, err := DecodeWireInformationElement(test.typeID, wire)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != len(wire) || !reflect.DeepEqual(got, test.value) {
				t.Fatalf("got=%#v consumed=%d want=%#v length=%d", got, consumed, test.value, len(wire))
			}
		})
	}
}

func TestWireCP56Time2aRejectsMalformedValues(t *testing.T) {
	t.Parallel()
	for _, value := range []time.Time{
		time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if _, err := EncodeWireCP56Time2a(value); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	for _, wire := range [][]byte{
		nil,
		{0, 0, 0x80, 0, 1, 1, 26},
		{0x60, 0xea, 0, 0, 1, 1, 26},
		{0, 0, 60, 0, 1, 1, 26},
		{0, 0, 0, 24, 1, 1, 26},
		{0, 0, 0, 0, 31, 2, 26},
	} {
		if _, err := DecodeWireCP56Time2a(wire); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
}

func TestWireInformationElementRejectsMalformedValues(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		typeID byte
		value  WireInformationObject
	}{
		{1, WireInformationObject{Value: uint8(1)}},
		{3, WireInformationObject{Value: uint8(4)}},
		{5, WireInformationObject{Value: int8(-65)}},
		{13, WireInformationObject{Value: float32(math.NaN())}},
		{30, WireInformationObject{Value: true}},
		{50, WireInformationObject{Value: float32(math.Inf(1))}},
		{99, WireInformationObject{}},
	} {
		if _, err := EncodeWireInformationElement(test.typeID, test.value); err == nil {
			t.Fatalf("accepted type=%d value=%#v", test.typeID, test.value)
		}
	}
	for _, typeID := range []byte{1, 5, 13, 30, 103, 99} {
		if _, _, err := DecodeWireInformationElement(typeID, nil); err == nil {
			t.Fatalf("accepted truncated type %d", typeID)
		}
	}
}
