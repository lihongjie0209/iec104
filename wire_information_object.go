package iec104

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// WireInformationObject is the typed value portion of an IEC 60870-5-104
// information object. The three-byte information-object address is encoded by
// the containing ASDU because SQ addressing can omit it.
type WireInformationObject struct {
	Value     any
	Quality   byte
	Qualifier byte
	Select    bool
	Transient bool
	Timestamp *time.Time
}

// EncodeWireInformationElement encodes the value portion for a supported ASDU
// type. It does not include the information-object address.
func EncodeWireInformationElement(typeID byte, object WireInformationObject) ([]byte, error) {
	baseType, timed := wireInformationBaseType(typeID)
	var data []byte
	switch baseType {
	case 1:
		value, ok := object.Value.(bool)
		if !ok {
			return nil, errors.New("single point value must be boolean")
		}
		encoded := object.Quality & 0xf0
		if value {
			encoded |= 1
		}
		data = []byte{encoded}
	case 3:
		value, ok := object.Value.(uint8)
		if !ok || value > 3 {
			return nil, errors.New("double point value must be between 0 and 3")
		}
		data = []byte{object.Quality&0xf0 | value}
	case 5:
		value, ok := object.Value.(int8)
		if !ok || value < -64 || value > 63 {
			return nil, errors.New("step position value must be between -64 and 63")
		}
		encoded := byte(value) & 0x7f
		if object.Transient {
			encoded |= 0x80
		}
		data = []byte{encoded, object.Quality}
	case 7:
		value, ok := object.Value.(uint32)
		if !ok {
			return nil, errors.New("bitstring value must be uint32")
		}
		data = make([]byte, 5)
		binary.LittleEndian.PutUint32(data, value)
		data[4] = object.Quality
	case 9, 11:
		value, ok := object.Value.(int16)
		if !ok {
			return nil, errors.New("measured value must be int16")
		}
		data = make([]byte, 3)
		binary.LittleEndian.PutUint16(data, uint16(value))
		data[2] = object.Quality
	case 13:
		value, ok := object.Value.(float32)
		if !ok || !wireFiniteFloat32(value) {
			return nil, errors.New("short float value must be finite float32")
		}
		data = make([]byte, 5)
		binary.LittleEndian.PutUint32(data, math.Float32bits(value))
		data[4] = object.Quality
	case 15:
		value, ok := object.Value.(int32)
		if !ok {
			return nil, errors.New("integrated total value must be int32")
		}
		data = make([]byte, 5)
		binary.LittleEndian.PutUint32(data, uint32(value))
		data[4] = object.Quality
	case 45:
		value, ok := object.Value.(bool)
		if !ok {
			return nil, errors.New("single command value must be boolean")
		}
		encoded, err := encodeWireCommandQualifier(object)
		if err != nil {
			return nil, err
		}
		if value {
			encoded |= 1
		}
		data = []byte{encoded}
	case 46, 47:
		value, ok := object.Value.(uint8)
		if !ok || value > 3 {
			return nil, errors.New("double or regulating command value must be between 0 and 3")
		}
		encoded, err := encodeWireCommandQualifier(object)
		if err != nil {
			return nil, err
		}
		data = []byte{encoded | value}
	case 48, 49:
		value, ok := object.Value.(int16)
		if !ok {
			return nil, errors.New("setpoint value must be int16")
		}
		qualifier, err := encodeWireSetpointQualifier(object)
		if err != nil {
			return nil, err
		}
		data = make([]byte, 3)
		binary.LittleEndian.PutUint16(data, uint16(value))
		data[2] = qualifier
	case 50:
		value, ok := object.Value.(float32)
		if !ok || !wireFiniteFloat32(value) {
			return nil, errors.New("short float setpoint must be finite float32")
		}
		qualifier, err := encodeWireSetpointQualifier(object)
		if err != nil {
			return nil, err
		}
		data = make([]byte, 5)
		binary.LittleEndian.PutUint32(data, math.Float32bits(value))
		data[4] = qualifier
	case 51:
		value, ok := object.Value.(uint32)
		if !ok {
			return nil, errors.New("bitstring command value must be uint32")
		}
		qualifier, err := encodeWireSetpointQualifier(object)
		if err != nil {
			return nil, err
		}
		data = make([]byte, 5)
		binary.LittleEndian.PutUint32(data, value)
		data[4] = qualifier
	case 70, 100, 101:
		value, ok := object.Value.(uint8)
		if !ok {
			return nil, errors.New("system information value must be uint8")
		}
		data = []byte{value}
	case 102:
		if object.Value != nil {
			return nil, errors.New("read command value must be nil")
		}
	case 103:
		value, ok := object.Value.(time.Time)
		if !ok {
			return nil, errors.New("clock synchronization value must be time.Time")
		}
		return EncodeWireCP56Time2a(value)
	default:
		return nil, fmt.Errorf("unsupported IEC 104 type ID %d", typeID)
	}
	if timed {
		if object.Timestamp == nil {
			return nil, errors.New("timed IEC 104 object requires timestamp")
		}
		encodedTime, err := EncodeWireCP56Time2a(*object.Timestamp)
		if err != nil {
			return nil, err
		}
		data = append(data, encodedTime...)
	}
	return data, nil
}

// DecodeWireInformationElement decodes one value portion and returns the
// number of consumed bytes so callers can parse consecutive SQ elements.
func DecodeWireInformationElement(typeID byte, data []byte) (WireInformationObject, int, error) {
	baseType, timed := wireInformationBaseType(typeID)
	object := WireInformationObject{}
	consumed := 0
	require := func(count int) error {
		if len(data) < count {
			return errors.New("truncated IEC 104 information element")
		}
		return nil
	}
	switch baseType {
	case 1:
		if err := require(1); err != nil {
			return object, 0, err
		}
		object.Value, object.Quality, consumed = data[0]&1 != 0, data[0]&0xf0, 1
	case 3:
		if err := require(1); err != nil {
			return object, 0, err
		}
		object.Value, object.Quality, consumed = data[0]&3, data[0]&0xf0, 1
	case 5:
		if err := require(2); err != nil {
			return object, 0, err
		}
		value := int8(data[0] & 0x7f)
		if value&0x40 != 0 {
			value |= ^int8(0x7f)
		}
		object.Value, object.Transient, object.Quality, consumed = value, data[0]&0x80 != 0, data[1], 2
	case 7:
		if err := require(5); err != nil {
			return object, 0, err
		}
		object.Value, object.Quality, consumed = binary.LittleEndian.Uint32(data), data[4], 5
	case 9, 11:
		if err := require(3); err != nil {
			return object, 0, err
		}
		object.Value, object.Quality, consumed = int16(binary.LittleEndian.Uint16(data)), data[2], 3
	case 13:
		if err := require(5); err != nil {
			return object, 0, err
		}
		value := math.Float32frombits(binary.LittleEndian.Uint32(data))
		if !wireFiniteFloat32(value) {
			return object, 0, errors.New("non-finite IEC 104 short float")
		}
		object.Value, object.Quality, consumed = value, data[4], 5
	case 15:
		if err := require(5); err != nil {
			return object, 0, err
		}
		object.Value, object.Quality, consumed = int32(binary.LittleEndian.Uint32(data)), data[4], 5
	case 45:
		if err := require(1); err != nil {
			return object, 0, err
		}
		object.Value, object.Qualifier, object.Select, consumed = data[0]&1 != 0, data[0]>>2&0x1f, data[0]&0x80 != 0, 1
	case 46, 47:
		if err := require(1); err != nil {
			return object, 0, err
		}
		object.Value, object.Qualifier, object.Select, consumed = data[0]&3, data[0]>>2&0x1f, data[0]&0x80 != 0, 1
	case 48, 49:
		if err := require(3); err != nil {
			return object, 0, err
		}
		object.Value, object.Qualifier, object.Select, consumed = int16(binary.LittleEndian.Uint16(data)), data[2]&0x7f, data[2]&0x80 != 0, 3
	case 50:
		if err := require(5); err != nil {
			return object, 0, err
		}
		value := math.Float32frombits(binary.LittleEndian.Uint32(data))
		if !wireFiniteFloat32(value) {
			return object, 0, errors.New("non-finite IEC 104 short float command")
		}
		object.Value, object.Qualifier, object.Select, consumed = value, data[4]&0x7f, data[4]&0x80 != 0, 5
	case 51:
		if err := require(5); err != nil {
			return object, 0, err
		}
		object.Value, object.Qualifier, object.Select, consumed = binary.LittleEndian.Uint32(data), data[4]&0x7f, data[4]&0x80 != 0, 5
	case 70, 100, 101:
		if err := require(1); err != nil {
			return object, 0, err
		}
		object.Value, consumed = data[0], 1
	case 102:
		object.Value = nil
	case 103:
		if err := require(7); err != nil {
			return object, 0, err
		}
		value, err := DecodeWireCP56Time2a(data[:7])
		if err != nil {
			return object, 0, err
		}
		object.Value, consumed = value, 7
	default:
		return object, 0, fmt.Errorf("unsupported IEC 104 type ID %d", typeID)
	}
	if timed {
		if err := require(consumed + 7); err != nil {
			return object, 0, err
		}
		value, err := DecodeWireCP56Time2a(data[consumed : consumed+7])
		if err != nil {
			return object, 0, err
		}
		object.Timestamp = &value
		consumed += 7
	}
	return object, consumed, nil
}

// EncodeWireCP56Time2a encodes a UTC timestamp with millisecond precision.
func EncodeWireCP56Time2a(value time.Time) ([]byte, error) {
	value = value.UTC()
	if value.Year() < 2000 || value.Year() > 2099 {
		return nil, errors.New("IEC 104 CP56Time2a year must be between 2000 and 2099")
	}
	milliseconds := value.Second()*1000 + value.Nanosecond()/int(time.Millisecond)
	data := make([]byte, 7)
	binary.LittleEndian.PutUint16(data[0:2], uint16(milliseconds))
	data[2] = byte(value.Minute())
	data[3] = byte(value.Hour())
	data[4] = byte(value.Day()) | byte(value.Weekday())<<5
	data[5] = byte(value.Month())
	data[6] = byte(value.Year() - 2000)
	return data, nil
}

// DecodeWireCP56Time2a strictly decodes a valid timestamp as UTC.
func DecodeWireCP56Time2a(data []byte) (time.Time, error) {
	if len(data) != 7 || data[2]&0x80 != 0 {
		return time.Time{}, errors.New("invalid or marked-invalid IEC 104 CP56Time2a timestamp")
	}
	milliseconds := int(binary.LittleEndian.Uint16(data[0:2]))
	minute := int(data[2] & 0x3f)
	hour := int(data[3] & 0x1f)
	day := int(data[4] & 0x1f)
	month := time.Month(data[5] & 0x0f)
	year := 2000 + int(data[6]&0x7f)
	if milliseconds >= 60000 || minute >= 60 || hour >= 24 || day < 1 || day > 31 || month < 1 || month > 12 {
		return time.Time{}, errors.New("invalid IEC 104 CP56Time2a timestamp fields")
	}
	value := time.Date(year, month, day, hour, minute, milliseconds/1000, milliseconds%1000*int(time.Millisecond), time.UTC)
	if value.Year() != year || value.Month() != month || value.Day() != day {
		return time.Time{}, errors.New("invalid IEC 104 CP56Time2a calendar date")
	}
	return value, nil
}

func wireInformationBaseType(typeID byte) (byte, bool) {
	if typeID >= 30 && typeID <= 37 {
		return 1 + (typeID-30)*2, true
	}
	if typeID >= 58 && typeID <= 64 {
		return typeID - 13, true
	}
	return typeID, false
}

func wireFiniteFloat32(value float32) bool {
	return !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0)
}

func encodeWireCommandQualifier(object WireInformationObject) (byte, error) {
	if object.Qualifier > 31 {
		return 0, errors.New("command qualifier must be between 0 and 31")
	}
	encoded := object.Qualifier << 2
	if object.Select {
		encoded |= 0x80
	}
	return encoded, nil
}

func encodeWireSetpointQualifier(object WireInformationObject) (byte, error) {
	if object.Qualifier > 31 {
		return 0, errors.New("setpoint qualifier must be between 0 and 31")
	}
	encoded := object.Qualifier
	if object.Select {
		encoded |= 0x80
	}
	return encoded, nil
}
