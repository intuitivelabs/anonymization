package anonymization

import (
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

//This file contains functionality for padding and unpadding (removal of padding) of cryptographic blocks
// See https://tools.ietf.org/html/rfc2315#section-10.3 for details

const (
	// at most 1024 blocks of 16 bytes are supported
	maxBlocks = 1024
)

type Block struct {
	Offs int
	Len  int
}

func isPadded(buf []byte, pad byte) bool {
	if pad == 0 {
		return false
	}
	if len(buf) != int(pad) {
		return false
	}
	for _, v := range buf {
		if v != pad {
			return false
		}
	}
	return true
}

//PadLen returns the number of padding bytes necessary for extending length to a multiple of factor
func PadLen(length, factor int) (int, error) {
	if factor > 255 {
		return 0, fmt.Errorf("block factor %d not supported by padding algorithm.", factor)
	}
	return factor - (length % factor), nil
}

// PKCSPad padds the slice starting at offset and having length bytes up to a multiple of size. Size has to be less than 256.
// The following should hold: offset < length < len(buf)
// See https://tools.ietf.org/html/rfc2315#section-10.3 for details
func PKCSPad(buf []byte, offset, length, size int) ([]byte, error) {
	df := DbgOff()
	defer DbgRestore(df)
	if size > 255 {
		return nil, fmt.Errorf("block size %d not supported by padding algorithm.", size)
	}
	padLen, err := PadLen(length, size)
	if err != nil {
		return nil, fmt.Errorf("cannot compute padding length: %w.", err)
	}
	if len(buf) < offset+length+padLen {
		return nil, fmt.Errorf("buffer of %d bytes too small for padding between offsets %d-%d.",
			len(buf), length, length+padLen)
	}
	// fill with padding bytes
	fill := buf[length : length+padLen]
	for i, _ := range fill {
		fill[i] = byte(padLen)
	}
	return buf[offset : length+padLen], nil
}

// PKCSUnpad removes the padding from buf returning an unpadded slice
// See https://tools.ietf.org/html/rfc2315#section-10.3 for details
func PKCSUnpad(buf []byte, size int) ([]byte, error) {
	df := DbgOff()
	defer DbgRestore(df)
	if size > 255 {
		return nil, fmt.Errorf("block size %d not supported by padding algorithm.", size)
	}
	l := len(buf)
	if l == 0 {
		return nil, fmt.Errorf("empty buffer")
	}
	if l%size != 0 {
		return nil, fmt.Errorf("buffer length %d is not a multiple of block size %d.", l, size)
	}
	pad := int(buf[l-1])
	if pad > size || pad == 0 ||
		pad > l || (pad == 16 && l < 16) {
		return nil, fmt.Errorf("invalid pad byte %d for block size %d and buffer length %d.", pad, size, l)
	}
	if ok := isPadded(buf[l-pad:l], byte(pad)); !ok {
		return nil, fmt.Errorf("broken padding with byte 0x%x (%d) between offsets %d-%d.", pad, pad, l-pad, l)
	}
	return buf[0 : l-pad], nil
}

func PKCSPadToken(dst []byte, pf sipsp.PField, blockSize int) ([]byte, error) {
	return PKCSPad(dst, int(pf.Offs), int(pf.Len), blockSize)
}
