package anonymization

import (
	"fmt"
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

//PKCSPadLen returns the length of the necessary padding
func PKCSPadLen(length, size int) (int, error) {
	if size > 255 {
		return 0, fmt.Errorf("size %d not supported by padding algorithm:", size)
	}
	return size - (length % size), nil
}

// PKCSPad padds buf up to a length which is multiple of size. Size has to be less than 256.
// See https://tools.ietf.org/html/rfc2315#section-10.3 for details
func PKCSPad(buf []byte, size int) ([]byte, error) {
	df := DbgOff()
	defer DbgRestore(df)
	if size > 255 {
		return nil, fmt.Errorf("size %d not supported by padding algorithm:", size)
	}
	l := len(buf)
	padLen, err := PKCSPadLen(l, size)
	if err != nil {
		return nil, fmt.Errorf("could not compute pad len: %w", err)
	}
	n := l + padLen
	// reallocate slice if needed
	if n > cap(buf) {
		s := make([]byte, (n+1)*2)
		copy(s, buf)
		buf = s
	}
	buf = buf[0:n]
	for i := 0; i < padLen; i++ {
		buf[l+i] = byte(padLen)
	}
	return buf, nil
}

// PKCSUnpad removes the padding from buf returning an unpadded slice
// See https://tools.ietf.org/html/rfc2315#section-10.3 for details
func PKCSUnpad(buf []byte, size int) ([]byte, error) {
	df := DbgOff()
	defer DbgRestore(df)
	if size > 255 {
		return nil, fmt.Errorf("block size %d not supported by padding algorithm:", size)
	}
	l := len(buf)
	if l%size != 0 {
		return nil, fmt.Errorf("buffer length %d is not a multiple of block size %d:", l, size)
	}
	pad := int(buf[l-1])
	if pad > size || pad == 0 ||
		pad > l || (pad == 16 && l < 32) {
		return nil, fmt.Errorf("invalid pad byte %d for block size %d and buffer length %d", pad, size, l)
	}
	if ok := isPadded(buf[l-pad:l], byte(pad)); !ok {
		return nil, fmt.Errorf("broken padding with byte 0x%x (%d) between offsets %d-%d", pad, pad, l-pad, l)
	}
	return buf[0 : l-pad], nil
}
