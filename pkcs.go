package anonymization

import (
	"fmt"
)

//This file contains functionality for padding and unpadding (removal of padding) of cryptographic blocks
// See https://tools.ietf.org/html/rfc2315#section-10.3 for details

type Block struct {
	Offs int
	Len  int
}

func isPadded(buf []byte, pad byte) bool {
	if pad == 0 {
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
	df := DbgOn()
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
	df := DbgOn()
	defer DbgRestore(df)
	if size > 255 {
		return nil, fmt.Errorf("block size %d not supported by padding algorithm:", size)
	}
	l := len(buf)
	if l%size != 0 {
		return nil, fmt.Errorf("buffer length %d is not a multiple of block size %d:", l, size)
	}
	noBlocks := l / size
	blocks := make([]Block, noBlocks)
	for j, bi := 0, 0; bi < noBlocks; j, bi = j+1, bi+1 {
		offs := bi * size
		if bi+1 < noBlocks {
			if ok := isPadded(buf[(bi+1)*size:(bi+2)*size], byte(size)); ok {
				blocks[j] = Block{offs, size}
				bi++
				continue
			}
		}
		Dbg("buf: %v\n", buf)
		pad := buf[offs+size-1]
		if pad == 0 {
			return nil, fmt.Errorf("broken padding byte 0x%x (%d) starting at offset %d", pad, pad, offs+size-1)
		}
		if int(pad) > offs+size {
			return nil, fmt.Errorf("broken padding byte 0x%x (%d) starting at offset %d", pad, pad, offs+size-1)
		}
		if ok := isPadded(buf[offs+size-int(pad):offs+size], pad); ok {
			blocks[j] = Block{offs, size - int(pad)}
		} else {
			return nil, fmt.Errorf("broken padding byte 0x%x (%d) between offsets %d-%d",
				buf[offs+size-int(pad)],
				buf[offs+size-int(pad)],
				offs+size-int(pad), offs+size-1)
		}
	}
	buf = buf[blocks[0].Offs : blocks[0].Offs+blocks[0].Len]
	length := blocks[0].Len
	if len(blocks) > 1 {
		for _, v := range blocks[1:] {
			buf = append(buf, buf[v.Offs:v.Offs+v.Len]...)
			length += v.Len
		}
	}
	return buf, nil
}
