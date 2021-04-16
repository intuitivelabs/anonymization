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
	if size > 255 {
		return nil, fmt.Errorf("size %d not supported by padding algorithm:", size)
	}
	l := len(buf)
	padLen, err := PKCSPadLen(l, size)
	if err != nil {
		return nil, fmt.Errorf("could noot compute pad len: %w", err)
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
		buf[n+i] = byte(padLen)
	}
	return buf, nil
}

// PKCSUnpad removes the padding from buf returning an unpadded slice
// See https://tools.ietf.org/html/rfc2315#section-10.3 for details
func PKCSUnpad(buf []byte, size int) ([]byte, error) {
	if size > 255 {
		return nil, fmt.Errorf("size %d not supported by padding algorithm:", size)
	}
	//tmp := dst[:1]
	noBlocks := len(buf) / size
	blocks := make([]Block, noBlocks)
	for j, bi := 0, 0; bi < noBlocks; j, bi = j+1, bi+1 {
		offs := bi * size
		if bi+1 < noBlocks {
			if ok := isPadded(buf[(bi+1)*size:(bi+2)*size], byte(size)); ok {
				//tmp = append(tmp, buf[offs:(bi+1)*size]...)
				blocks[j] = Block{offs, size}
				bi++
				continue
			}
		}
		pad := buf[offs+size-1]
		if ok := isPadded(buf[offs+size-int(pad):offs+size], byte(size)); ok {
			//tmp = append(tmp, buf[offs:offs+size-int(pad)]...)
			blocks[j] = Block{offs, size - int(pad)}
		} else {
			return nil, fmt.Errorf("broken padding byte %x starting at offset: %d",
				buf[offs+size-int(pad)], offs+size-int(pad))
		}
	}
	buf = buf[blocks[0].Offs : blocks[0].Offs+blocks[0].Len]
	length := blocks[0].Len
	for _, v := range blocks[1:] {
		buf = append(buf, buf[v.Offs:v.Offs+v.Len]...)
		length += v.Len
	}
	return buf, nil
}
