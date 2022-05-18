package anonymization

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

const (
	// padding character used in base32 encoding
	pad rune = '-'
)

// type of codec used for encoding the anonymized object
type Codec int

const (
	Base32 Codec = iota
	Hex
)

type Encoding interface {
	Encode(dst, src []byte)
	Decode(dst, src []byte) (n int, err error)
	EncodedLen(n int) int
	DecodedLen(n int) int
}

// HexEncoding is a type which implements the Encoding interface by encoding/decoding to/from hexadecimal
type HexEncoding struct {
}

func (h *HexEncoding) Encode(dst, src []byte) {
	hex.Encode(dst, src)
	return
}

func (h *HexEncoding) Decode(dst, src []byte) (n int, err error) {
	return hex.Decode(dst, src)
}

func (h *HexEncoding) EncodedLen(n int) int {
	return hex.EncodedLen(n)
}

func (h *HexEncoding) DecodedLen(n int) int {
	return hex.DecodedLen(n)
}

var hexEncoding *HexEncoding = &HexEncoding{}

func NewEncoding(c Codec) Encoding {
	switch c {
	case Base32:
		return base32.HexEncoding.WithPadding(pad)
	case Hex:
		return hexEncoding
	}
	return nil
}

// encodeToken encodes the token specified by sipsp.PField from src buffer into dst buffer using the codec.
// It returns the length of the encoded token.
func encodeToken(dst, src []byte, pf sipsp.PField, codec Encoding) (length int) {
	df := DbgOn()
	defer DbgRestore(df)
	token := pf.Get(src)
	_ = WithDebug && Dbg("token: %v", token)
	length = codec.EncodedLen(len(token))
	ePf := sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(length),
	}
	eToken := ePf.Get(dst)
	codec.Encode(eToken, token)
	return
}

// decodeToken decodes the token specified by sipsp.PField from src buffer into dst buffer using the codec.
// It returns the length of the encoded token.
func decodeToken(dst, src []byte, pf sipsp.PField, codec Encoding) (length int, err error) {
	df := DbgOn()
	defer DbgRestore(df)
	length = 0
	err = nil
	token := pf.Get(src)
	_ = WithDebug && Dbg("encoded (src) token: %v", token)
	length = codec.DecodedLen(len(token))
	if len(dst) < length {
		err = fmt.Errorf(`"dst" buffer to small for decoded data (%d bytes required and %d bytes available)`,
			length, len(dst))
		return
	}
	dPf := sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(length),
	}
	dToken := dPf.Get(dst)
	length, err = codec.Decode(dToken, token)
	dPf = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(length),
	}
	dToken = dPf.Get(dst)
	_ = WithDebug && Dbg("decoded (dst) token: %v len: %d", dToken, len(dToken))
	return
}
