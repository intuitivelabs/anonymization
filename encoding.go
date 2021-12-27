package anonymization

import (
	"encoding/base32"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

const (
	// padding character used in base32 encoding
	pad rune = '-'
)

func NewEncoding() *base32.Encoding {
	return base32.HexEncoding.WithPadding(pad)
}

// encodeToken encodes the token specified by sipsp.PField from src buffer into dst buffer using the codec.
// It returns the length of the encoded token.
func encodeToken(dst, src []byte, pf sipsp.PField, codec *base32.Encoding) (length int) {
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
func decodeToken(dst, src []byte, pf sipsp.PField, codec *base32.Encoding) (length int, err error) {
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
