package anonymization

import (
	"fmt"
	"github.com/intuitivelabs/sipsp"
)

// AnonymPField is a PField that can be anonymized using a cipher in Cipher Block Chaining mode
type AnonymPField struct {
	PField sipsp.PField
	CBC    CBC
}

func (apf *AnonymPField) WithKeyingMaterial(km *KeyingMaterial) *AnonymPField {
	apf.CBC.WithKeyingMaterial(km)
	return apf
}

func (apf *AnonymPField) EncodedLen() int {
	return NewEncoding().EncodedLen(int(apf.PField.Len))
}

func (apf *AnonymPField) DecodedLen() int {
	return NewEncoding().DecodedLen(int(apf.PField.Len))
}

func (apf *AnonymPField) PKCSPaddedLen(size int) (length int, err error) {
	length = 0
	err = nil
	if length, err = PKCSPadLen(int(apf.PField.Len), size); err != nil {
		err = fmt.Errorf("Call-ID padding error: %w", err)
		return
	}
	length += int(apf.PField.Len)
	return
}

func (apf *AnonymPField) CBCEncrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	err = nil
	blockSize := apf.CBC.Encrypter.BlockSize()
	// 1. check dst len
	paddedLen, err := apf.PKCSPaddedLen(blockSize)
	if err != nil {
		err = fmt.Errorf("Call-ID encryption error: %w", err)
		return
	}
	if paddedLen > len(dst) {
		err = fmt.Errorf("Call-ID encryption error: encryption buffer too small, got %d bytes need %d bytes",
			len(dst), paddedLen+1)
		return
	}
	apf.CBC.Reset()
	length, err := cbcEncryptToken(dst, src, apf.PField, apf.CBC.Encrypter)
	if err != nil {
		err = fmt.Errorf("Call-ID encryption error: %w", err)
	}
	apf.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(length),
	}
	return
}

func (apf *AnonymPField) CBCDecrypt(dst, src []byte) (err error) {
	err = nil
	apf.CBC.Reset()
	length, err := cbcDecryptToken(dst, src, apf.PField, apf.CBC.Decrypter)
	if err != nil {
		err = fmt.Errorf("cannot encrypt Call-ID: %w", err)
	}
	apf.PField.Len = sipsp.OffsT(length)
	return
}

func (apf *AnonymPField) Encode(dst, src []byte) (err error) {
	err = nil
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < apf.EncodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for encoded Call-ID (%d bytes required and %d bytes available)",
			apf.EncodedLen(), len(dst))
		return
	}
	l := encodeToken(dst, src, apf.PField, codec)
	apf.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(l),
	}
	return
}

func (apf *AnonymPField) Decode(dst, src []byte) (err error) {
	err = nil
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < apf.DecodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for decoded Call-ID (%d bytes required and %d bytes available)",
			apf.DecodedLen(), len(dst))
		return
	}
	l, _ := decodeToken(dst, src, apf.PField, codec)
	apf.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(l),
	}
	return
}

func (apf *AnonymPField) Anonymize(dst, src []byte) ([]byte, error) {
	df := DbgOn()
	defer DbgRestore(df)
	var ciphertxt [callIdMaxBufSize]byte
	apf.PField.Set(0, len(src))
	if err := apf.CBCEncrypt(ciphertxt[:], src); err != nil {
		return nil, fmt.Errorf("Call-ID anonymizing error: %w", err)
	}
	if err := apf.Encode(dst, ciphertxt[:]); err != nil {
		return nil, fmt.Errorf("Call-ID anonymizing error: %w", err)
	}
	return apf.PField.Get(dst), nil
}

func (apf *AnonymPField) Deanonymize(dst, src []byte) ([]byte, error) {
	var decoded [callIdMaxBufSize]byte
	apf.PField.Set(0, len(src))
	if err := apf.Decode(decoded[:], src); err != nil {
		return nil, fmt.Errorf("cannot deanonymize Call-ID: %w", err)
	}
	if err := apf.CBCDecrypt(dst, decoded[:]); err != nil {
		return nil, fmt.Errorf("cannot deanonymize Call-ID: %w", err)
	}
	return apf.PField.Get(dst), nil
}

func AnonymizePField(dst, src []byte) ([]byte, error) {
	apf := AnonymPField{
		PField: sipsp.PField{
			Offs: 0,
			Len:  sipsp.OffsT(len(src)),
		},
	}
	anonym, err := apf.Anonymize(dst, src)
	if err != nil {
		return nil, err
	}
	return anonym, nil
}
