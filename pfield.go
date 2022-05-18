package anonymization

import (
	"fmt"
	"github.com/intuitivelabs/sipsp"
)

const (
	PfMaxBufSize int = 4096
)

// AnonymPField is a PField that can be anonymized using a cipher in Cipher Block Chaining mode
type AnonymPField struct {
	PField sipsp.PField
	CBC    CBC
	Codec  Codec
}

func (apf *AnonymPField) SetPField(pf *sipsp.PField) {
	apf.PField = *pf
}

func (apf *AnonymPField) WithKeyingMaterial(km *KeyingMaterial) *AnonymPField {
	apf.CBC.WithKeyingMaterial(km)
	return apf
}

func (apf *AnonymPField) EncodedLen() int {
	return NewEncoding(apf.Codec).EncodedLen(int(apf.PField.Len))
}

func (apf *AnonymPField) DecodedLen() int {
	return NewEncoding(apf.Codec).DecodedLen(int(apf.PField.Len))
}

func (apf *AnonymPField) PaddedLen(size int) (length int, err error) {
	length = 0
	err = nil
	if length, err = PadLen(int(apf.PField.Len), size); err != nil {
		err = fmt.Errorf("cannot pad: %w", err)
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
	paddedLen, err := apf.PaddedLen(blockSize)
	if err != nil {
		err = fmt.Errorf("cannot encrypt: %w", err)
		return
	}
	if paddedLen > len(dst) {
		err = fmt.Errorf("encryption buffer too small, got %d bytes need %d bytes",
			len(dst), paddedLen+1)
		return
	}
	apf.CBC.Reset()
	length, err := apf.CBC.EncryptToken(dst, src, apf.PField)
	if err != nil {
		err = fmt.Errorf("cannot encrypt: %w", err)
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
	length, err := apf.CBC.DecryptToken(dst, src, apf.PField)
	if err != nil {
		err = fmt.Errorf("cannot decrypt: %w", err)
	}
	apf.PField.Len = sipsp.OffsT(length)
	return
}

func (apf *AnonymPField) Encode(dst, src []byte) (err error) {
	err = nil
	codec := NewEncoding(apf.Codec)
	// 1. check dst len
	if len(dst) < apf.EncodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for encoded pfield (%d bytes required and %d bytes available)",
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
	codec := NewEncoding(apf.Codec)
	// 1. check dst len
	if len(dst) < apf.DecodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for decoded pfield (%d bytes required and %d bytes available)",
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
	var ciphertxt [PfMaxBufSize]byte
	if err := apf.CBCEncrypt(ciphertxt[:], src); err != nil {
		return nil, fmt.Errorf("cannot anonymize: %w", err)
	}
	if err := apf.Encode(dst, ciphertxt[:]); err != nil {
		return nil, fmt.Errorf("cannot anonymize: %w", err)
	}
	return apf.PField.Get(dst), nil
}

func (apf *AnonymPField) Deanonymize(dst, src []byte) ([]byte, error) {
	var decoded [PfMaxBufSize]byte
	if err := apf.Decode(decoded[:], src); err != nil {
		return nil, fmt.Errorf("cannot deanonymize: %w", err)
	}
	if err := apf.CBCDecrypt(dst, decoded[:]); err != nil {
		return nil, fmt.Errorf("cannot deanonymize: %w", err)
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
