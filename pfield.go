package anonymization

import (
	"fmt"
	"github.com/intuitivelabs/sipsp"
)

type (
	AnonymPField struct {
		PField sipsp.PField
	}
)

func (callId *AnonymPField) EncodedLen() int {
	return NewEncoding().EncodedLen(int(callId.PField.Len))
}

func (pField *AnonymPField) DecodedLen() int {
	return NewEncoding().DecodedLen(int(pField.PField.Len))
}

func (pField *AnonymPField) PKCSPaddedLen(size int) (length int, err error) {
	length = 0
	err = nil
	if length, err = PKCSPadLen(int(pField.PField.Len), size); err != nil {
		err = fmt.Errorf("Call-ID padding error: %w", err)
		return
	}
	length += int(pField.PField.Len)
	return
}

func (pField *AnonymPField) CBCEncrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	err = nil
	blockSize := CallIdCBC().Encrypter.BlockSize()
	// 1. check dst len
	paddedLen, err := pField.PKCSPaddedLen(blockSize)
	if err != nil {
		err = fmt.Errorf("Call-ID encryption error: %w", err)
		return
	}
	if paddedLen > len(dst) {
		err = fmt.Errorf("Call-ID encryption error: encryption buffer too small, got %d bytes need %d bytes",
			len(dst), paddedLen+1)
		return
	}
	CallIdCBC().Reset()
	length, err := cbcEncryptToken(dst, src, pField.PField, CallIdCBC().Encrypter)
	if err != nil {
		err = fmt.Errorf("Call-ID encryption error: %w", err)
	}
	pField.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(length),
	}
	return
}

func (pField *AnonymPField) CBCDecrypt(dst, src []byte) (err error) {
	err = nil
	CallIdCBC().Reset()
	length, err := cbcDecryptToken(dst, src, pField.PField, CallIdCBC().Decrypter)
	if err != nil {
		err = fmt.Errorf("cannot encrypt Call-ID: %w", err)
	}
	pField.PField.Len = sipsp.OffsT(length)
	return
}

func (pField *AnonymPField) Encode(dst, src []byte) (err error) {
	err = nil
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < pField.EncodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for encoded Call-ID (%d bytes required and %d bytes available)",
			pField.EncodedLen(), len(dst))
		return
	}
	l := encodeToken(dst, src, pField.PField, codec)
	pField.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(l),
	}
	return
}

func (pField *AnonymPField) Decode(dst, src []byte) (err error) {
	err = nil
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < pField.DecodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for decoded Call-ID (%d bytes required and %d bytes available)",
			pField.DecodedLen(), len(dst))
		return
	}
	l, _ := decodeToken(dst, src, pField.PField, codec)
	pField.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(l),
	}
	return
}

func (pField *AnonymPField) Anonymize(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var ciphertxt [callIdMaxBufSize]byte
	if err = pField.CBCEncrypt(ciphertxt[:], src); err != nil {
		return fmt.Errorf("Call-ID anonymizing error: %w", err)
	}
	if err = pField.Encode(dst, ciphertxt[:]); err != nil {
		return fmt.Errorf("Call-ID anonymizing error: %w", err)
	}
	return nil
}

func (pField *AnonymPField) Deanonymize(dst, src []byte) (err error) {
	var decoded [callIdMaxBufSize]byte
	if err = pField.Decode(decoded[:], src); err != nil {
		return fmt.Errorf("cannot deanonymize Call-ID: %w", err)
	}
	if err = pField.CBCDecrypt(dst, decoded[:]); err != nil {
		return fmt.Errorf("cannot deanonymize Call-ID: %w", err)
	}
	return nil
}

func AnonymizePField(dst, src []byte) ([]byte, error) {
	ac := AnonymPField{
		PField: sipsp.PField{
			Offs: 0,
			Len:  sipsp.OffsT(len(src)),
		},
	}
	if err := ac.Anonymize(dst, src); err != nil {
		return nil, err
	}
	return ac.PField.Get(dst), nil
}
