package anonymization

import (
	"crypto/aes"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

type (
	AnonymCallId sipsp.PCallIDBody
)

const (
	// maximum size allowed for an anonymized Call-Id
	callIdMaxBufSize int = 4096
)

var (
	callIdCBC = BlockModeCipher{}
)

func NewCallIdCBC(iv, key []byte) *BlockModeCipher {
	if block, err := aes.NewCipher(key); err != nil {
		panic(err)
	} else {
		callIdCBC.Init(iv, key, block)
	}
	return &callIdCBC
}

func CallIdCBC() *BlockModeCipher {
	return &callIdCBC
}

func (callId *AnonymCallId) EncodedLen() int {
	return NewEncoding().EncodedLen(int(callId.CallID.Len))
}

func (callId *AnonymCallId) DecodedLen() int {
	return NewEncoding().DecodedLen(int(callId.CallID.Len))
}

func (callId *AnonymCallId) PKCSPaddedLen(size int) (length int, err error) {
	length = 0
	err = nil
	if length, err = PKCSPadLen(int(callId.CallID.Len), size); err != nil {
		err = fmt.Errorf("Call-ID padding error: %w", err)
		return
	}
	length += int(callId.CallID.Len)
	return
}

func (callId *AnonymCallId) CBCEncrypt(dst, src []byte) (err error) {
	err = nil
	blockSize := CallIdCBC().Encrypter.BlockSize()
	// 1. check dst len
	paddedLen, err := callId.PKCSPaddedLen(blockSize)
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
	length, err := cbcEncryptToken(dst, src, callId.CallID, CallIdCBC().Encrypter)
	if err != nil {
		err = fmt.Errorf("Call-ID encryption error: %w", err)
	}
	callId.CallID = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(length),
	}
	return
}

func (callId *AnonymCallId) CBCDecrypt(dst, src []byte) (err error) {
	err = nil
	CallIdCBC().Reset()
	length, err := cbcDecryptToken(dst, src, callId.CallID, CallIdCBC().Decrypter)
	if err != nil {
		err = fmt.Errorf("cannot encrypt Call-ID: %w", err)
	}
	callId.CallID.Len = sipsp.OffsT(length)
	return
}

func (callId *AnonymCallId) Encode(dst, src []byte) (err error) {
	err = nil
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < callId.EncodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for encoded Call-ID (%d bytes required and %d bytes available)",
			callId.EncodedLen(), len(dst))
		return
	}
	l := encodeToken(dst, src, callId.CallID, codec)
	callId.CallID = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(l),
	}
	return
}

func (callId *AnonymCallId) Decode(dst, src []byte) (err error) {
	err = nil
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < callId.DecodedLen() {
		err = fmt.Errorf("\"dst\" buffer too small for decoded Call-ID (%d bytes required and %d bytes available)",
			callId.DecodedLen(), len(dst))
		return
	}
	l, _ := decodeToken(dst, src, callId.CallID, codec)
	callId.CallID = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(l),
	}
	return
}

func (callId *AnonymCallId) Anonymize(dst, src []byte) (err error) {
	var ciphertxt [callIdMaxBufSize]byte
	if err = callId.CBCEncrypt(ciphertxt[:], src); err != nil {
		return fmt.Errorf("cannot anonymize URI: %w", err)
	}
	if err = callId.Encode(dst, ciphertxt[:]); err != nil {
		return fmt.Errorf("cannot anonymize URI: %w", err)
	}
	return nil
}

func (callId *AnonymCallId) Deanonymize(dst, src []byte) (err error) {
	var decoded [callIdMaxBufSize]byte
	if err = callId.Decode(decoded[:], src); err != nil {
		return fmt.Errorf("cannot deanonymize Call-ID: %w", err)
	}
	if err = callId.CBCDecrypt(dst, decoded[:]); err != nil {
		return fmt.Errorf("cannot deanonymize Call-ID: %w", err)
	}
	return nil
}
