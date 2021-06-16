package anonymization

import (
	"crypto/aes"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

type (
	AnonymCallId struct {
		PField sipsp.PField
	}
)

const (
	// maximum size allowed for an anonymized Call-Id
	callIdMaxBufSize int = 4096
	// salt used for generating Call-ID encryption keys
	SaltCallIdIV  = "ea3f055967db474b9f3bf4afc9c2c712"
	SaltCallIdKey = "26ef0bb4d6e45cb90a6bb2a121b4a683"
)

type CallIdKeys struct {
	// initialization vector
	IV [EncryptionKeyLen]byte
	// encryption key used
	Key [EncryptionKeyLen]byte
}

var (
	callIdCBC  = BlockModeCipher{}
	callIdKeys = CallIdKeys{}
)

func GenerateCallIdIV(masterKey []byte, ivLen int, iv []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltCallIdIV, masterKey, ivLen, iv)
}

func GenerateCallIdKey(masterKey []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltCallIdKey, masterKey, keyLen, key)
}

func GetCallIdKeys() *CallIdKeys {
	return &callIdKeys
}

func InitCallIdKeys(iv []byte, k []byte) {
	copy(GetCallIdKeys().IV[:], iv)
	copy(GetCallIdKeys().Key[:], k)
}

func InitCallIdKeysFromMasterKey(masterKey []byte, keyLen int) {
	// generate Call-ID IV for CBC
	GenerateCallIdIV(masterKey[:], EncryptionKeyLen, GetCallIdKeys().IV[:])
	// generate key for Call-ID
	GenerateCallIdKey(masterKey[:], EncryptionKeyLen, GetCallIdKeys().Key[:])
}

func NewCallIdCBC(keys *CallIdKeys) *BlockModeCipher {
	if block, err := aes.NewCipher(keys.Key[:]); err != nil {
		panic(err)
	} else {
		callIdCBC.Init(keys.IV[:], keys.Key[:], block)
	}
	return &callIdCBC
}

func CallIdCBC() *BlockModeCipher {
	return &callIdCBC
}

func (callId *AnonymCallId) EncodedLen() int {
	return NewEncoding().EncodedLen(int(callId.PField.Len))
}

func (callId *AnonymCallId) DecodedLen() int {
	return NewEncoding().DecodedLen(int(callId.PField.Len))
}

func (callId *AnonymCallId) PKCSPaddedLen(size int) (length int, err error) {
	length = 0
	err = nil
	if length, err = PKCSPadLen(int(callId.PField.Len), size); err != nil {
		err = fmt.Errorf("Call-ID padding error: %w", err)
		return
	}
	length += int(callId.PField.Len)
	return
}

func (callId *AnonymCallId) CBCEncrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
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
	length, err := cbcEncryptToken(dst, src, callId.PField, CallIdCBC().Encrypter)
	if err != nil {
		err = fmt.Errorf("Call-ID encryption error: %w", err)
	}
	callId.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(length),
	}
	return
}

func (callId *AnonymCallId) CBCDecrypt(dst, src []byte) (err error) {
	err = nil
	CallIdCBC().Reset()
	length, err := cbcDecryptToken(dst, src, callId.PField, CallIdCBC().Decrypter)
	if err != nil {
		err = fmt.Errorf("cannot encrypt Call-ID: %w", err)
	}
	callId.PField.Len = sipsp.OffsT(length)
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
	l := encodeToken(dst, src, callId.PField, codec)
	callId.PField = sipsp.PField{
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
	l, _ := decodeToken(dst, src, callId.PField, codec)
	callId.PField = sipsp.PField{
		Offs: 0,
		Len:  sipsp.OffsT(l),
	}
	return
}

func (callId *AnonymCallId) Anonymize(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var ciphertxt [callIdMaxBufSize]byte
	if err = callId.CBCEncrypt(ciphertxt[:], src); err != nil {
		return fmt.Errorf("Call-ID anonymizing error: %w", err)
	}
	if err = callId.Encode(dst, ciphertxt[:]); err != nil {
		return fmt.Errorf("Call-ID anonymizing error: %w", err)
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
