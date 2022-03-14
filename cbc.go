package anonymization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

// block mode cipher used in CBC (cipher block chaining) mode
type CBC struct {
	Km        KeyingMaterial
	Block     cipher.Block
	Encrypter cipher.BlockMode
	Decrypter cipher.BlockMode
}

func (cbc *CBC) WithKeyingMaterial(km *KeyingMaterial) *CBC {
	cbc.Km = *km
	if block, err := aes.NewCipher(km.Enc[:]); err != nil {
		panic(err)
	} else {
		cbc.Init(km.IV[:], km.Enc[:], block)
	}
	return cbc
}

func (cbc *CBC) Init(iv, key []byte, block cipher.Block) {
	subtle.ConstantTimeCopy(1, cbc.Km.Enc[:], key)
	subtle.ConstantTimeCopy(1, cbc.Km.IV[:], iv)
	cbc.Block = block
	cbc.Encrypter = cipher.NewCBCEncrypter(cbc.Block, cbc.Km.IV[:])
	cbc.Decrypter = cipher.NewCBCDecrypter(cbc.Block, cbc.Km.IV[:])
}

func (cbc *CBC) Reset() {
	cbc.Encrypter = cipher.NewCBCEncrypter(cbc.Block, cbc.Km.IV[:])
	cbc.Decrypter = cipher.NewCBCDecrypter(cbc.Block, cbc.Km.IV[:])
}

// EncryptToken encrypts the token from the src byte, specified using a sipsp.PField into dst
func (cbc *CBC) EncryptToken(dst, src []byte, pf sipsp.PField) (length int, err error) {
	df := DbgOn()
	defer DbgRestore(df)
	_ = WithDebug && Dbg("src: %v len: %d offset: %d len: %d", src, len(src), pf.Offs, pf.Len)
	token := pf.Get(src)
	// 1. copy token
	_ = copy(dst, token)
	ePf := sipsp.PField{
		Offs: sipsp.OffsT(0),
		Len:  sipsp.OffsT(len(token)),
	}
	// 2. pad token
	blockSize := cbc.Encrypter.BlockSize()
	eToken, err := PKCSPadToken(dst, ePf, blockSize)
	if err != nil {
		return 0, fmt.Errorf("token encryption error: %w", err)
	}
	_ = WithDebug && Dbg("padded eToken: %v", eToken)
	// 3. encrypt token
	cbc.Encrypter.CryptBlocks(eToken, eToken)
	_ = WithDebug && Dbg("encrypted eToken: %v (len: %d)", eToken, len(eToken))
	return len(eToken), nil
}

// cbcDecryptToken decrypts the token from the src byte, specified using a sipsp.PField into dst
func (cbc *CBC) DecryptToken(dst, src []byte, pf sipsp.PField) (length int, err error) {
	length = 0
	err = nil
	blockSize := cbc.Decrypter.BlockSize()
	token := pf.Get(src)
	// 1. copy token
	_ = copy(dst, token)
	// 2. get the token from dst
	dToken := pf.Get(dst)
	// 3. decrypt token
	cbc.Decrypter.CryptBlocks(dToken, dToken)
	unpadded, err := PKCSUnpad(dToken, blockSize)
	if err != nil {
		err = fmt.Errorf("cannot decrypt token: %w", err)
		return
	}
	length = len(unpadded)
	return
}
