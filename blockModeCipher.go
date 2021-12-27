package anonymization

import (
	"crypto/cipher"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

type BlockModeCipher struct {
	IV        []byte
	Key       []byte
	Block     cipher.Block
	Encrypter cipher.BlockMode
	Decrypter cipher.BlockMode
}

func (bm *BlockModeCipher) Init(iv, key []byte, block cipher.Block) {
	bm.Key = key
	bm.IV = iv
	bm.Block = block
	bm.Encrypter = cipher.NewCBCEncrypter(bm.Block, bm.IV)
	bm.Decrypter = cipher.NewCBCDecrypter(bm.Block, bm.IV)
}

func (bm *BlockModeCipher) Reset() {
	bm.Encrypter = cipher.NewCBCEncrypter(bm.Block, bm.IV)
	bm.Decrypter = cipher.NewCBCDecrypter(bm.Block, bm.IV)
}

// cbcEncryptToken encrypts the token from the src byte, specified using a sipsp.PField into dst
func cbcEncryptToken(dst, src []byte, pf sipsp.PField, encrypter cipher.BlockMode) (length int, err error) {
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
	blockSize := encrypter.BlockSize()
	eToken, err := PKCSPadToken(dst, ePf, blockSize)
	if err != nil {
		return 0, fmt.Errorf("token encryption error: %w", err)
	}
	_ = WithDebug && Dbg("padded eToken: %v", eToken)
	// 3. encrypt token
	encrypter.CryptBlocks(eToken, eToken)
	_ = WithDebug && Dbg("encrypted eToken: %v (len: %d)", eToken, len(eToken))
	return len(eToken), nil
}

// cbcDecryptToken decrypts the token from the src byte, specified using a sipsp.PField into dst
func cbcDecryptToken(dst, src []byte, pf sipsp.PField, decrypter cipher.BlockMode) (length int, err error) {
	length = 0
	err = nil
	blockSize := decrypter.BlockSize()
	token := pf.Get(src)
	// 1. copy token
	_ = copy(dst, token)
	// 2. get the token from dst
	dToken := pf.Get(dst)
	// 3. decrypt token
	decrypter.CryptBlocks(dToken, dToken)
	unpadded, err := PKCSUnpad(dToken, blockSize)
	if err != nil {
		err = fmt.Errorf("cannot decrypt token: %w", err)
		return
	}
	length = len(unpadded)
	return
}
