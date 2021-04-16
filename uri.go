package anonymization

import (
	"crypto/aes"
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

type UriCBC struct {
	// user part cipher (key SHOULD be different from host part cipher)
	User BlockModeCipher
	// host part cipher (key SHOULD be different from user part cipher)
	Host BlockModeCipher
}

func (bm *BlockModeCipher) Init(iv, key []byte, block cipher.Block) {
	bm.Key = key
	bm.IV = iv
	bm.Block = block
	bm.Encrypter = cipher.NewCBCEncrypter(bm.Block, bm.IV)
	bm.Decrypter = cipher.NewCBCDecrypter(bm.Block, bm.IV)
}

var (
	uriCBC = UriCBC{}
	//uriGCM = UriGCM{}
)

func NewUriCBC(iv, userKey, hostKey []byte) *UriCBC {
	if block, err := aes.NewCipher(userKey); err != nil {
		panic(err)
	} else {
		uriCBC.User.Init(iv, userKey, block)
	}
	if block, err := aes.NewCipher(hostKey); err != nil {
		panic(err)
	} else {
		uriCBC.Host.Init(iv, hostKey, block)
	}
	return &uriCBC
}

type AnonymURI sipsp.PsipURI

func (uri *AnonymURI) PKCSPaddedLen(size int) (int, error) {
	var (
		err                          error
		hLen, uLen, hPadLen, uPadLen int
	)
	uLen = int(uri.Pass.Len + uri.User.Len)
	if uPadLen, err = PKCSPadLen(uLen, size); err != nil {
		return 0, fmt.Errorf("cannot pad uri's user part: %w", err)
	}
	uLen += uPadLen
	hLen = int(uri.Headers.Len + uri.Params.Len + uri.Port.Len + uri.Host.Len)
	if hPadLen, err = PKCSPadLen(hLen, size); err != nil {
		return 0, fmt.Errorf("cannot pad uri's host part: %w", err)
	}
	hLen += hPadLen
	return int(uLen + hLen), nil
}

// CBCEncryptURI encrypts the user info and host part of uri preserving the generic URI format userinfo@hostinfo.
// The encrypted URI for user@host is AES_CBC_ENCRYPT(user)@AES_CBC_ENCRYPT(host)
func (uri *AnonymURI) CBCEncrypt(dst, src []byte) (err error) {
	var (
		paddedLen    int
		eUser, eHost []byte
	)
	blockSize := uriCBC.User.Encrypter.BlockSize()
	// 0. check dst len
	if paddedLen, err = uri.PKCSPaddedLen(blockSize); err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
	}
	if paddedLen+1 > len(dst) {
		return fmt.Errorf("buffer for encrypted URI is too small: %d bytes (need %d bytes)",
			len(dst), paddedLen+1)
	}
	// 1. copy & pad user+pass
	userEnd := uri.Pass.Offs + uri.Pass.Len
	if userEnd == 0 {
		userEnd = uri.User.Offs + uri.User.Len
	}
	if userEnd > 0 {
		eUser = append(dst[:1], src[uri.User.Offs:userEnd]...)
		if eUser, err = PKCSPad(eUser, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's user part: %w", err)
		}
		// 2. encrypt (user+pass)
		uriCBC.User.Encrypter.CryptBlocks(eUser, eUser)
		// write '@' into dst
		dst[len(eUser)+1] = '@'
	}
	// 3. copy & pad host+port+params+header
	hostEnd := uri.Headers.Offs + uri.Headers.Len
	if hostEnd == 0 {
		hostEnd = uri.Params.Offs + uri.Params.Len
	}
	if hostEnd == 0 {
		hostEnd = uri.Port.Offs + uri.Port.Len
	}
	if hostEnd == 0 {
		hostEnd = uri.Host.Offs + uri.Host.Len
	}
	if hostEnd > 0 {
		eHost = append(dst[:len(eUser)+1], src[uri.Host.Offs:hostEnd]...)
		if eHost, err = PKCSPad(eHost, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's host part: %w", err)
		}
		// 4. encrypt host+port+params+header
		uriCBC.Host.Encrypter.CryptBlocks(eHost, eHost)
	}
	return nil
}

// CBCDecryptURI decrypts the user info and host part of uri preserving the generic URI format userinfo@hostinfo.
// The decrypted URI for user@host is AES_CBC_DECRYPT(user)@AES_CBC_DECRYPT(host)
// dst should be least uri.User.Len+uri.Host.Len bytes long
func (uri *AnonymURI) CBCDecrypt(dst, src []byte) (err error) {
	var user []byte
	blockSize := uriCBC.User.Decrypter.BlockSize()
	//dst := make([]byte, uri.User.Len+uri.Host.Len)
	uriCBC.User.Decrypter.CryptBlocks(dst, src[:uri.User.Offs+uri.User.Len])
	if user, err = PKCSUnpad(dst[:uri.User.Offs+uri.User.Len], blockSize); err != nil {
		return fmt.Errorf("cannot decrypt URI's user part: %w", err)
	}
	l := len(user)
	dst = append(dst[0:l], '@')
	uriCBC.Host.Decrypter.CryptBlocks(dst[l+1:], src[:uri.Host.Offs+uri.Host.Len])
	if _, err = PKCSUnpad(dst[l+1:], blockSize); err != nil {
		return fmt.Errorf("cannot decrypt URI's host part: %w", err)
	}
	return nil
}
