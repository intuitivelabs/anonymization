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

// PKCSPaddedLen computes the length of URI with the userpart and host padded to a multiple of size.
// Scheme and separator '@' are not padded.
func (uri *AnonymURI) PKCSPaddedLen(size int) (int, error) {
	var (
		err                                  error
		sepLen, hLen, uLen, hPadLen, uPadLen int = 0, 0, 0, 0, 0
	)
	uLen = int(uri.Pass.Len + uri.User.Len)
	if uLen > 0 {
		if uPadLen, err = PKCSPadLen(uLen, size); err != nil {
			return 0, fmt.Errorf("cannot pad uri's user part: %w", err)
		}
		uLen += uPadLen
		sepLen = 1
	}
	hLen = int(uri.Headers.Len + uri.Params.Len + uri.Port.Len + uri.Host.Len)
	if hPadLen, err = PKCSPadLen(hLen, size); err != nil {
		return 0, fmt.Errorf("cannot pad uri's host part: %w", err)
	}
	hLen += hPadLen
	return uLen + hLen + int(uri.Scheme.Len) + sepLen, nil
}

// CBCEncryptURI encrypts the user info and host part of uri preserving the generic URI format userinfo@hostinfo.
// The encrypted URI for user@host is AES_CBC_ENCRYPT(user)@AES_CBC_ENCRYPT(host)
func (uri *AnonymURI) CBCEncrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		paddedLen    int
		eUser, eHost []byte
		offs         int
	)
	blockSize := uriCBC.User.Encrypter.BlockSize()
	// 0. check dst len
	if paddedLen, err = uri.PKCSPaddedLen(blockSize); err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
	}
	if paddedLen > len(dst) {
		return fmt.Errorf("buffer for encrypted URI is too small: %d bytes (need %d bytes)",
			len(dst), paddedLen+1)
	}
	// append sip scheme
	_ = copy(dst, src[uri.Scheme.Offs:uri.Scheme.Offs+uri.Scheme.Len])
	offs = int(uri.Scheme.Len)
	// 1. copy & pad user+pass
	userEnd := uri.Pass.Offs + uri.Pass.Len
	if userEnd == 0 {
		userEnd = uri.User.Offs + uri.User.Len
	}
	if userEnd > 0 {
		_ = copy(dst[offs:], src[uri.User.Offs:userEnd])
		eUser = dst[offs : offs+int(userEnd-uri.User.Offs)]
		if eUser, err = PKCSPad(eUser, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's user part: %w", err)
		}
		Dbg("padded eUser: %v\n", eUser)
		uri.User.Offs = sipsp.OffsT(offs)
		uri.User.Len = sipsp.OffsT(len(eUser))
		// 2. encrypt (user+pass)
		uriCBC.User.Encrypter.CryptBlocks(eUser, eUser)
		Dbg("encrypted eUser: %v\n", eUser)
		offs = int(uri.User.Offs + uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
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
		_ = copy(dst[offs:], src[uri.Host.Offs:hostEnd])
		eHost = dst[offs : offs+int(hostEnd-uri.Host.Offs)]
		if eHost, err = PKCSPad(eHost, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's host part: %w", err)
		}
		Dbg("padded eHost: %v\n", eHost)
		uri.Host.Offs = sipsp.OffsT(offs)
		uri.Host.Len = sipsp.OffsT(len(eHost))
		// 4. encrypt host+port+params+header
		uriCBC.Host.Encrypter.CryptBlocks(eHost, eHost)
		Dbg("encrypted eHost: %v (offs: %d len: %d)\n", eHost, int(uri.Host.Offs), int(uri.Host.Len))
	}
	Dbg("dst: %v\n", dst)
	return nil
}

// CBCDecryptURI decrypts the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The decrypted URI for sip:user@host is sip:AES_CBC_DECRYPT(user)@AES_CBC_DECRYPT(host)
// dst should be least uri.User.Len+uri.Host.Len bytes long
func (uri *AnonymURI) CBCDecrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		user []byte
		host []byte
		offs int = 0
	)
	blockSize := uriCBC.User.Decrypter.BlockSize()
	// append the SIP scheme
	_ = copy(dst, src[uri.Scheme.Offs:uri.Scheme.Offs+uri.Scheme.Len])
	offs = int(uri.Scheme.Len)
	if uri.User.Len > 0 {
		dUser := dst[offs : offs+int(uri.User.Len)]
		uriCBC.User.Decrypter.CryptBlocks(dUser, src[uri.User.Offs:uri.User.Offs+uri.User.Len])
		Dbg("decrypted user part (padded): %v\n", dUser)
		if user, err = PKCSUnpad(dUser, blockSize); err != nil {
			return fmt.Errorf("cannot decrypt URI's user part: %w", err)
		}
		Dbg("decrypted user part (un-padded): %v %s\n", user, string(user))
		l := len(user)
		uri.User.Offs = sipsp.OffsT(offs)
		uri.User.Len = sipsp.OffsT(l)
		offs = int(uri.User.Offs + uri.User.Len)
		dst[offs] = '@'
		offs++
		Dbg("len(dst[offs:]): %d\n", len(dst[offs:]))
	}
	dHost := dst[offs : offs+int(uri.Host.Len)]
	Dbg("host offs: %d host len : %d\n", int(uri.Host.Offs), int(uri.Host.Len))
	uriCBC.Host.Decrypter.CryptBlocks(dHost, src[uri.Host.Offs:uri.Host.Offs+uri.Host.Len])
	Dbg("decrypted host part (padded): %v\n", dHost)
	if host, err = PKCSUnpad(dHost, blockSize); err != nil {
		return fmt.Errorf("cannot decrypt URI's host part: %w", err)
	}
	Dbg("decrypted host part (un-padded): %v %s\n", host, string(host))
	uri.Host.Offs = sipsp.OffsT(offs)
	uri.Host.Len = sipsp.OffsT(len(host))
	return nil
}
