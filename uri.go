package anonymization

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

const (
	// maximum size allowed for an SIP URI is 2KB; with padding this results in at most 4KB
	maxBufSize int = 1 << 12
	// padding character used in base32 encoding
	pad rune = '-'
)

// static buffers for encryption/decryption
var (
	encryptBuf [maxBufSize]byte
	decryptBuf [maxBufSize]byte
	encodeBuf  [maxBufSize]byte
	decodeBuf  [maxBufSize]byte
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
	// URI CBC cipher
	uriCBC = UriCBC{}
	//uriGCM = UriGCM{}
)

func NewEncoding() *base32.Encoding {
	return base32.HexEncoding.WithPadding(pad)
}

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

func EncryptBuf() []byte {
	return encryptBuf[:]
}

func DecryptBuf() []byte {
	return decryptBuf[:]
}

func EncodeBuf() []byte {
	return encodeBuf[:]
}

func DecodeBuf() []byte {
	return decodeBuf[:]
}

type AnonymURI sipsp.PsipURI

func (uri AnonymURI) String(buf []byte) string {
	scheme := string(buf[uri.Scheme.Offs : uri.Scheme.Offs+uri.Scheme.Len])
	user := string(buf[uri.User.Offs : uri.User.Offs+uri.User.Len])
	pass := string(buf[uri.Pass.Offs : uri.Pass.Offs+uri.Pass.Len])
	host := string(buf[uri.Host.Offs : uri.Host.Offs+uri.Host.Len])
	port := string(buf[uri.Port.Offs : uri.Port.Offs+uri.Port.Len])
	params := string(buf[uri.Params.Offs : uri.Params.Offs+uri.Params.Len])
	headers := string(buf[uri.Headers.Offs : uri.Headers.Offs+uri.Headers.Len])
	s := scheme
	if uri.User.Len > 0 {
		s += user + pass + "@"
	}
	s += host + port + params + headers
	return s
}

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

func (uri AnonymURI) copyScheme(dst, src []byte) sipsp.OffsT {
	_ = copy(dst, src[uri.Scheme.Offs:uri.Scheme.Offs+uri.Scheme.Len])
	return uri.Scheme.Len
}

func (uri AnonymURI) userPassLen() sipsp.OffsT {
	return uri.Pass.Len + uri.User.Len
}

func (uri AnonymURI) userPassEnd() sipsp.OffsT {
	end := uri.Pass.Offs + uri.Pass.Len
	if end == 0 {
		end = uri.User.Offs + uri.User.Len
	}
	return end
}

func (uri AnonymURI) hostPortParamsHeadersLen() sipsp.OffsT {
	return uri.Headers.Len + uri.Params.Len +
		uri.Port.Len + uri.Host.Len
}

func (uri AnonymURI) hostPortParamsHeadersEnd() sipsp.OffsT {
	end := uri.Headers.Offs + uri.Headers.Len
	if end == 0 {
		end = uri.Params.Offs + uri.Params.Len
	}
	if end == 0 {
		end = uri.Port.Offs + uri.Port.Len
	}
	if end == 0 {
		end = uri.Host.Offs + uri.Host.Len
	}
	return end
}

// CBCEncrypt encrypts the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The encrypted URI for sip:user@host is sip:AES_CBC_ENCRYPT(user)@AES_CBC_ENCRYPT(host)
func (uri *AnonymURI) CBCEncrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		paddedLen    int
		eUser, eHost []byte
		offs         int
	)
	blockSize := uriCBC.User.Encrypter.BlockSize()
	// 1. check dst len
	if paddedLen, err = uri.PKCSPaddedLen(blockSize); err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
	}
	if paddedLen > len(dst) {
		return fmt.Errorf("buffer for encrypted URI is too small: %d bytes (need %d bytes)",
			len(dst), paddedLen+1)
	}
	// 2. copy sip scheme
	offs = int(uri.copyScheme(dst, src))
	// 3. copy, pad & encrypt user+pass
	userEnd := uri.userPassEnd()
	if userEnd > 0 {
		_ = copy(dst[offs:], src[uri.User.Offs:userEnd])
		eUser = dst[offs : offs+int(userEnd-uri.User.Offs)]
		if eUser, err = PKCSPad(eUser, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's user part: %w", err)
		}
		Dbg("padded eUser: %v\n", eUser)
		uri.User.Offs = sipsp.OffsT(offs)
		uri.User.Len = sipsp.OffsT(len(eUser))
		uri.Pass.Offs, uri.Pass.Len = 0, 0
		// 2. encrypt (user+pass)
		uriCBC.User.Encrypter.CryptBlocks(eUser, eUser)
		Dbg("encrypted eUser: %v\n", eUser)
		offs = int(uri.User.Offs + uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. copy, pad & encrypt host+port+params+header
	hostEnd := uri.hostPortParamsHeadersEnd()
	if hostEnd > 0 {
		_ = copy(dst[offs:], src[uri.Host.Offs:hostEnd])
		eHost = dst[offs : offs+int(hostEnd-uri.Host.Offs)]
		if eHost, err = PKCSPad(eHost, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's host part: %w", err)
		}
		Dbg("padded eHost: %v\n", eHost)
		uri.Host.Offs = sipsp.OffsT(offs)
		uri.Host.Len = sipsp.OffsT(len(eHost))
		uri.Headers.Offs, uri.Headers.Len = 0, 0
		uri.Params.Offs, uri.Params.Len = 0, 0
		uri.Port.Offs, uri.Port.Len = 0, 0
		// 4. encrypt host+port+params+header
		uriCBC.Host.Encrypter.CryptBlocks(eHost, eHost)
		Dbg("encrypted eHost: %v (offs: %d len: %d)\n", eHost, int(uri.Host.Offs), int(uri.Host.Len))
	}
	Dbg("dst: %v\n", dst)
	return nil
}

// CBCDecrypt decrypts the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The decrypted URI for sip:user@host is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(hostinfo)
func (uri *AnonymURI) CBCDecrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		user []byte
		host []byte
		offs int = 0
	)
	blockSize := uriCBC.User.Decrypter.BlockSize()
	// copy the SIP scheme
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
		uri.Pass.Offs, uri.Pass.Len = 0, 0
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
	uri.Headers.Offs, uri.Headers.Len = 0, 0
	uri.Params.Offs, uri.Params.Len = 0, 0
	uri.Port.Offs, uri.Port.Len = 0, 0
	return nil
}

func (uri AnonymURI) EncodedLen(buf []byte) (l int) {
	l = int(uri.Scheme.Len)
	codec := NewEncoding()
	userEnd := uri.userPassEnd()
	if userEnd > 0 {
		l += codec.EncodedLen(len(buf[uri.User.Offs:userEnd]))
		// add 1 byte for '@'
		l++
	}
	hostEnd := uri.hostPortParamsHeadersEnd()
	if hostEnd > 0 {
		l += codec.EncodedLen(len(buf[uri.Host.Offs:hostEnd]))
	}
	return l
}

func (uri AnonymURI) DecodedLen(buf []byte) (l int) {
	l = int(uri.Scheme.Len)
	codec := NewEncoding()
	userEnd := uri.userPassEnd()
	if userEnd > 0 {
		l += codec.DecodedLen(len(buf[uri.User.Offs:userEnd]))
		// add 1 byte for '@'
		l++
	}
	hostEnd := uri.hostPortParamsHeadersEnd()
	if hostEnd > 0 {
		l += codec.DecodedLen(len(buf[uri.Host.Offs:hostEnd]))
	}
	return l
}

// Encode encodes using base32 the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The encoded URI for sip:user@host is sip:base32(userinfo)@base32(hostinfo)
func (uri *AnonymURI) Encode(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		offs int = 0
	)
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < uri.EncodedLen(src) {
		return fmt.Errorf("\"dst\" buffer too small for encoded URI (%d bytes required and %d bytes available)",
			len(dst), uri.EncodedLen(src))
	}
	// 2. copy sip scheme
	offs = int(uri.copyScheme(dst, src))
	// 3. encode user+pass
	userEnd := uri.userPassEnd()
	if userEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.User.Offs), int(userEnd))
		user := pf.Get(src)
		Dbg("user: %v\n", user)
		ePf := sipsp.PField{
			Offs: uri.User.Offs,
			Len:  sipsp.OffsT(codec.EncodedLen(len(user))),
		}
		eUser := ePf.Get(dst)
		codec.Encode(eUser, user)
		uri.User.Len = sipsp.OffsT(len(eUser))
		uri.Pass.Offs, uri.Pass.Len = 0, 0
		Dbg("encoded eUser: %v\n", eUser)
		offs = int(uri.User.Offs + uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. encode host+port+params+header
	hostEnd := uri.hostPortParamsHeadersEnd()
	if hostEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.Host.Offs), int(hostEnd))
		host := pf.Get(src)
		Dbg("len(host): %d codec.EncodedLen(len(host)): %d\n", len(host), codec.EncodedLen(len(host)))
		ePf := sipsp.PField{
			Offs: sipsp.OffsT(offs),
			Len:  sipsp.OffsT(codec.EncodedLen(len(host))),
		}
		eHost := ePf.Get(dst)
		codec.Encode(eHost, host)
		uri.Headers.Offs, uri.Headers.Len = 0, 0
		uri.Params.Offs, uri.Params.Len = 0, 0
		uri.Port.Offs, uri.Port.Len = 0, 0
		uri.Host.Offs = sipsp.OffsT(offs)
		uri.Host.Len = sipsp.OffsT(len(eHost))
		Dbg("encoded eHost: %v\n", eHost)
	}
	return nil
}

// Decode decodes using base32 the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The decoded URI for sip:base32(userinfo)@base32(hostinfo) is sip:userinfo@hostinfo
func (uri *AnonymURI) Decode(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		offs int = 0
	)
	codec := NewEncoding()
	if len(dst) < uri.DecodedLen(src) {
		return fmt.Errorf("\"dst\" buffer too small for decoded URI (%d bytes required and %d bytes available)",
			len(dst), codec.DecodedLen(len(src)))
	}
	// copy the SIP scheme
	offs = int(uri.copyScheme(dst, src))
	// 3. encode user+pass
	userEnd := uri.userPassEnd()
	if userEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.User.Offs), int(userEnd))
		user := pf.Get(src)
		Dbg("user: %v %s\n", user, string(user))
		ePf := sipsp.PField{
			Offs: uri.User.Offs,
			Len:  sipsp.OffsT(codec.DecodedLen(len(user))),
		}
		eUser := ePf.Get(dst)
		n, err := codec.Decode(eUser, user)
		if err != nil {
			return fmt.Errorf("error decoding URI user part: %w", err)
		}
		uri.User.Len = sipsp.OffsT(n)
		uri.Pass.Offs, uri.Pass.Len = 0, 0
		Dbg("decoded eUser: %v\n", eUser[:n])
		offs = int(uri.User.Offs + uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. encode host+port+params+header
	hostEnd := uri.hostPortParamsHeadersEnd()
	if hostEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.Host.Offs), int(hostEnd))
		host := pf.Get(src)
		ePf := sipsp.PField{
			Offs: sipsp.OffsT(offs),
			Len:  sipsp.OffsT(codec.DecodedLen(len(host))),
		}
		eHost := ePf.Get(dst)
		n, err := codec.Decode(eHost, host)
		if err != nil {
			return fmt.Errorf("error decoding URI host part: %w", err)
		}
		uri.Headers.Offs, uri.Headers.Len = 0, 0
		uri.Params.Offs, uri.Params.Len = 0, 0
		uri.Port.Offs, uri.Port.Len = 0, 0
		uri.Host.Offs = sipsp.OffsT(offs)
		uri.Host.Len = sipsp.OffsT(n)
		Dbg("encoded eHost: %v\n", eHost[:n])
	}
	return nil
}
