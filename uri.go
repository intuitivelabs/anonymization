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

// static buffers for encryption, encoding, anonymization
var (
	encryptBuf [maxBufSize]byte
	decryptBuf [maxBufSize]byte
	encodeBuf  [maxBufSize]byte
	decodeBuf  [maxBufSize]byte
	anonBuf    [maxBufSize]byte
	deanonBuf  [maxBufSize]byte
)

type BlockModeCipher struct {
	IV        []byte
	Key       []byte
	Block     cipher.Block
	Encrypter cipher.BlockMode
	Decrypter cipher.BlockMode
}

type UriCBCMode struct {
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
	uriCBC = UriCBCMode{}
	//uriGCM = UriGCM{}
)

func NewEncoding() *base32.Encoding {
	return base32.HexEncoding.WithPadding(pad)
}

func NewUriCBC(iv, userKey, hostKey []byte) *UriCBCMode {
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

func UriCBC() *UriCBCMode {
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

func AnonymizeBuf() []byte {
	return anonBuf[:]
}

func DeanonymizeBuf() []byte {
	return deanonBuf[:]
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

func (uri AnonymURI) copyScheme(dst, src []byte) sipsp.OffsT {
	//_ = copy(dst, src[uri.Scheme.Offs:uri.Scheme.Offs+uri.Scheme.Len])
	_ = copy(dst, uri.Scheme.Get(src))
	return uri.Scheme.Len
}

// copyPortParamsHeaders copies "port;uri-parameter?headers" part of the SIP URI from src to dst; it properly
// appends one of the separators [:;?] to dst. It assumes that PFields up to Host belong to dst and from Port on they belong to src.
// It updates the Port, Params, Headers offsets
func (uri *AnonymURI) copyPortParamsHeaders(dst, src []byte) sipsp.OffsT {
	df := DbgOn()
	defer DbgRestore(df)
	pph := uri.PortParamsHeaders(src)
	if pph == nil {
		return 0
	}
	Dbg("pph: %v %s", pph, string(pph))
	offs := int(uri.Host.Offs + uri.Host.Len)
	if uri.Port.Offs > 0 && uri.Port.Len > 0 {
		// write ':' into dst
		dst[offs] = ':'
	} else if uri.Params.Offs > 0 && uri.Params.Len > 0 {
		// write ';' into dst
		dst[offs] = ';'
	} else if uri.Headers.Offs > 0 && uri.Headers.Len > 0 {
		// write '?' into dst
		dst[offs] = '?'
	}
	offs++
	_ = copy(dst[offs:], pph)
	Dbg("offs: %d dst[offs:]: %v", offs, dst[offs:])
	if uri.Port.Offs > 0 {
		uri.Port.Offs = sipsp.OffsT(offs)
		Dbg("uri.Port.Offs: %d", offs)
		offs += int(uri.Port.Len)
	}
	if uri.Params.Offs > 0 {
		if uri.Port.Offs > 0 {
			// increase offset past the `;` separator
			offs++
		}
		uri.Params.Offs = sipsp.OffsT(offs)
		Dbg("uri.Param.Offs: %d", offs)
		offs += int(uri.Params.Len)
	}
	if uri.Headers.Offs > 0 {
		if uri.Params.Offs > 0 || uri.Port.Offs > 0 {
			// increase offset past the `?` separator
			offs++
		}
		uri.Headers.Offs = sipsp.OffsT(offs)
		Dbg("uri.Headers.Offs: %d", offs)
		offs += int(uri.Headers.Len)
	}
	return 1 + uri.Port.Len + uri.Params.Len + uri.Headers.Len
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

func (uri AnonymURI) hostEnd() sipsp.OffsT {
	return uri.Host.Offs + uri.Host.Len
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

func (uri AnonymURI) portParamsHeadersEnd() sipsp.OffsT {
	df := DbgOn()
	defer DbgRestore(df)
	end := uri.Headers.Offs + uri.Headers.Len
	if end != 0 {
		Dbg("pph.end: %d, uri.Headers.Offs: %d", end, uri.Headers.Offs)
		return end
	}
	end = uri.Params.Offs + uri.Params.Len
	if end != 0 {
		Dbg("pph end: %d, uri.Params.Offs: %d", end, uri.Params.Offs)
		return end
	}
	end = uri.Port.Offs + uri.Port.Len
	Dbg("pph end: %d, uri.Port.Offs: %d", end, uri.Port.Offs)
	return end
}

func (uri AnonymURI) portParamsHeadersStart() sipsp.OffsT {
	df := DbgOn()
	defer DbgRestore(df)
	start := uri.Port.Offs
	if start != 0 {
		Dbg("pph start: uri.Port.Offs: %d", start)
		return start
	}
	start = uri.Params.Offs
	if start != 0 {
		Dbg("pph start: uri.Params.offs: %d", start)
		return start
	}
	start = uri.Headers.Offs
	Dbg("pph start: uri.Headers.offs: %d", start)
	return start
}

// PortParamsHeaders returns a slice containing the "port;uri-parameter?headers" part of the SIP URI
func (uri AnonymURI) PortParamsHeaders(buf []byte) []byte {
	start := uri.portParamsHeadersStart()
	end := uri.portParamsHeadersEnd()
	// the `port` cannot have the offset 0 in an SIP URI
	if start == 0 || end == 0 {
		return nil
	}
	return buf[start:end]
}

// CBCEncrypt encrypts the user info and host part of uri preserving SIP URI format.
// The general form of the SIP URI is:
// sip:user:password@host:port;uri-parameters?headers
// By default (opts not specified or opt[0] is false), the encrypted URI is:
// sip:AES_CBC_ENCRYPT(user:password)@AES_CBC_ENCRYPT(host:port;uri-parameters?headers)
// If opts[0] is true, the encrypted URI is:
// sip:AES_CBC_ENCRYPT(user:password)@AES_CBC_ENCRYPT(host):port;uri-parameters?headers
func (uri *AnonymURI) CBCEncrypt(dst, src []byte, opts ...bool) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		onlyHost  bool = false
		paddedLen int
		offs      int
	)
	if len(opts) > 0 {
		onlyHost = opts[0]
	}
	blockSize := UriCBC().User.Encrypter.BlockSize()
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
		pf := sipsp.PField{}
		pf.Set(int(uri.User.Offs), int(userEnd))
		user := pf.Get(src)
		_ = copy(dst[offs:], user)
		ePf := sipsp.PField{}
		ePf.Set(int(uri.User.Offs), int(userEnd))
		eUser := ePf.Get(dst)
		if eUser, err = PKCSPad(eUser, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's user part: %w", err)
		}
		Dbg("padded eUser: %v", eUser)
		uri.User.Offs = sipsp.OffsT(offs)
		uri.User.Len = sipsp.OffsT(len(eUser))
		uri.Pass.Offs, uri.Pass.Len = 0, 0
		// 2. encrypt (user+pass)
		UriCBC().User.Encrypter.CryptBlocks(eUser, eUser)
		Dbg("encrypted eUser: %v", eUser)
		offs = int(uri.User.Offs + uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. copy, pad & encrypt `host`+`port`+`params`+`header`
	hostEnd := uri.hostPortParamsHeadersEnd()
	if onlyHost {
		// 4. copy, pad & encrypt `host`
		hostEnd = uri.hostEnd()
	}
	if hostEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.Host.Offs), int(hostEnd))
		host := pf.Get(src)
		_ = copy(dst[offs:], host)
		ePf := sipsp.PField{
			Offs: sipsp.OffsT(offs),
			Len:  hostEnd - uri.Host.Offs,
		}
		eHost := ePf.Get(dst)
		if eHost, err = PKCSPad(eHost, blockSize); err != nil {
			return fmt.Errorf("cannot encrypt URI's host part: %w", err)
		}
		Dbg("padded eHost: %v", eHost)
		uri.Host.Offs = sipsp.OffsT(offs)
		uri.Host.Len = sipsp.OffsT(len(eHost))
		offs += len(eHost)
		// 4. encrypt host+port+params+header
		UriCBC().Host.Encrypter.CryptBlocks(eHost, eHost)
		Dbg("encrypted eHost: %v (offs: %d len: %d)", eHost, int(uri.Host.Offs), int(uri.Host.Len))
	}
	if onlyHost {
		// 5. copy `port`+`params`+`header`
		_ = uri.copyPortParamsHeaders(dst, src)
	} else {
		// 5. set the Offs, Len for everything on rhs besides `host` to 0
		uri.Headers.Offs, uri.Headers.Len = 0, 0
		uri.Params.Offs, uri.Params.Len = 0, 0
		uri.Port.Offs, uri.Port.Len = 0, 0
	}
	Dbg("dst: %v", dst)
	return nil
}

// CBCDecrypt decrypts the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The decrypted URI for sip:user@host is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(hostinfo)
// The decrypted URI for sip:user@host:port;params?headers is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(host):port;params?headers
// The decrypted URI for sip:user@host;params?headers is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(host);params?headers
// The decrypted URI for sip:user@host?headers is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(host)?headers
func (uri *AnonymURI) CBCDecrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	blockSize := UriCBC().User.Decrypter.BlockSize()
	// copy the SIP scheme
	offs := int(uri.copyScheme(dst, src))
	if uri.User.Len > 0 {
		dPf := sipsp.PField{
			Offs: sipsp.OffsT(offs),
			Len:  uri.User.Len,
		}
		dUser := dPf.Get(dst)
		pf := sipsp.PField{
			Offs: uri.User.Offs,
			Len:  uri.User.Len,
		}
		user := pf.Get(src)
		UriCBC().User.Decrypter.CryptBlocks(dUser, user)
		Dbg("decrypted user part (padded): %v", dUser)
		if user, err = PKCSUnpad(dUser, blockSize); err != nil {
			return fmt.Errorf("cannot decrypt URI's user part: %w", err)
		}
		Dbg("decrypted user part (un-padded): %v %s", user, string(user))
		l := len(user)
		uri.User.Offs = sipsp.OffsT(offs)
		uri.User.Len = sipsp.OffsT(l)
		uri.Pass.Offs, uri.Pass.Len = 0, 0
		offs = int(uri.User.Offs + uri.User.Len)
		dst[offs] = '@'
		offs++
		Dbg("len(dst[offs:]): %d", len(dst[offs:]))
	}
	dPf := sipsp.PField{
		Offs: sipsp.OffsT(offs),
		Len:  uri.Host.Len,
	}
	dHost := dPf.Get(dst)
	pf := sipsp.PField{
		Offs: uri.Host.Offs,
		Len:  uri.Host.Len,
	}
	host := pf.Get(src)
	Dbg("host offs: %d host len : %d", int(uri.Host.Offs), int(uri.Host.Len))
	UriCBC().Host.Decrypter.CryptBlocks(dHost, host)
	Dbg("decrypted host part (padded): %v", dHost)
	uri.Host.Offs = sipsp.OffsT(offs)
	if host, err = PKCSUnpad(dHost, blockSize); err != nil {
		return fmt.Errorf("cannot decrypt URI's host part: %w", err)
	}
	Dbg("decrypted host part (un-padded): %v %s", host, string(host))
	uri.Host.Len = sipsp.OffsT(len(host))
	_ = uri.copyPortParamsHeaders(dst, src)
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
		Dbg("user: %v", user)
		ePf := sipsp.PField{
			Offs: uri.User.Offs,
			Len:  sipsp.OffsT(codec.EncodedLen(len(user))),
		}
		eUser := ePf.Get(dst)
		codec.Encode(eUser, user)
		uri.User.Len = sipsp.OffsT(len(eUser))
		uri.Pass.Offs, uri.Pass.Len = 0, 0
		Dbg("encoded eUser: %v", eUser)
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
		Dbg("len(host): %d codec.EncodedLen(len(host)): %d", len(host), codec.EncodedLen(len(host)))
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
		Dbg("encoded eHost: %v", eHost)
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
		Dbg("user: %v %s", user, string(user))
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
		Dbg("decoded eUser: %v", eUser[:n])
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
		Dbg("encoded eHost: %v", eHost[:n])
	}
	return nil
}

func (uri *AnonymURI) Anonymize(dst, src []byte) (err error) {
	ciphertxt := EncryptBuf()
	if err = uri.CBCEncrypt(ciphertxt, src); err != nil {
		return fmt.Errorf("cannot anonymize URI: %w", err)
	}
	if err = uri.Encode(dst, ciphertxt); err != nil {
		return fmt.Errorf("cannot anonymize URI: %w", err)
	}
	return nil
}

func (uri *AnonymURI) Deanonymize(dst, src []byte) (err error) {
	decoded := DecodeBuf()
	if err = uri.Decode(decoded, src); err != nil {
		return fmt.Errorf("cannot deanonymize URI: %w", err)
	}
	if err = uri.CBCDecrypt(dst, decoded); err != nil {
		return fmt.Errorf("cannot deanonymize URI: %w", err)
	}
	return nil
}
