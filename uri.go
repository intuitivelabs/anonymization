package anonymization

import (
	"crypto/aes"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

const (
	// maximum size allowed for an SIP URI is 2KB; with padding this results in at most 4KB
	uriMaxBufSize int = 1 << 12
	// salt used for generating URI encryption keys
	SaltUriIV = "1190e68008426899bc48fe7719c2ffb7"
	SaltUriUK = "e3ab68497b69d87ddf6b5d97e24b6bb1"
	SaltUriHK = "23c1be46c4af62a6c6be8c860e2f13bc"
)

type UriCBCMode struct {
	// user part cipher (key SHOULD be different from host part cipher)
	User BlockModeCipher
	// host part cipher (key SHOULD be different from user part cipher)
	Host BlockModeCipher
}

type UriKeys struct {
	// initialization vector
	IV [EncryptionKeyLen]byte
	// encryption key used for user info
	UserKey [EncryptionKeyLen]byte
	// encryption key used for host info
	HostKey [EncryptionKeyLen]byte
}

var (
	UriUsernameSalt = Salt{
		Key: SaltUriUK,
		IV:  SaltUriIV,
	}
	UriHostSalt = Salt{
		Key: SaltUriHK,
		IV:  SaltUriIV,
	}
	uriKeys = UriKeys{}
	// URI CBC cipher
	uriCBC = UriCBCMode{}
	//uriGCM = UriGCM{}
)

// generate IV for CBC
func GenerateUriIV(masterKey []byte, ivLen int, iv []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltUriIV, masterKey, ivLen, iv)
}

// generate key for URI's user part
func GenerateURIUserKey(masterKey []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltUriUK, masterKey, keyLen, key)
}

// generate key for URI's host part
func GenerateURIHostKey(masterKey []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltUriHK, masterKey, keyLen, key)
}

func NewUriCBCWithMasterKey(masterKey []byte) *UriCBCMode {
	InitUriKeysFromMasterKey(masterKey)
	return NewUriCBC(GetUriKeys())
}

func NewUriCBC(keys *UriKeys) *UriCBCMode {
	if block, err := aes.NewCipher(keys.UserKey[:]); err != nil {
		panic(err)
	} else {
		uriCBC.User.Init(keys.IV[:], keys.UserKey[:], block)
	}
	if block, err := aes.NewCipher(keys.HostKey[:]); err != nil {
		panic(err)
	} else {
		uriCBC.Host.Init(keys.IV[:], keys.HostKey[:], block)
	}
	return &uriCBC
}

func UriCBC() *UriCBCMode {
	return &uriCBC
}

func InitUriKeys(iv []byte, uk []byte, hk []byte) {
	copy(GetUriKeys().IV[:], iv)
	copy(GetUriKeys().UserKey[:], uk)
	copy(GetUriKeys().HostKey[:], hk)
}

func InitUriKeysFromMasterKey(masterKey []byte) {
	// generate IV for CBC
	GenerateUriIV(masterKey[:], EncryptionKeyLen, GetUriKeys().IV[:])
	// generate key for URI's user part
	GenerateURIUserKey(masterKey[:], EncryptionKeyLen, GetUriKeys().UserKey[:])
	// generate key for URI's host part
	GenerateURIHostKey(masterKey[:], EncryptionKeyLen, GetUriKeys().HostKey[:])
}

func GetUriKeys() *UriKeys {
	return &uriKeys
}

type AnonymURI struct {
	uri sipsp.PsipURI
	cbc UriCBCMode
}

func NewAnonymURI(key []byte) *AnonymURI {
	a := AnonymURI{}
	a.cbc = *NewUriCBCWithMasterKey(key)
	return &a
}

func (au AnonymURI) Flat(src []byte) []byte {
	return (&au.uri).Flat(src)
}

func (au *AnonymURI) Parse(src []byte) error {
	(&au.uri).Reset()
	err, _ := sipsp.ParseURI(src, &au.uri)
	if err == 0 {
		return nil
	}
	return err
}

func (au *AnonymURI) hostToLower(buf []byte) {
	host := au.uri.Host.Get(buf)
	for i, c := range host {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		host[i] = c
	}
}

// PKCSPaddedLen computes the length of URI with the userpart and host padded to a multiple of size.
// Scheme and separator '@' are not padded.
func (au *AnonymURI) PKCSPaddedLen(size int) (int, error) {
	var (
		err                                  error
		sepLen, hLen, uLen, hPadLen, uPadLen int = 0, 0, 0, 0, 0
	)
	uLen = int(au.uri.Pass.Len + au.uri.User.Len)
	if uLen > 0 {
		if uPadLen, err = PKCSPadLen(uLen, size); err != nil {
			return 0, fmt.Errorf("cannot pad uri's user part: %w", err)
		}
		uLen += uPadLen
		sepLen = 1
	}
	hLen = int(au.uri.Headers.Len + au.uri.Params.Len + au.uri.Port.Len + au.uri.Host.Len)
	if hPadLen, err = PKCSPadLen(hLen, size); err != nil {
		return 0, fmt.Errorf("cannot pad uri's host part: %w", err)
	}
	hLen += hPadLen
	return uLen + hLen + int(au.uri.Scheme.Len) + sepLen, nil
}

func (au AnonymURI) copyScheme(dst, src []byte) sipsp.OffsT {
	//_ = copy(dst, src[au.uri.Scheme.Offs:au.uri.Scheme.Offs+au.uri.Scheme.Len])
	_ = copy(dst, au.uri.Scheme.Get(src))
	return au.uri.Scheme.Len
}

// copyPortParamsHeaders copies "port;uri-parameter?headers" part of the SIP URI from src to dst; it properly
// appends one of the separators [:;?] to dst. It assumes that PFields up to Host belong to dst and from Port on they belong to src.
// It updates the Port, Params, Headers offsets
func (au *AnonymURI) copyPortParamsHeaders(dst, src []byte) sipsp.OffsT {
	df := DbgOn()
	defer DbgRestore(df)
	pph := au.PortParamsHeaders(src)
	if pph == nil {
		return 0
	}
	_ = WithDebug && Dbg("pph: %v %s", pph, string(pph))
	offs := int(au.uri.Host.Offs + au.uri.Host.Len)
	if au.uri.Port.Offs > 0 && au.uri.Port.Len > 0 {
		// write ':' into dst
		dst[offs] = ':'
	} else if au.uri.Params.Offs > 0 && au.uri.Params.Len > 0 {
		// write ';' into dst
		dst[offs] = ';'
	} else if au.uri.Headers.Offs > 0 && au.uri.Headers.Len > 0 {
		// write '?' into dst
		dst[offs] = '?'
	}
	offs++
	_ = copy(dst[offs:], pph)
	_ = WithDebug && Dbg("offs: %d dst[offs:]: %v", offs, dst[offs:])
	if au.uri.Port.Offs > 0 {
		au.uri.Port.Offs = sipsp.OffsT(offs)
		_ = WithDebug && Dbg("au.uri.Port.Offs: %d", offs)
		offs += int(au.uri.Port.Len)
	}
	if au.uri.Params.Offs > 0 {
		if au.uri.Port.Offs > 0 {
			// increase offset past the `;` separator
			offs++
		}
		au.uri.Params.Offs = sipsp.OffsT(offs)
		_ = WithDebug && Dbg("au.uri.Param.Offs: %d", offs)
		offs += int(au.uri.Params.Len)
	}
	if au.uri.Headers.Offs > 0 {
		if au.uri.Params.Offs > 0 || au.uri.Port.Offs > 0 {
			// increase offset past the `?` separator
			offs++
		}
		au.uri.Headers.Offs = sipsp.OffsT(offs)
		_ = WithDebug && Dbg("au.uri.Headers.Offs: %d", offs)
		offs += int(au.uri.Headers.Len)
	}
	return 1 + au.uri.Port.Len + au.uri.Params.Len + au.uri.Headers.Len
}

func (au AnonymURI) userPassLen() sipsp.OffsT {
	return au.uri.Pass.Len + au.uri.User.Len
}

func (au AnonymURI) userPassEnd() sipsp.OffsT {
	end := au.uri.Pass.Offs + au.uri.Pass.Len
	if end == 0 {
		end = au.uri.User.Offs + au.uri.User.Len
	}
	return end
}

func (au AnonymURI) hostEnd() sipsp.OffsT {
	return au.uri.Host.Offs + au.uri.Host.Len
}

func (au AnonymURI) hostPortParamsHeadersLen() sipsp.OffsT {
	return au.uri.Headers.Len + au.uri.Params.Len +
		au.uri.Port.Len + au.uri.Host.Len
}

func (au AnonymURI) hostPortParamsHeadersEnd() sipsp.OffsT {
	end := au.uri.Headers.Offs + au.uri.Headers.Len
	if end == 0 {
		end = au.uri.Params.Offs + au.uri.Params.Len
	}
	if end == 0 {
		end = au.uri.Port.Offs + au.uri.Port.Len
	}
	if end == 0 {
		end = au.uri.Host.Offs + au.uri.Host.Len
	}
	return end
}

func (au AnonymURI) portParamsHeadersEnd() sipsp.OffsT {
	df := DbgOn()
	defer DbgRestore(df)
	end := au.uri.Headers.Offs + au.uri.Headers.Len
	if end != 0 {
		_ = WithDebug && Dbg("pph.end: %d, au.uri.Headers.Offs: %d", end, au.uri.Headers.Offs)
		return end
	}
	end = au.uri.Params.Offs + au.uri.Params.Len
	if end != 0 {
		_ = WithDebug && Dbg("pph end: %d, au.uri.Params.Offs: %d", end, au.uri.Params.Offs)
		return end
	}
	end = au.uri.Port.Offs + au.uri.Port.Len
	_ = WithDebug && Dbg("pph end: %d, au.uri.Port.Offs: %d", end, au.uri.Port.Offs)
	return end
}

func (au AnonymURI) portParamsHeadersStart() sipsp.OffsT {
	df := DbgOn()
	defer DbgRestore(df)
	start := au.uri.Port.Offs
	if start != 0 {
		_ = WithDebug && Dbg("pph start: au.uri.Port.Offs: %d", start)
		return start
	}
	start = au.uri.Params.Offs
	if start != 0 {
		_ = WithDebug && Dbg("pph start: au.uri.Params.Offs: %d", start)
		return start
	}
	start = au.uri.Headers.Offs
	_ = WithDebug && Dbg("pph start: au.uri.Headers.Offs: %d", start)
	return start
}

// PortParamsHeaders returns a slice containing the "port;uri-parameter?headers" part of the SIP URI
func (au AnonymURI) PortParamsHeaders(buf []byte) []byte {
	start := au.portParamsHeadersStart()
	end := au.portParamsHeadersEnd()
	// the `port` cannot have the offset 0 in an SIP URI
	if start == 0 || end == 0 {
		return nil
	}
	return buf[start:end]
}

// cbcEncryptUserInfo encrypts the URI's user info (lhs of the `@`) from src into dst starting at offset offs when there is a non-empty user info;
// it returns the length of the encrypted user info. It returns a 0 length when there is no user info in the URI.
func (au *AnonymURI) cbcEncryptUserInfo(dst, src []byte, offs int) (int, error) {
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		dst = dst[offs:]
		pf := sipsp.PField{}
		pf.Set(int(au.uri.User.Offs), int(userEnd))
		au.cbc.User.Reset()
		l, err := cbcEncryptToken(dst, src, pf, au.cbc.User.Encrypter)
		if err != nil {
			return 0, fmt.Errorf("cannot encrypt user part: %w", err)
		}
		au.uri.User = sipsp.PField{
			Offs: sipsp.OffsT(offs),
			Len:  sipsp.OffsT(l),
		}
		au.uri.Pass = sipsp.PField{
			Offs: 0,
			Len:  0,
		}
		return l, nil
	}
	return 0, nil
}

// cbcEncryptHostInfo encrypts the URI's host info (rhs of the `@`) from src into dst starting at offset offs
// when there is a non-empty host info. The host part is lowercased before it is encrypted.
// It returns the length of the encrypted host info. It returns a 0 length when there is no user info in the URI.
// The boolean flag `onlyHost` indicates whether only the host name gets encrypted (true) or the whole rhs gets encrypted (false).
func (au *AnonymURI) cbcEncryptHostInfo(dst, src []byte, offs int, onlyHost bool) (l int, err error) {
	au.hostToLower(src)
	end := au.hostPortParamsHeadersEnd()
	if onlyHost {
		end = au.hostEnd()
	}
	if end > 0 {
		pf := sipsp.PField{}
		pf.Set(int(au.uri.Host.Offs), int(end))
		au.cbc.Host.Reset()
		l, err = cbcEncryptToken(dst[offs:], src, pf, au.cbc.Host.Encrypter)
		if err != nil {
			return 0, fmt.Errorf("cannot encrypt URI: %w", err)
		}
		// update Offs, Len
		au.uri.Host.Offs = sipsp.OffsT(offs)
		au.uri.Host.Len = sipsp.OffsT(l)
		offs += int(au.uri.Host.Len)
		if onlyHost {
			// 5. copy `port`+`params`+`header`
			l += int(au.copyPortParamsHeaders(dst, src))
		} else {
			// 5. set the Offs, Len for everything on rhs besides `host` to 0
			au.uri.Headers.Offs, au.uri.Headers.Len = 0, 0
			au.uri.Params.Offs, au.uri.Params.Len = 0, 0
			au.uri.Port.Offs, au.uri.Port.Len = 0, 0
		}
		return l, nil
	}
	return 0, nil
}

// CBCEncrypt encrypts the user info (lhs of `@`) and host info (rhs of `@`) of uri preserving SIP URI format.
// The general form of the SIP URI is:
// sip:user:password@host:port;uri-parameters?headers
// By default (opts not specified) or when opt[0] is false everything on the rhs of the @ is encrypted and the
// encrypted URI has the following format:
//
//   sip:AES_CBC_ENCRYPT(user:password)@AES_CBC_ENCRYPT(host:port;uri-parameters?headers)
//
// If opts[0] is true, only the host part of the URI is encrypted and the encrypted URI has the following format:
//
//   sip:AES_CBC_ENCRYPT(user:password)@AES_CBC_ENCRYPT(host):port;uri-parameters?headers
//
func (au *AnonymURI) CBCEncrypt(dst, src []byte, opts ...bool) (err error) {
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
	blockSize := au.cbc.User.Encrypter.BlockSize()
	// 1. check dst len
	if paddedLen, err = au.PKCSPaddedLen(blockSize); err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
	}
	if paddedLen > len(dst) {
		return fmt.Errorf("buffer for encrypted URI is too small: %d bytes (need %d bytes)",
			len(dst), paddedLen+1)
	}
	// 2. copy sip scheme
	offs = int(au.copyScheme(dst, src))
	_ = WithDebug && Dbg(`dst: "%s"`, string(dst[0:au.uri.Scheme.Len]))
	// 3. copy, pad & encrypt user+pass
	l, err := au.cbcEncryptUserInfo(dst, src, offs)
	if err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
	}
	if l > 0 {
		offs = int(au.uri.User.Offs + au.uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. copy, pad & encrypt `host`+`port`+`params`+`header`
	l, err = au.cbcEncryptHostInfo(dst, src, offs, onlyHost)
	if err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
	}
	_ = WithDebug && Dbg("dst: %v", dst)
	return nil
}

// CBCDecrypt decrypts the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The decrypted URI for sip:user@host is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(hostinfo)
// The decrypted URI for sip:user@host:port;params?headers is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(host):port;params?headers
// The decrypted URI for sip:user@host;params?headers is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(host);params?headers
// The decrypted URI for sip:user@host?headers is sip:AES_CBC_DECRYPT(userinfo)@AES_CBC_DECRYPT(host)?headers
func (au *AnonymURI) CBCDecrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	blockSize := au.cbc.User.Decrypter.BlockSize()
	// copy the SIP scheme
	offs := int(au.copyScheme(dst, src))
	if au.uri.User.Len > 0 {
		dPf := sipsp.PField{
			Offs: au.uri.User.Offs,
			Len:  au.uri.User.Len,
		}
		dUser := dPf.Get(dst)
		pf := sipsp.PField{
			Offs: au.uri.User.Offs,
			Len:  au.uri.User.Len,
		}
		user := pf.Get(src)
		_ = WithDebug && Dbg("encrypted user part: %v", user)
		au.cbc.User.Reset()
		au.cbc.User.Decrypter.CryptBlocks(dUser, user)
		_ = WithDebug && Dbg("decrypted user part (padded): %v", dUser)
		if user, err = PKCSUnpad(dUser, blockSize); err != nil {
			return fmt.Errorf("cannot decrypt URI's user part: %w", err)
		}
		_ = WithDebug && Dbg("decrypted user part (un-padded): %v %s", user, string(user))
		l := len(user)
		au.uri.User.Offs = sipsp.OffsT(offs)
		au.uri.User.Len = sipsp.OffsT(l)
		au.uri.Pass.Offs, au.uri.Pass.Len = 0, 0
		offs = int(au.uri.User.Offs + au.uri.User.Len)
		dst[offs] = '@'
		offs++
		_ = WithDebug && Dbg("len(dst[offs:]): %d", len(dst[offs:]))
	}
	dPf := sipsp.PField{
		Offs: sipsp.OffsT(offs),
		Len:  au.uri.Host.Len,
	}
	dHost := dPf.Get(dst)
	pf := sipsp.PField{
		Offs: au.uri.Host.Offs,
		Len:  au.uri.Host.Len,
	}
	host := pf.Get(src)
	_ = WithDebug && Dbg("host offs: %d host len : %d", int(au.uri.Host.Offs), int(au.uri.Host.Len))
	au.cbc.Host.Reset()
	au.cbc.Host.Decrypter.CryptBlocks(dHost, host)
	_ = WithDebug && Dbg("decrypted host part (padded): %v", dHost)
	au.uri.Host.Offs = sipsp.OffsT(offs)
	if host, err = PKCSUnpad(dHost, blockSize); err != nil {
		return fmt.Errorf("cannot decrypt URI's host part: %w", err)
	}
	_ = WithDebug && Dbg("decrypted host part (un-padded): %v %s", host, string(host))
	au.uri.Host.Len = sipsp.OffsT(len(host))
	_ = au.copyPortParamsHeaders(dst, src)
	return nil
}

func (au AnonymURI) EncodedLen(buf []byte) (l int) {
	l = int(au.uri.Scheme.Len)
	codec := NewEncoding()
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		l += codec.EncodedLen(len(buf[au.uri.User.Offs:userEnd]))
		// add 1 byte for '@'
		l++
	}
	hostEnd := au.hostPortParamsHeadersEnd()
	if hostEnd > 0 {
		l += codec.EncodedLen(len(buf[au.uri.Host.Offs:hostEnd]))
	}
	return l
}

func (au AnonymURI) DecodedLen(buf []byte) (l int) {
	l = int(au.uri.Scheme.Len)
	codec := NewEncoding()
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		l += codec.DecodedLen(len(buf[au.uri.User.Offs:userEnd]))
		// add 1 byte for '@'
		l++
	}
	if au.uri.Host.Len > 0 {
		l += codec.DecodedLen(int(au.uri.Host.Len))
	}
	if au.uri.Port.Len > 0 {
		l += int(au.uri.Port.Len)
		// add 1 byte for ':'
		l++
	}
	if au.uri.Params.Len > 0 {
		l += int(au.uri.Params.Len)
		// add 1 byte for ';'
		l++
	}
	if au.uri.Headers.Len > 0 {
		l += int(au.uri.Headers.Len)
		// add 1 byte for '?'
		l++
	}
	return l
}

// Encode encodes using base32 the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The encoded URI for sip:user@host is sip:base32(userinfo)@base32(hostinfo)
func (au *AnonymURI) Encode(dst, src []byte, opts ...bool) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		offs     int  = 0
		onlyHost bool = false
	)
	if len(opts) > 0 {
		onlyHost = opts[0]
	}
	codec := NewEncoding()
	// 1. check dst len
	if len(dst) < au.EncodedLen(src) {
		return fmt.Errorf("\"dst\" buffer too small for encoded URI (%d bytes required and %d bytes available)",
			au.EncodedLen(src), len(dst))
	}
	// 2. copy sip scheme
	offs = int(au.copyScheme(dst, src))
	// 3. encode user+pass
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(au.uri.User.Offs), int(userEnd))
		l := encodeToken(dst[au.uri.User.Offs:], src, pf, codec)
		// update the length of the encoded `user`
		au.uri.User.Len = sipsp.OffsT(l)
		// `password` was encoded as part of `user`
		au.uri.Pass.Offs, au.uri.Pass.Len = 0, 0
		_ = WithDebug && Dbg("encoded user: %v", au.uri.User.Get(dst))
		offs = int(au.uri.User.Offs + au.uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. encode host+port+params+header
	hostEnd := au.hostPortParamsHeadersEnd()
	if onlyHost {
		// 4. copy, pad & encrypt `host`
		hostEnd = au.hostEnd()
	}
	if hostEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(au.uri.Host.Offs), int(hostEnd))
		l := encodeToken(dst[offs:], src, pf, codec)
		// update the Offs and Len of the Host
		au.uri.Host.Offs = sipsp.OffsT(offs)
		au.uri.Host.Len = sipsp.OffsT(l)
		_ = WithDebug && Dbg("encoded host: %v", au.uri.Host.Get(dst))
		offs += int(au.uri.Host.Len)
	}
	if onlyHost {
		_ = au.copyPortParamsHeaders(dst, src)
	} else {
		// `headers`, `params`, `port` were encoded as part of host
		au.uri.Headers.Offs, au.uri.Headers.Len = 0, 0
		au.uri.Params.Offs, au.uri.Params.Len = 0, 0
		au.uri.Port.Offs, au.uri.Port.Len = 0, 0
	}
	return nil
}

// Decode decodes using base32 the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The decoded URI for sip:base32(userinfo)@base32(hostinfo) is sip:userinfo@hostinfo
func (au *AnonymURI) Decode(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		offs int = 0
	)
	codec := NewEncoding()
	if len(dst) < au.DecodedLen(src) {
		return fmt.Errorf("\"dst\" buffer too small for decoded URI (%d bytes required and %d bytes available)",
			len(dst), codec.DecodedLen(len(src)))
	}
	// copy the SIP scheme
	offs = int(au.copyScheme(dst, src))
	// decode user+pass
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(au.uri.User.Offs), int(userEnd))
		user := pf.Get(src)
		_ = WithDebug && Dbg("user: %v %s", user, string(user))
		ePf := sipsp.PField{
			Offs: au.uri.User.Offs,
			Len:  sipsp.OffsT(codec.DecodedLen(len(user))),
		}
		eUser := ePf.Get(dst)
		n, err := codec.Decode(eUser, user)
		if err != nil {
			return fmt.Errorf("error decoding URI user part: %w", err)
		}
		au.uri.User.Len = sipsp.OffsT(n)
		au.uri.Pass.Offs, au.uri.Pass.Len = 0, 0
		_ = WithDebug && Dbg("decoded eUser: %v", eUser[:n])
		offs = int(au.uri.User.Offs + au.uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// decode host
	host := au.uri.Host.Get(src)
	dPf := sipsp.PField{
		Offs: sipsp.OffsT(offs),
		Len:  sipsp.OffsT(codec.DecodedLen(int(au.uri.Host.Len))),
	}
	dHost := dPf.Get(dst)
	l, err := codec.Decode(dHost, host)
	if err != nil {
		return fmt.Errorf("error decoding URI host part: %w", err)
	}
	_ = WithDebug && Dbg("decoded host: %v", dHost[:l])
	au.uri.Host.Offs = sipsp.OffsT(offs)
	au.uri.Host.Len = sipsp.OffsT(l)
	_ = au.copyPortParamsHeaders(dst, src)
	return nil
}

func (au *AnonymURI) Anonymize(dst, src []byte, opts ...bool) (uri []byte, err error) {
	var ciphertxt [uriMaxBufSize]byte
	if err = au.Parse(src); err != nil {
		return nil, err
	}
	if err = au.CBCEncrypt(ciphertxt[:], src, opts...); err != nil {
		return nil, fmt.Errorf("cannot anonymize URI: %w", err)
	}
	if err = au.Encode(dst, ciphertxt[:], opts...); err != nil {
		return nil, fmt.Errorf("cannot anonymize URI: %w", err)
	}
	return au.Flat(dst), nil
}

func (au *AnonymURI) Deanonymize(dst, src []byte) (uri []byte, err error) {
	var decoded [uriMaxBufSize]byte
	if err = au.Parse(src); err != nil {
		return nil, err
	}
	_ = WithDebug && Dbg("uri: %v", au.uri)
	if err = au.Decode(decoded[:], src); err != nil {
		return nil, fmt.Errorf("cannot deanonymize URI: %w", err)
	}
	if err = au.CBCDecrypt(dst, decoded[:]); err != nil {
		return nil, fmt.Errorf("cannot deanonymize URI: %w", err)
	}
	return au.Flat(dst), nil
}
