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

func InitUriKeysFromMasterKey(masterKey []byte, keyLen int) {
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

type AnonymURI sipsp.PsipURI

func (uri *AnonymURI) hostToLower(buf []byte) {
	host := uri.Host.Get(buf)
	for i, c := range host {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		host[i] = c
	}
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
		Dbg("pph start: uri.Params.Offs: %d", start)
		return start
	}
	start = uri.Headers.Offs
	Dbg("pph start: uri.Headers.Offs: %d", start)
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

// cbcEncryptUserInfo encrypts the URI's user info (lhs of the `@`) from src into dst starting at offset offs when there is a non-empty user info;
// it returns the length of the encrypted user info. It returns a 0 length when there is no user info in the URI.
func (uri *AnonymURI) cbcEncryptUserInfo(dst, src []byte, offs int) (int, error) {
	userEnd := uri.userPassEnd()
	if userEnd > 0 {
		dst = dst[offs:]
		pf := sipsp.PField{}
		pf.Set(int(uri.User.Offs), int(userEnd))
		UriCBC().User.Reset()
		l, err := cbcEncryptToken(dst, src, pf, UriCBC().User.Encrypter)
		if err != nil {
			return 0, fmt.Errorf("cannot encrypt user part: %w", err)
		}
		uri.User = sipsp.PField{
			Offs: sipsp.OffsT(offs),
			Len:  sipsp.OffsT(l),
		}
		uri.Pass = sipsp.PField{
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
func (uri *AnonymURI) cbcEncryptHostInfo(dst, src []byte, offs int, onlyHost bool) (l int, err error) {
	uri.hostToLower(src)
	end := uri.hostPortParamsHeadersEnd()
	if onlyHost {
		end = uri.hostEnd()
	}
	if end > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.Host.Offs), int(end))
		UriCBC().Host.Reset()
		l, err = cbcEncryptToken(dst[offs:], src, pf, UriCBC().Host.Encrypter)
		if err != nil {
			return 0, fmt.Errorf("cannot encrypt URI: %w", err)
		}
		// update Offs, Len
		uri.Host.Offs = sipsp.OffsT(offs)
		uri.Host.Len = sipsp.OffsT(l)
		offs += int(uri.Host.Len)
		if onlyHost {
			// 5. copy `port`+`params`+`header`
			l += int(uri.copyPortParamsHeaders(dst, src))
		} else {
			// 5. set the Offs, Len for everything on rhs besides `host` to 0
			uri.Headers.Offs, uri.Headers.Len = 0, 0
			uri.Params.Offs, uri.Params.Len = 0, 0
			uri.Port.Offs, uri.Port.Len = 0, 0
		}
		return l, nil
	}
	return 0, nil
}

// CBCEncrypt encrypts the user info (lhs of `@`) and host info (rhs of `@`) of uri preserving SIP URI format.
// The general form of the SIP URI is:
// sip:user:password@host:port;uri-parameters?headers
// By default (opts not specified) or when opt[0] is false, the encrypted URI is:
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
	Dbg(`dst: "%s"`, string(dst[0:uri.Scheme.Len]))
	// 3. copy, pad & encrypt user+pass
	l, err := uri.cbcEncryptUserInfo(dst, src, offs)
	if err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
	}
	if l > 0 {
		offs = int(uri.User.Offs + uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. copy, pad & encrypt `host`+`port`+`params`+`header`
	l, err = uri.cbcEncryptHostInfo(dst, src, offs, onlyHost)
	if err != nil {
		return fmt.Errorf("cannot encrypt URI: %w", err)
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
			Offs: uri.User.Offs,
			Len:  uri.User.Len,
		}
		dUser := dPf.Get(dst)
		pf := sipsp.PField{
			Offs: uri.User.Offs,
			Len:  uri.User.Len,
		}
		user := pf.Get(src)
		Dbg("encrypted user part: %v", user)
		UriCBC().User.Reset()
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
	UriCBC().Host.Reset()
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
	if uri.Host.Len > 0 {
		l += codec.DecodedLen(int(uri.Host.Len))
	}
	if uri.Port.Len > 0 {
		l += int(uri.Port.Len)
		// add 1 byte for ':'
		l++
	}
	if uri.Params.Len > 0 {
		l += int(uri.Params.Len)
		// add 1 byte for ';'
		l++
	}
	if uri.Headers.Len > 0 {
		l += int(uri.Headers.Len)
		// add 1 byte for '?'
		l++
	}
	return l
}

// Encode encodes using base32 the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The encoded URI for sip:user@host is sip:base32(userinfo)@base32(hostinfo)
func (uri *AnonymURI) Encode(dst, src []byte, opts ...bool) (err error) {
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
	if len(dst) < uri.EncodedLen(src) {
		return fmt.Errorf("\"dst\" buffer too small for encoded URI (%d bytes required and %d bytes available)",
			uri.EncodedLen(src), len(dst))
	}
	// 2. copy sip scheme
	offs = int(uri.copyScheme(dst, src))
	// 3. encode user+pass
	userEnd := uri.userPassEnd()
	if userEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.User.Offs), int(userEnd))
		l := encodeToken(dst[uri.User.Offs:], src, pf, codec)
		// update the length of the encoded `user`
		uri.User.Len = sipsp.OffsT(l)
		// `password` was encoded as part of `user`
		uri.Pass.Offs, uri.Pass.Len = 0, 0
		Dbg("encoded user: %v", uri.User.Get(dst))
		offs = int(uri.User.Offs + uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// 4. encode host+port+params+header
	hostEnd := uri.hostPortParamsHeadersEnd()
	if onlyHost {
		// 4. copy, pad & encrypt `host`
		hostEnd = uri.hostEnd()
	}
	if hostEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(uri.Host.Offs), int(hostEnd))
		l := encodeToken(dst[offs:], src, pf, codec)
		// update the Offs and Len of the Host
		uri.Host.Offs = sipsp.OffsT(offs)
		uri.Host.Len = sipsp.OffsT(l)
		Dbg("encoded host: %v", uri.Host.Get(dst))
		offs += int(uri.Host.Len)
	}
	if onlyHost {
		_ = uri.copyPortParamsHeaders(dst, src)
	} else {
		// `headers`, `params`, `port` were encoded as part of host
		uri.Headers.Offs, uri.Headers.Len = 0, 0
		uri.Params.Offs, uri.Params.Len = 0, 0
		uri.Port.Offs, uri.Port.Len = 0, 0
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
	// decode user+pass
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
	// decode host
	host := uri.Host.Get(src)
	dPf := sipsp.PField{
		Offs: sipsp.OffsT(offs),
		Len:  sipsp.OffsT(codec.DecodedLen(int(uri.Host.Len))),
	}
	dHost := dPf.Get(dst)
	l, err := codec.Decode(dHost, host)
	if err != nil {
		return fmt.Errorf("error decoding URI host part: %w", err)
	}
	Dbg("decoded host: %v", dHost[:l])
	uri.Host.Offs = sipsp.OffsT(offs)
	uri.Host.Len = sipsp.OffsT(l)
	_ = uri.copyPortParamsHeaders(dst, src)
	return nil
}

func (uri *AnonymURI) Anonymize(dst, src []byte, opts ...bool) (err error) {
	var ciphertxt [uriMaxBufSize]byte
	if err = uri.CBCEncrypt(ciphertxt[:], src, opts...); err != nil {
		return fmt.Errorf("cannot anonymize URI: %w", err)
	}
	if err = uri.Encode(dst, ciphertxt[:], opts...); err != nil {
		return fmt.Errorf("cannot anonymize URI: %w", err)
	}
	return nil
}

func (uri *AnonymURI) Deanonymize(dst, src []byte) (err error) {
	var decoded [uriMaxBufSize]byte
	if err = uri.Decode(decoded[:], src); err != nil {
		return fmt.Errorf("cannot deanonymize URI: %w", err)
	}
	if err = uri.CBCDecrypt(dst, decoded[:]); err != nil {
		return fmt.Errorf("cannot deanonymize URI: %w", err)
	}
	return nil
}
