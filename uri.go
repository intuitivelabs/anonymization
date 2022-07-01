package anonymization

import (
	"crypto/aes"
	"errors"
	"fmt"

	"github.com/intuitivelabs/sipsp"
)

var (
	ErrNoPFields             = errors.New("no PFields")
	ErrNonContinuousPFields  = errors.New("PFields are non-continous")
	ErrUnknownEncryptionMode = errors.New("Unknown encryption mode")
)

const (
	// maximum size allowed for an SIP URI is 2KB; with padding this results in at most 4KB
	uriMaxBufSize int = 1 << 12
)

const (
	// salt used for generating URI encryption keys
	SaltUriIV = "1190e68008426899bc48fe7719c2ffb7"
	SaltUriUK = "e3ab68497b69d87ddf6b5d97e24b6bb1"
	SaltUriHK = "23c1be46c4af62a6c6be8c860e2f13bc"
)

// type of encryption used for anonymizing
type Encryption int

const (
	CbcMode Encryption = iota
	PanMode
	InvalidEncryption
)

const (
	anonTypeAlphabetStart = 'g'
)

// Encoding used for the representation of the binary anonymized URI
type UriEncoding struct {
	base32 Encoding
	hex    Encoding
	// encoding for the user part (either hex or base32)
	user Encoding
	// encoding for the host part (base32)
	host Encoding
}

func NewUriEncoding(c Codec) (enc *UriEncoding) {
	enc = &UriEncoding{}
	enc.base32 = NewEncoding(Base32)
	enc.hex = NewEncoding(Hex)
	switch c {
	case Base32:
		enc.user = enc.base32
	case Hex:
		enc.user = enc.hex
	default:
		//unkown encoding
		return nil
	}
	// host is always encoded using base32
	enc.host = enc.base32
	return
}

func (enc *UriEncoding) WithHexCodec() *UriEncoding {
	enc.base32 = NewEncoding(Base32)
	enc.hex = NewEncoding(Hex)
	enc.host = enc.base32
	enc.user = enc.hex
	return enc
}

func (enc *UriEncoding) WithBase32Codec() *UriEncoding {
	enc.base32 = NewEncoding(Base32)
	enc.hex = NewEncoding(Hex)
	enc.host = enc.base32
	enc.user = enc.base32
	return enc
}

// CBC cipher block used for URI anonymization
type UriCBC struct {
	// user part cipher (key SHOULD be different from host part cipher)
	User CBC
	// host part cipher (key SHOULD be different from user part cipher)
	Host CBC
}

func (cbc *UriCBC) WithKeyingMaterial(km []KeyingMaterial) *UriCBC {
	cbc.User.WithKeyingMaterial(&km[0])
	cbc.Host.WithKeyingMaterial(&km[1])
	return cbc
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
	uriCBC = UriCBC{}
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

func NewUriCBCWithMasterKey(masterKey []byte) *UriCBC {
	InitUriKeysFromMasterKey(masterKey)
	return NewUriCBCWithKeys(GetUriKeys())
}

func NewUriCBCWithKeys(keys *UriKeys) *UriCBC {
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

func NewUriCBC(keys []KeyingMaterial) *UriCBC {
	if block, err := aes.NewCipher(keys[0].Enc[:]); err != nil {
		panic(err)
	} else {
		uriCBC.User.Init(keys[0].IV[:], keys[0].Enc[:], block)
	}
	if block, err := aes.NewCipher(keys[1].Enc[:]); err != nil {
		panic(err)
	} else {
		uriCBC.Host.Init(keys[1].IV[:], keys[1].Enc[:], block)
	}
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

type Padding struct {
	// user part padding
	u int
	// host part padding
	h int
}

type AnonymURI struct {
	uri sipsp.PsipURI
	// codec used for encoding the user part of the binary anonymized URI
	codec Codec
	// encoding/decoding used for the representation of the binary anonymized URI
	// encoding is used for anonymization; it is configuration driven
	encode UriEncoding
	// decoding is used for de-anonymization; the decoder can be dynamically changed based
	// on the uri username first character
	decode  UriEncoding
	padding Padding
	// encryption used for anonymizing of the user part
	encryption Encryption
	// chain block cipher anomyizer; either cbc or pan is used for the user part
	cbc UriCBC
	// prefix preserving anonymizer; either pan or cbc is used for the user part
	pan Pan
}

func NewAnonymURI() *AnonymURI {
	a := AnonymURI{}
	// set a default padding size; use BlockSize
	a.padding = Padding{u: BlockSize, h: BlockSize}
	a.pan.WithBitsPrefixBoundary(EightBitsPrefix)
	a.encode = *NewUriEncoding(a.codec)
	a.decode = *NewUriEncoding(a.codec)
	return &a
}

func (au AnonymURI) decUserAnonymizationType(src []byte) (Codec, Encryption) {
	if au.userPassLen() > 0 {
		code := src[au.uri.User.Offs]
		if code >= anonTypeAlphabetStart || code < (anonTypeAlphabetStart+15) {
			aType := code - anonTypeAlphabetStart
			return Codec(aType & 3), Encryption((aType & 0xC) >> 2)
		}
	}
	return InvalidCodec, InvalidEncryption
}

// encUserAnonymizationType returns the anonymization type used for the user part of the URI encoded
// as an ASCII character in the range [g-v]
func (au AnonymURI) encUserAnonymizationType() (aType byte) {
	aType = byte(au.codec)
	aType = aType | (byte(au.encryption) << 2)
	aType += anonTypeAlphabetStart
	return
}

func (au AnonymURI) hasUserAnonymizationType(src []byte) bool {
	if au.userPassLen() > 0 {
		aType := src[au.uri.User.Offs]
		return aType >= anonTypeAlphabetStart && aType < (anonTypeAlphabetStart+15)
	}
	return false
}

func (au *AnonymURI) WithKeyingMaterial(keys []KeyingMaterial) *AnonymURI {
	au.cbc.WithKeyingMaterial(keys)
	au.padding = Padding{
		u: au.cbc.User.Encrypter.BlockSize(),
		h: au.cbc.Host.Encrypter.BlockSize(),
	}
	au.pan.WithKeyingMaterial(&keys[0])
	return au
}

func (au *AnonymURI) SetUserCodec(codec Codec) {
	switch codec {
	case Hex:
		au.WithHexCodec()
	case Base32:
		fallthrough
	default:
		au.WithBase32Codec()
	}
}

func (au *AnonymURI) SetUserDecoder(codec Codec) {
	switch codec {
	case Hex:
		au.WithHexDecoder()
	case Base32:
		fallthrough
	default:
		au.WithBase32Decoder()
	}
}

func (au *AnonymURI) SetUserEncryption(enc Encryption) {
	switch enc {
	case PanMode:
		au.WithPanEnc()
	case CbcMode:
		fallthrough
	default:
		au.WithCbcEnc()
	}
}

// WithPanEnc sets the encryption to PAN (prefix preserving)
func (au *AnonymURI) WithPanEnc() *AnonymURI {
	// set-up the encryption
	au.encryption = PanMode
	au.pan.WithBitsPrefixBoundary(EightBitsPrefix)
	au.padding.u = PanPaddingSize

	return au
}

// WithCbcEnc sets the encryption to AES-CBC mode
func (au *AnonymURI) WithCbcEnc() *AnonymURI {
	// set-up the encryption
	au.encryption = CbcMode
	au.padding.u = BlockSize

	return au
}

// WithPan sets the encryption to PAN (prefix preserving) and encoding to hexadecimal
func (au *AnonymURI) WithPan() *AnonymURI {
	// set-up the encryption
	au.WithPanEnc()
	// set-up the encoding
	au.WithHexCodec()

	return au
}

// WithCbc sets the encryption to AES-CBC mode and encoding to base32
func (au *AnonymURI) WithCbc() *AnonymURI {
	// set-up the encryption
	au.WithCbcEnc()
	// set-up the encoding
	au.WithBase32Codec()

	return au
}

func (au *AnonymURI) WithHexDecoder() *AnonymURI {
	(&au.decode).WithHexCodec()
	return au
}

func (au *AnonymURI) WithHexCodec() *AnonymURI {
	au.codec = Hex
	(&au.encode).WithHexCodec()
	(&au.decode).WithHexCodec()
	return au
}

func (au *AnonymURI) WithBase32Decoder() *AnonymURI {
	(&au.decode).WithBase32Codec()
	return au
}

func (au *AnonymURI) WithBase32Codec() *AnonymURI {
	au.codec = Base32
	(&au.encode).WithBase32Codec()
	(&au.decode).WithBase32Codec()
	return au
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

// PaddedLen computes the length of URI with the user part and host part padded using the padding sizes in au.Padding.
// Scheme and separator '@' are not padded.
func (au *AnonymURI) PaddedLen() (int, error) {
	var (
		err                                  error
		sepLen, hLen, uLen, hPadLen, uPadLen int = 0, 0, 0, 0, 0
	)
	uLen = int(au.uri.Pass.Len + au.uri.User.Len)
	if uLen > 0 {
		if uPadLen, err = PadLen(uLen, au.padding.u); err != nil {
			return 0, fmt.Errorf("cannot pad uri's user part: %w", err)
		}
		uLen += uPadLen
		sepLen = 1
	}
	hLen = int(au.uri.Headers.Len + au.uri.Params.Len + au.uri.Port.Len + au.uri.Host.Len)
	if hPadLen, err = PadLen(hLen, au.padding.h); err != nil {
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
	_ = WithDebug && Dbg("offs: %d dst[offs:offs+len(pph)]: %v", offs, dst[offs:offs+len(pph)])
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

func concatPFields(pfs ...sipsp.PField) (*sipsp.PField, error) {
	concat := sipsp.PField{}
	if len(pfs) == 0 {
		return nil, ErrNoPFields
	}
	concat.Offs = pfs[0].Offs
	last := 0
	for i, pf := range pfs {
		// jump over empty pfields
		if pf.Len == 0 {
			continue
		}
		// store last pfield with non-zero offset
		if pf.Offs != 0 {
			last = i
		}
		if i == 0 {
			continue
		}
		_ = WithDebug && Dbg("pf.Offs: %d, pfs[i-1].Offs: %d pfs[i-1].Len :%d", pf.Offs, pfs[i-1].Offs, pfs[i-1].Len)
		if pf.Offs < pfs[i-1].Offs+pfs[i-1].Len {
			return nil, ErrNonContinuousPFields
		}
	}
	concat.Len = pfs[last].Offs - pfs[0].Offs + pfs[last].Len
	_ = WithDebug && Dbg("len(pfs): %d concat.Offs: %d concat.Len: %d", len(pfs), concat.Offs, concat.Len)
	return &concat, nil
}

func (au AnonymURI) concatUserPass() *sipsp.PField {
	if pf, err := concatPFields(au.uri.User, au.uri.Pass); err == nil {
		return pf
	}
	return nil
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

func (au *AnonymURI) panEncryptUserInfo(dst, src []byte, offs int) (int, error) {
	pf := au.concatUserPass()
	if pf.Len > 0 {
		dst = dst[offs:]
		l, err := au.pan.Encrypt(dst, pf.Get(src))
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

// cbcEncryptUserInfo encrypts the URI's user info (lhs of the `@`) from src
// into dst starting at offset offs when there is a non-empty user info.
// It returns either the length of the encrypted user info or 0 when there is no user info in the URI.
func (au *AnonymURI) cbcEncryptUserInfo(dst, src []byte, offs int) (int, error) {
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		dst = dst[offs:]
		pf := sipsp.PField{}
		pf.Set(int(au.uri.User.Offs), int(userEnd))
		au.cbc.User.Reset()
		l, err := au.cbc.User.EncryptToken(dst, src, pf)
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
		l, err = au.cbc.Host.EncryptToken(dst[offs:], src, pf)
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

// Encrypt encrypts the user info (lhs of `@`) and host info (rhs of `@`) of uri preserving SIP URI format.
// The general form of the SIP URI is:
// sip:user:password@host:port;uri-parameters?headers
// By default (opts not specified) or when opt[0] is false everything on the rhs of the @ is encrypted and the
// encrypted URI has the following format:
//
//   sip:ENCRYPT(user:password)@ENCRYPT(host:port;uri-parameters?headers)
//
// If opts[0] is true, only the host part of the URI is encrypted and the encrypted URI has the following format:
//
//   sip:ENCRYPT(user:password)@ENCRYPT(host):port;uri-parameters?headers
//
func (au *AnonymURI) Encrypt(dst, src []byte, opts ...bool) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		onlyHost  bool = false
		paddedLen int
		offs      int
		l         int
	)
	if len(opts) > 0 {
		onlyHost = opts[0]
	}
	// 1. check dst len
	if paddedLen, err = au.PaddedLen(); err != nil {
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
	switch au.encryption {
	case PanMode:
		l, err = au.panEncryptUserInfo(dst, src, offs)
		if err != nil {
			return fmt.Errorf("cannot encrypt URI: %w", err)
		}
	case CbcMode:
		l, err = au.cbcEncryptUserInfo(dst, src, offs)
		if err != nil {
			return fmt.Errorf("cannot encrypt URI: %w", err)
		}
	default:
		return ErrUnknownEncryptionMode
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
	_ = WithDebug && Dbg("dst: %v", au.Flat(dst))
	return nil
}

// Decrypt decrypts the user info and host part of uri preserving the generic URI format sip:userinfo@hostinfo.
// The decrypted URI for sip:user@host is sip:DECRYPT(userinfo)@DECRYPT(hostinfo)
// The decrypted URI for sip:user@host:port;params?headers is sip:DECRYPT(userinfo)@DECRYPT(host):port;params?headers
// The decrypted URI for sip:user@host;params?headers is sip:DECRYPT(userinfo)@DECRYPT(host);params?headers
// The decrypted URI for sip:user@host?headers is sip:DECRYPT(userinfo)@DECRYPT(host)?headers
func (au *AnonymURI) Decrypt(dst, src []byte) (err error) {
	df := DbgOn()
	defer DbgRestore(df)
	// copy the SIP scheme
	offs := int(au.copyScheme(dst, src))
	if au.uri.User.Len > 0 {
		dUser := au.uri.User.Get(dst)
		_ = WithDebug && Dbg("encrypted user part: %v", au.uri.User.Get(src))
		l := 0
		switch au.encryption {
		case PanMode:
			au.pan.Decrypt(dUser, au.uri.User.Get(src))
			// remove the '0' padding
			for l = int(au.uri.User.Len); l >= 0; l-- {
				_ = WithDebug && Dbg("l: %v dst[%v]: %v", l, l-1, dUser[l-1])
				if dUser[l-1] != 0 {
					break
				}
			}
		case CbcMode:
			au.cbc.User.Reset()
			l, err = au.cbc.User.DecryptToken(dUser, src, au.uri.User)
			if err != nil {
				return fmt.Errorf("cannot decrypt URI's user part: %w", err)
			}

		default:
			return ErrUnknownEncryptionMode

		}
		_ = WithDebug && Dbg("decrypted user part (padded): %v", dUser)
		_ = WithDebug && Dbg("decrypted user part (un-padded): %v %s", dUser[0:l], string(dUser[0:l]))
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
	_ = WithDebug && Dbg("host: %v (offs: %d len : %d)", au.uri.Host.Get(src), int(au.uri.Host.Offs), int(au.uri.Host.Len))
	au.cbc.Host.Reset()
	l, err := au.cbc.Host.DecryptToken(dHost, src, au.uri.Host)
	if err != nil {
		return fmt.Errorf("cannot decrypt URI's host part: %w", err)
	}
	_ = WithDebug && Dbg("decrypted host part (padded): %v", dHost)
	au.uri.Host.Offs = sipsp.OffsT(offs)
	au.uri.Host.Len = sipsp.OffsT(l)
	_ = au.copyPortParamsHeaders(dst, src)
	return nil
}

func (au AnonymURI) EncodedLen(buf []byte) (l int) {
	l = int(au.uri.Scheme.Len)
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		l += au.encode.user.EncodedLen(len(buf[au.uri.User.Offs:userEnd]))
		// add 1 byte for the anonymization type
		l++
		// add 1 byte for '@'
		l++
	}
	hostEnd := au.hostPortParamsHeadersEnd()
	if hostEnd > 0 {
		l += au.encode.host.EncodedLen(len(buf[au.uri.Host.Offs:hostEnd]))
	}
	return l
}

func (au AnonymURI) DecodedLen(buf []byte) (l int) {
	l = int(au.uri.Scheme.Len)
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		l += au.decode.user.DecodedLen(len(buf[au.uri.User.Offs:userEnd]))
		// add 1 byte for '@'
		l++
	}
	if au.uri.Host.Len > 0 {
		l += au.decode.host.DecodedLen(int(au.uri.Host.Len))
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
// The encoded URI for sip:user@host is:
// - either sip:[anonymizationType]base32(userinfo)@base32(hostinfo)
// - or sip:[anonymizationType]hex(userinfo)@base32(hostinfo)
// 'anonymizationType' is an optional ASCII character in the range [g-v] which describes:
// - encoding type for the user info
// - encryption mode for the user info
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
		// first character for user+pass is a digit which describes encryption and encoding
		dst[offs] = au.encUserAnonymizationType()
		offs++
		pf := sipsp.PField{}
		pf.Set(int(au.uri.User.Offs), int(userEnd))
		l := encodeToken(dst[offs:], src, pf, au.encode.user)
		// update the length of the encoded `user`
		au.uri.User.Len = sipsp.OffsT(l) + 1
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
		// 4. copy, pad & encode 'host'
		hostEnd = au.hostEnd()
	}
	if hostEnd > 0 {
		pf := sipsp.PField{}
		pf.Set(int(au.uri.Host.Offs), int(hostEnd))
		l := encodeToken(dst[offs:], src, pf, au.encode.host)
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
	if len(dst) < au.DecodedLen(src) {
		return fmt.Errorf("\"dst\" buffer too small for decoded URI (%d bytes required and %d bytes available)",
			len(dst), au.DecodedLen(src))
	}
	// copy the SIP scheme
	offs = int(au.copyScheme(dst, src))
	// decode user+pass
	userEnd := au.userPassEnd()
	if userEnd > 0 {
		pf := sipsp.PField{}
		if au.hasUserAnonymizationType(src) {
			codec, enc := au.decUserAnonymizationType(src)
			_ = WithDebug && Dbg("codec: %v enc: %v", codec, enc)
			au.SetUserCodec(codec)
			au.SetUserEncryption(enc)
			// skip the first character of the user part; it is used for encoding the anonymization type
			pf.Set(int(au.uri.User.Offs+1), int(userEnd))
		} else {
			pf.Set(int(au.uri.User.Offs), int(userEnd))
			// reset the user anonymization type to default
			au.WithCbc()
		}
		user := pf.Get(src)
		_ = WithDebug && Dbg("user: %v %s", user, string(user))
		dPf := sipsp.PField{
			Offs: au.uri.User.Offs,
			Len:  sipsp.OffsT(au.decode.user.DecodedLen(len(user))),
		}
		dUser := dPf.Get(dst)
		n, err := au.decode.user.Decode(dUser, user)
		if err != nil {
			return fmt.Errorf("error decoding URI user part: %w", err)
		}
		au.uri.User.Len = sipsp.OffsT(n)
		au.uri.Pass.Offs, au.uri.Pass.Len = 0, 0
		_ = WithDebug && Dbg("decoded user: %v", dUser[:n])
		offs = int(au.uri.User.Offs + au.uri.User.Len)
		// write '@' into dst
		dst[offs] = '@'
		offs++
	}
	// decode host
	host := au.uri.Host.Get(src)
	dPf := sipsp.PField{
		Offs: sipsp.OffsT(offs),
		Len:  sipsp.OffsT(au.decode.host.DecodedLen(int(au.uri.Host.Len))),
	}
	dHost := dPf.Get(dst)
	l, err := au.decode.host.Decode(dHost, host)
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
	if err = au.Encrypt(ciphertxt[:], src, opts...); err != nil {
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
	if err = au.Decrypt(dst, decoded[:]); err != nil {
		return nil, fmt.Errorf("cannot deanonymize URI: %w", err)
	}
	return au.Flat(dst), nil
}
