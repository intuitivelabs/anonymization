package anonymization

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/intuitivelabs/sipsp"
)

func TestBase32Codec(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	uris := [...][]byte{
		[]byte("sip:foo:pass@bar.com"),
		[]byte("sip:foo:pass@bar.com:5060"),
		[]byte("sip:foo:pass@bar.com:5060;ttl=1"),
		[]byte("sip:foo:pass@bar.com:5060;ttl=1?h=foo"),
		[]byte("sip:foo:pass@bar.com;ttl=1"),
		[]byte("sip:foo:pass@bar.com;ttl=1?h=foo"),
		[]byte("sip:foo:pass@bar.com?h=foo"),
		[]byte("sip:foo@bar.com"),
		[]byte("sips:foo:pass@bar.com"),
		[]byte("sip:1234"),
		[]byte("sip:1234:5060"),
		[]byte("sip:1234:5060;ttl=1"),
		[]byte("sip:1234:5060;ttl=1?h=foo"),
		[]byte("sip:1234;ttl=1"),
		[]byte("sip:1234?h=foo"),
		[]byte("sip:foo"),
	}
	pUris := make([]sipsp.PsipURI, len(uris))
	for i, s := range uris {
		if err, _ := sipsp.ParseURI(s, &pUris[i]); err != 0 {
			t.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	// tests
	t.Run("dynamic memory", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s", string(uris[i]))
			au := AnonymURI(u)
			l := au.EncodedLen(uris[i])
			Dbg("encoded len: %d", l)
			encoded := make([]byte, l)
			if err := au.Encode(encoded, uris[i]); err != nil {
				t.Fatalf("cannot encode URI %s: %s", uris[i], err.Error())
			}
			Dbg("encoded URI: %v (len: %d)", encoded, len(encoded))
			//Dbg("encoded URI: %s", au.Str*ing(encoded))
			Dbg("encoded URI: %s", string((*sipsp.PsipURI)(&au).Flat(encoded)))
			l = au.DecodedLen(encoded)
			decoded := make([]byte, l)
			if err := au.Decode(decoded, encoded); err != nil {
				Dbg("decoded URI: %v", decoded)
				t.Fatalf("cannot decode URI %s: %s", uris[i], err.Error())
			}
			Dbg("decoded URI: %s", string((*sipsp.PsipURI)(&au).Flat(decoded)))
			uri := sipsp.PsipURI(au)
			if !bytes.Equal(uris[i], uri.Flat(decoded)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(uri.Flat(decoded)))
			}
		}
	})
	t.Run("host only", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s", string(uris[i]))
			au := AnonymURI(u)
			l := au.EncodedLen(uris[i])
			Dbg("encoded len: %d", l)
			encoded := make([]byte, l)
			if err := au.Encode(encoded, uris[i], true); err != nil {
				t.Fatalf("cannot encode URI %s: %s", uris[i], err.Error())
			}
			Dbg("encoded URI: %v (len: %d)", encoded, len(encoded))
			//Dbg("encoded URI: %s", au.Str*ing(encoded))
			Dbg("encoded URI: %s", string((*sipsp.PsipURI)(&au).Flat(encoded)))
			l = au.DecodedLen(encoded)
			decoded := make([]byte, l)
			if err := au.Decode(decoded, encoded); err != nil {
				Dbg("decoded URI: %v", decoded)
				t.Fatalf("cannot decode URI %s: %s", uris[i], err.Error())
			}
			Dbg("decoded URI: %s", string((*sipsp.PsipURI)(&au).Flat(decoded)))
			uri := sipsp.PsipURI(au)
			if !bytes.Equal(uris[i], uri.Flat(decoded)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(uri.Flat(decoded)))
			}
		}
	})
}

func TestCBCEncrypt(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	ukey, _ := hex.DecodeString("6368616e676520746869732070617373")
	hkey, _ := hex.DecodeString("7368616e676520746869732070617374")
	var iv [16]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		t.Fatalf("could not init IV: %s", err)
	}
	cipher := NewUriCBC(iv[:], ukey, hkey)
	// test case data
	uris := [...][]byte{
		[]byte("sip:foo:pass@bar.com"),
		[]byte("sip:foo@bar.com"),
		[]byte("sips:foo:pass@bar.com"),
		[]byte("sip:1234"),
		[]byte("sip:foo"),
	}
	urisPPH := [...][]byte{
		[]byte("sip:foo@bar.com;ttl=4"),
		[]byte("sip:foo@bar.com;ttl=4?to=foo"),
		[]byte("sip:foo@bar.com?to=foo&from=bar"),
		[]byte("sip:foo:bar@bar.com:5060"),
		[]byte("sip:foo@bar.com:5060"),
		[]byte("sip:foo@bar.com:5060;ttl=4"),
		[]byte("sip:foo@bar.com:5060;ttl=4?to=foo&from=bar"),
		[]byte("sip:foo@bar.com:5060;ttl=4;p1=20?to=foo&from=bar"),
		[]byte("sip:foo@bar.com:5060?to=foo&from=bar"),
		[]byte("sip:1234;ttl=5"),
		[]byte("sip:1234?to=bar"),
		[]byte("sip:1234:5060;ttl=5"),
		[]byte("sip:1234:5060?to=bar"),
		[]byte("sip:foo:5060"),
	}
	pUris := make([]sipsp.PsipURI, len(uris))
	for i, s := range uris {
		if err, _ := sipsp.ParseURI(s, &pUris[i]); err != 0 {
			t.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	pUrisPPH := make([]sipsp.PsipURI, len(urisPPH))
	for i, s := range urisPPH {
		if err, _ := sipsp.ParseURI(s, &pUrisPPH[i]); err != 0 {
			t.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	// tests
	t.Run("dynamic memory", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s", string(uris[i]))
			au := AnonymURI(u)
			l, err := au.PKCSPaddedLen(cipher.User.Encrypter.BlockSize())
			if err != nil {
				t.Fatalf("cannot compute URI pad len %s: %s", uris[i], err.Error())
			}
			Dbg("padded len: %d", l)
			ciphertxt := make([]byte, l)
			if err := au.CBCEncrypt(ciphertxt, uris[i]); err != nil {
				t.Fatalf("cannot encrypt URI %s: %s", uris[i], err.Error())
			}
			Dbg("encrypted URI: %v (len: %d)", ciphertxt, len(ciphertxt))
			plaintxt := make([]byte, len(ciphertxt))
			if err := au.CBCDecrypt(plaintxt, ciphertxt); err != nil {
				Dbg("decrypted URI: %v", plaintxt)
				t.Fatalf("cannot decrypt URI %s: %s", uris[i], err.Error())
			}
			Dbg("decrypted URI: %v %s", plaintxt, string((*sipsp.PsipURI)(&au).Flat(plaintxt)))
			uri := sipsp.PsipURI(au)
			if !bytes.Equal(uris[i], uri.Flat(plaintxt)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(uri.Flat(plaintxt)))
			}
		}
	})
	t.Run("static memory", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s", string(uris[i]))
			au := AnonymURI(u)
			l, err := au.PKCSPaddedLen(cipher.User.Encrypter.BlockSize())
			if err != nil {
				t.Fatalf("cannot compute URI pad len %s: %s", uris[i], err.Error())
			}
			Dbg("padded len: %d", l)
			ciphertxt := EncryptBuf()
			if err := au.CBCEncrypt(ciphertxt, uris[i]); err != nil {
				t.Fatalf("cannot encrypt URI %s: %s", uris[i], err.Error())
			}
			Dbg("encrypted URI: %v (len: %d)", ciphertxt, len(ciphertxt))
			plaintxt := DecryptBuf()
			if err := au.CBCDecrypt(plaintxt, ciphertxt); err != nil {
				Dbg("decrypted URI: %v", plaintxt)
				t.Fatalf("cannot decrypt URI %s: %s", uris[i], err.Error())
			}
			Dbg("decrypted URI: %v %s", plaintxt, string((*sipsp.PsipURI)(&au).Flat(plaintxt)))
			uri := sipsp.PsipURI(au)
			if !bytes.Equal(uris[i], uri.Flat(plaintxt)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(uri.Flat(plaintxt)))
			}
		}
	})
	t.Run("host only", func(t *testing.T) {
		for i, u := range pUrisPPH {
			Dbg("test case uri: %s", string(urisPPH[i]))
			au := AnonymURI(u)
			l, err := au.PKCSPaddedLen(cipher.User.Encrypter.BlockSize())
			if err != nil {
				t.Fatalf("cannot compute URI pad len %s: %s", urisPPH[i], err.Error())
			}
			Dbg("padded len: %d", l)
			ciphertxt := EncryptBuf()
			// host only encryption
			if err := au.CBCEncrypt(ciphertxt, urisPPH[i], true); err != nil {
				t.Fatalf("cannot encrypt URI %s: %s", urisPPH[i], err.Error())
			}
			Dbg("encrypted URI: %v (len: %d)", ciphertxt, len(ciphertxt))
			plaintxt := DecryptBuf()
			if err := au.CBCDecrypt(plaintxt, ciphertxt); err != nil {
				Dbg("decrypted URI: %v", plaintxt)
				t.Fatalf("cannot decrypt URI %s: %s", urisPPH[i], err.Error())
			}
			Dbg("decrypted URI: %v %s", plaintxt, string((*sipsp.PsipURI)(&au).Flat(plaintxt)))
			uri := sipsp.PsipURI(au)
			if !bytes.Equal(urisPPH[i], uri.Flat(plaintxt)) {
				t.Fatalf(`expected: "%s" got: "%s"`, urisPPH[i], string(uri.Flat(plaintxt)))
			}
		}
	})
	// clean-up
}

func TestAnonymization(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	var encKey [EncryptionKeyLen]byte
	var iv [EncryptionKeyLen]byte
	var uk [EncryptionKeyLen]byte
	var hk [EncryptionKeyLen]byte
	pass := "foobar"
	GenerateKeyFromPassphraseAndCopy(pass, EncryptionKeyLen, encKey[:])
	// generate IV for CBC
	GenerateIV(encKey[:], EncryptionKeyLen, iv[:])
	// generate key for URI's user part
	GenerateURIUserKey(encKey[:], EncryptionKeyLen, uk[:])
	// generate key for URI's host part
	GenerateURIHostKey(encKey[:], EncryptionKeyLen, hk[:])

	// initialize the URI CBC based encryption
	_ = NewUriCBC(iv[:], uk[:], hk[:])
	// test case data
	uris := [...][]byte{
		[]byte("sip:foo:pass@bar.com"),
		[]byte("sip:foo:pass@bar.com:5060"),
		[]byte("sip:foo:pass@bar.com:5060;ttl=1"),
		[]byte("sip:foo:pass@bar.com:5060;ttl=1?h=foo"),
		[]byte("sip:foo:pass@bar.com;ttl=1"),
		[]byte("sip:foo:pass@bar.com;ttl=1?h=foo"),
		[]byte("sip:foo:pass@bar.com?h=foo"),
		[]byte("sip:foo@bar.com"),
		[]byte("sips:foo:pass@bar.com"),
		[]byte("sip:1234"),
		[]byte("sip:1234:5060"),
		[]byte("sip:1234:5060;ttl=1"),
		[]byte("sip:1234:5060;ttl=1?h=foo"),
		[]byte("sip:1234;ttl=1"),
		[]byte("sip:1234?h=foo"),
		[]byte("sip:foo"),
		[]byte("sip:004956768326@188.74.3.208:3894"),
		[]byte("sip:004956768326@188.74.3.208:3894"),
		[]byte("sip:0049567683269215869@188.74.3.208:3894"),
		[]byte("sip:0049567683269215000@188.74.3.208:3894"),
		[]byte("sip:004924554390004@85.212.141.52"),
	}
	pUris := make([]sipsp.PsipURI, len(uris))
	for i, s := range uris {
		if err, _ := sipsp.ParseURI(s, &pUris[i]); err != 0 {
			t.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	// tests
	t.Run("CBC state", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s", string(uris[i]))
			au := AnonymURI(u)
			anon := AnonymizeBuf()
			if err := au.Anonymize(anon, uris[i], true); err != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
			}
			Dbg("anonymized uri: %v %s", anon, string((*sipsp.PsipURI)(&au).Flat(anon)))
			dupAnon := make([]byte, len(anon))
			dupAu := AnonymURI(u)
			if err := dupAu.Anonymize(dupAnon, uris[i], true); err != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
			}
			Dbg("duplicated anonymized uri: %v %s", dupAnon, string((*sipsp.PsipURI)(&dupAu).Flat(dupAnon)))
			if !bytes.Equal((*sipsp.PsipURI)(&au).Flat(anon), (*sipsp.PsipURI)(&au).Flat(dupAnon)) {
				t.Fatalf(`expected: "%s" got: "%s"`, (*sipsp.PsipURI)(&au).Flat(anon), (*sipsp.PsipURI)(&au).Flat(dupAnon))
			}
		}
	})
	t.Run("everything", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s", string(uris[i]))
			au := AnonymURI(u)
			anon := AnonymizeBuf()
			if err := au.Anonymize(anon, uris[i]); err != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
			}
			Dbg("anonymized uri: %v %s", anon, string((*sipsp.PsipURI)(&au).Flat(anon)))
			deanon := DeanonymizeBuf()
			if err := au.Deanonymize(deanon, anon); err != nil {
				t.Fatalf("could not deanonymize SIP URI %s: %s", string((*sipsp.PsipURI)(&au).Flat(anon)), err)
			}
			Dbg("deanonymized uri: %v %s", deanon, string((*sipsp.PsipURI)(&au).Flat(deanon)))
			if !bytes.Equal(uris[i], (*sipsp.PsipURI)(&au).Flat(deanon)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string((*sipsp.PsipURI)(&au).Flat(deanon)))
			}
		}
	})
	t.Run("host only", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s", string(uris[i]))
			au := AnonymURI(u)
			anon := AnonymizeBuf()
			if err := au.Anonymize(anon, uris[i], true); err != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
			}
			Dbg("anonymized uri: %v %s", anon, string((*sipsp.PsipURI)(&au).Flat(anon)))
			deanon := DeanonymizeBuf()
			if err := au.Deanonymize(deanon, anon); err != nil {
				t.Fatalf("could not deanonymize SIP URI %s: %s", string((*sipsp.PsipURI)(&au).Flat(anon)), err)
			}
			Dbg("deanonymized uri: %v %s", deanon, string((*sipsp.PsipURI)(&au).Flat(deanon)))
			if !bytes.Equal(uris[i], (*sipsp.PsipURI)(&au).Flat(deanon)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string((*sipsp.PsipURI)(&au).Flat(deanon)))
			}
		}
	})
	t.Run("deanonymize", func(t *testing.T) {
		anonUris := [...][]byte{
			[]byte("sip:7FIQTTVPC65OONS0H7B1O9EAE8------@86O14ERFB383DT1IOALB79L798------"),
			//[]byte("sip:0GRMFO2A6IO79EKVRV033U1EKG------@C27COJGS9GCRI94B274QLGMH30------"),
		}
		pAnonUris := make([]sipsp.PsipURI, len(anonUris))
		for i, s := range anonUris {
			if err, _ := sipsp.ParseURI(s, &pAnonUris[i]); err != 0 {
				t.Fatalf("could not parse SIP URI: %s", string(s))
			}
		}
		for i, u := range pAnonUris {
			Dbg("test case uri: %s", string(anonUris[i]))
			au := AnonymURI(u)
			deanon := DeanonymizeBuf()
			if err := au.Deanonymize(deanon, anonUris[i]); err != nil {
				t.Fatalf("could not deanonymize SIP URI %s: %s", anonUris[i], err)
			}
			Dbg("deanonymized uri: %v %s", deanon, string((*sipsp.PsipURI)(&au).Flat(deanon)))
		}
	})
}

func BenchmarkUriAnonymization(b *testing.B) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	var encKey [EncryptionKeyLen]byte
	var iv [EncryptionKeyLen]byte
	var uk [EncryptionKeyLen]byte
	var hk [EncryptionKeyLen]byte
	pass := "foobar"
	GenerateKeyFromPassphraseAndCopy(pass, EncryptionKeyLen, encKey[:])
	// generate IV for CBC
	GenerateIV(encKey[:], EncryptionKeyLen, iv[:])
	// generate key for URI's user part
	GenerateURIUserKey(encKey[:], EncryptionKeyLen, uk[:])
	// generate key for URI's host part
	GenerateURIHostKey(encKey[:], EncryptionKeyLen, hk[:])

	// initialize the URI CBC based encryption
	_ = NewUriCBC(iv[:], uk[:], hk[:])
	// test case data
	uris := [...][]byte{
		[]byte("sip:004956768326@188.74.3.208:3894"),
		[]byte("sip:004956768326@188.74.3.208:3894"),
		[]byte("sip:004956769215869@188.74.3.208:3894"),
	}
	pUris := make([]sipsp.PsipURI, len(uris))
	for i, s := range uris {
		if err, _ := sipsp.ParseURI(s, &pUris[i]); err != 0 {
			b.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	b.Run("anonymize", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for i, u := range pUris {
				au := AnonymURI(u)
				//anon := AnonymizeBuf()
				anon := make([]byte, 3000)
				if err := au.Anonymize(anon, uris[i], true); err != nil {
					b.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
				}
			}
		}
	})
}
