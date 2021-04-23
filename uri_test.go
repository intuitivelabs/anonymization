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
		[]byte("sip:foo@bar.com"),
		[]byte("sips:foo:pass@bar.com"),
		[]byte("sip:1234"),
		[]byte("sip:foo"),
	}
	pUris := make([]sipsp.PsipURI, len(uris))
	for i, s := range uris {
		if err, _ := sipsp.ParseURI(s, &pUris[i]); err != 0 {
			t.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	// tests
	t.Run("encode and decode with dynamic memory", func(t *testing.T) {
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
	pUris := make([]sipsp.PsipURI, len(uris))
	for i, s := range uris {
		if err, _ := sipsp.ParseURI(s, &pUris[i]); err != 0 {
			t.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	// tests
	t.Run("encrypt and decrypt using dynamic memory", func(t *testing.T) {
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
	t.Run("encrypt and decrypt using static memory", func(t *testing.T) {
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
	// clean-up
}

func TestAnonymization(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	ukey, _ := hex.DecodeString("6368616e676520746869732070617373")
	hkey, _ := hex.DecodeString("7368616e676520746869732070617374")
	var iv [16]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		t.Fatalf("could not init IV: %s", err)
	}
	_ = NewUriCBC(iv[:], ukey, hkey)
	// test case data
	uris := [...][]byte{
		[]byte("sip:foo:pass@bar.com"),
		[]byte("sip:foo@bar.com"),
		[]byte("sips:foo:pass@bar.com"),
		[]byte("sip:1234"),
		[]byte("sip:foo"),
	}
	pUris := make([]sipsp.PsipURI, len(uris))
	for i, s := range uris {
		if err, _ := sipsp.ParseURI(s, &pUris[i]); err != 0 {
			t.Fatalf("could not parse SIP URI: %s", string(s))
		}
	}
	t.Run("anonymize, de-anonymize", func(t *testing.T) {
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
	// tests
}
