package anonymization

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/intuitivelabs/sipsp"
)

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
	t.Run("encrypt / decrypt ", func(t *testing.T) {
		for i, u := range pUris {
			Dbg("test case uri: %s\n", string(uris[i]))
			au := AnonymURI(u)
			l, err := au.PKCSPaddedLen(cipher.User.Encrypter.BlockSize())
			if err != nil {
				t.Fatalf("cannot compute URI pad len %s: %s", uris[i], err.Error())
			}
			Dbg("padded len: %d\n", l)
			ciphertxt := make([]byte, l)
			if err := au.CBCEncrypt(ciphertxt, uris[i]); err != nil {
				t.Fatalf("cannot encrypt URI %s: %s", uris[i], err.Error())
			}
			Dbg("encrypted URI: %v (len: %d)\n", ciphertxt, len(ciphertxt))
			plaintxt := make([]byte, len(ciphertxt))
			if err := au.CBCDecrypt(plaintxt, ciphertxt); err != nil {
				Dbg("decrypted URI: %v\n", plaintxt)
				t.Fatalf("cannot decrypt URI %s: %s", uris[i], err.Error())
			}
			if au.User.Len > 0 {
				Dbg("decrypted URI: %v %s%s@%s\n", plaintxt,
					string(plaintxt[au.Scheme.Offs:au.Scheme.Offs+au.Scheme.Len]),
					string(plaintxt[au.User.Offs:au.User.Offs+au.User.Len]),
					string(plaintxt[au.Host.Offs:au.Host.Offs+au.Host.Len]))
			} else {
				Dbg("decrypted URI: %v %s%s\n", plaintxt,
					string(plaintxt[au.Scheme.Offs:au.Scheme.Offs+au.Scheme.Len]),
					string(plaintxt[au.Host.Offs:au.Host.Offs+au.Host.Len]))
			}
		}
	})
	// clean-up
}
