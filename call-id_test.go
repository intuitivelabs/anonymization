package anonymization

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/intuitivelabs/sipsp"
)

func TestCallIdBase32Codec(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	callIds := [...][]byte{
		[]byte("AB170EB876CF1542@188.74.1.5"),
		[]byte("34358C152D2E461B@134.19.92.222"),
		[]byte("E996A63EBD130CF4@134.19.43.69"),
		[]byte("2311242011@192_168_42_93"),
		[]byte("CC7893C861067F60@188.74.19.112"),
		[]byte("lbSVa-MrbY9KqwGJfVQJfQ.."),
		[]byte("2582469A238E481B@188.74.0.26"),
		[]byte("977BAAC8F30E4B10@77.182.102.199"),
		[]byte("66063557F19E4A73@134.19.44.57"),
		[]byte("b850d06d-2d87-1224-afa1-00095200ed73"),
		[]byte("3154A63A30C3CEF7@178.201.226.73"),
		[]byte("6E43D0571A0323EC@178.201.226.73"),
	}
	pCallIds := make([]sipsp.PCallIDBody, len(callIds))
	for i, s := range callIds {
		pCallIds[i].Reset()
		if _, err := sipsp.ParseCallIDVal([]byte(string(s)+"\r\n"), 0, &pCallIds[i]); (err != sipsp.ErrHdrOk) && (err != sipsp.ErrHdrMoreBytes) {
			t.Fatalf(`error parsing SIP Call-ID "%s": %v`, string(s), err)
		}
	}
	// tests
	t.Run("dynamic memory", func(t *testing.T) {
		for i, c := range pCallIds {
			Dbg("test case Call-ID: %s", string(callIds[i]))
			ac := AnonymPField{
				PField: c.CallID,
			}
			l := ac.EncodedLen()
			Dbg("encoded len: %d", l)
			encoded := make([]byte, l)
			if err := ac.Encode(encoded, callIds[i]); err != nil {
				t.Fatalf("cannot encode Call-ID %s: %s", callIds[i], err.Error())
			}
			Dbg("encoded Call-ID: %v (len: %d)", encoded, len(encoded))
			Dbg("encoded Call-ID: %s", string(ac.PField.Get(encoded)))
			l = ac.DecodedLen()
			decoded := make([]byte, l)
			if err := ac.Decode(decoded, encoded); err != nil {
				Dbg("decoded Call-ID: %v", decoded)
				t.Fatalf("cannot decode Call-ID %s: %s", callIds[i], err.Error())
			}
			Dbg(`decoded Call-ID: %v "%s"`, ac.PField.Get(decoded), string(ac.PField.Get(decoded)))
			if !bytes.Equal(callIds[i], ac.PField.Get(decoded)) {
				t.Fatalf(`expected: "%s" got: "%s"`, callIds[i], string(ac.PField.Get(decoded)))
			}
		}
	})
}

func TestCallIdCBCEncrypt(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	var iv [16]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		t.Fatalf("could not init IV: %s", err)
	}
	InitCallIdKeys(iv[:], key)
	cipher := NewCallIdCBC(GetCallIdKeys())
	// test case data
	callIds := [...][]byte{
		[]byte("AB170EB876CF1542@188.74.1.5"),
		[]byte("34358C152D2E461B@134.19.92.222"),
		[]byte("E996A63EBD130CF4@134.19.43.69"),
		[]byte("2311242011@192_168_42_93"),
		[]byte("CC7893C861067F60@188.74.19.112"),
		[]byte("lbSVa-MrbY9KqwGJfVQJfQ.."),
		[]byte("2582469A238E481B@188.74.0.26"),
		[]byte("977BAAC8F30E4B10@77.182.102.199"),
		[]byte("66063557F19E4A73@134.19.44.57"),
		[]byte("b850d06d-2d87-1224-afa1-00095200ed73"),
		[]byte("3154A63A30C3CEF7@178.201.226.73"),
		[]byte("6E43D0571A0323EC@178.201.226.73"),
	}
	pCallIds := make([]sipsp.PCallIDBody, len(callIds))
	for i, s := range callIds {
		pCallIds[i].Reset()
		if _, err := sipsp.ParseCallIDVal([]byte(string(s)+"\r\n"), 0, &pCallIds[i]); (err != sipsp.ErrHdrOk) && (err != sipsp.ErrHdrMoreBytes) {
			t.Fatalf(`error parsing SIP Call-ID "%s": %v`, string(s), err)
		}
	}
	// tests
	t.Run("dynamic memory", func(t *testing.T) {
		for i, c := range pCallIds {
			Dbg("test case Call-ID: %s", string(callIds[i]))
			ac := AnonymPField{
				PField: c.CallID,
			}
			l, err := ac.PKCSPaddedLen(cipher.Encrypter.BlockSize())
			if err != nil {
				t.Fatalf("cannot compute Call-ID pad len %s: %s", callIds[i], err.Error())
			}
			Dbg("padded len: %d", l)
			ciphertxt := make([]byte, l)
			if err := ac.CBCEncrypt(ciphertxt, callIds[i]); err != nil {
				t.Fatalf("cannot encrypt Call-ID %s: %s", callIds[i], err.Error())
			}
			Dbg("encrypted Call-ID: %v (len: %d)", ciphertxt, len(ciphertxt))
			plaintxt := make([]byte, len(ciphertxt))
			if err := ac.CBCDecrypt(plaintxt, ciphertxt); err != nil {
				Dbg("decrypted Call-ID: %v", plaintxt)
				t.Fatalf("cannot decrypt Call-ID %s: %s", callIds[i], err.Error())
			}
			Dbg("decrypted Call-ID: %v %s", plaintxt, string(ac.PField.Get(plaintxt)))
			if !bytes.Equal(callIds[i], ac.PField.Get(plaintxt)) {
				t.Fatalf(`expected: "%s" got: "%s"`, callIds[i], string(ac.PField.Get(plaintxt)))
			}
		}
	})
	// clean-up
}
