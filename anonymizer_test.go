package anonymization

import (
	"bytes"
	"github.com/intuitivelabs/sipsp"
	"testing"
)

func TestAnonymizer(t *testing.T) {
	// channel used to signal go routines state
	var ch chan int = make(chan int)
	// number of go routines
	n := 10
	pass := "foobar"
	df := DbgOn()
	defer DbgRestore(df)
	waitForAll := func() {
		for i := 0; i < n; i++ {
			// there is only one state: ready (coded as 1)
			<-ch
			if WithDebug {
				Dbg("thread %d has finished", i)
			}
		}
	}
	ready := func() {
		// there is only one state: ready (coded as 1)
		ch <- 1
	}
	t.Run("empty challenge", func(t *testing.T) {
		defer waitForAll()
		// worker thread function
		wt := func() {
			defer ready()
			a, err := NewAnonymizer("")
			if err != nil {
				t.Fatalf("anonymizer initialization failure")
			}
			a.UpdateKeys(Keys[:])
			if c := a.Validator.Compute(); len(c) == 0 {
				t.Errorf("validator code len is 0")
			} else {
				if WithDebug {
					Dbg("key validation code: %s", c)
				}
				if !a.Validator.Validate(c) {
					t.Errorf("key is not valid")
				}
			}
		}
		GenerateAllKeysWithPassphrase(pass)
		for i := 0; i < n; i++ {
			go wt()
		}
	})
	t.Run("uuid challenge", func(t *testing.T) {
		defer waitForAll()
		// worker thread function
		wt := func() {
			defer ready()
			a, err := NewAnonymizer("a86483ec-8568-48da-b2cc-b4db9307d7f4")
			if err != nil {
				t.Fatalf("anonymizer initialization failure")
			}
			a.UpdateKeys(Keys[:])
			if c := a.Validator.Compute(); len(c) == 0 {
				t.Errorf("validator code len is 0")
			} else {
				//_ = WithDebug && Dbg("key validation code: %s", c)
				if !a.Validator.Validate(c) {
					t.Errorf("key is not valid")
				}
			}
		}
		GenerateAllKeysWithPassphrase(pass)
		for i := 0; i < n; i++ {
			go wt()
		}
	})
	t.Run("uris", func(t *testing.T) {
		defer waitForAll()
		uris := [...][]byte{
			[]byte("sip:servicevolontaireinternational@bar.com"),
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
		// worker thread function
		wt := func() {
			defer ready()
			var (
				anonBuf   [uriMaxBufSize]byte
				deanonBuf [uriMaxBufSize]byte
			)
			a, err := NewAnonymizer("a86483ec-8568-48da-b2cc-b4db9307d7f4")
			if err != nil {
				t.Fatalf("anonymizer initialization failure")
			}
			a.UpdateKeys(Keys[:])
			for _, u := range uris {
				a.Uri.Parse(u)
				aUri, err := a.Uri.Anonymize(anonBuf[:], u)
				if err != nil {
					t.Fatalf("could not anonymize SIP URI %s: %s", u, err)
				}
				_ = WithDebug && Dbg("anonymized uri: %v %s", aUri, string(aUri))
				dUri, err := a.Uri.Deanonymize(deanonBuf[:], aUri)
				if err != nil {
					t.Fatalf(`could not deanonymize SIP URI "%s": %s`, aUri, err)
				}
				_ = WithDebug && Dbg("deanonymized uri: %v %s", dUri, string(dUri))
				if !bytes.Equal(u, dUri) {
					t.Fatalf(`expected: "%s" got: "%s"`, u, dUri)
				}
			}
		}
		GenerateAllKeysWithPassphrase(pass)
		for i := 0; i < n; i++ {
			go wt()
		}
	})
	t.Run("call-id", func(t *testing.T) {
		defer waitForAll()
		// test case data
		callIds := [...][]byte{
			[]byte(""),
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
			[]byte("3a47be62-d375a8278d51bf575997bcc342233ca8@10.1.6.1"),
		}
		pCallIds := make([]sipsp.PCallIDBody, len(callIds))
		for i, s := range callIds {
			pCallIds[i].Reset()
			if _, err := sipsp.ParseCallIDVal([]byte(string(s)+"\r\n"), 0, &pCallIds[i]); (err != sipsp.ErrHdrOk) && (err != sipsp.ErrHdrMoreBytes) {
				t.Fatalf(`error parsing SIP Call-ID "%s": %v`, string(s), err)
			}
		}
		// worker thread function
		wt := func() {
			defer ready()
			a, err := NewAnonymizer("a86483ec-8568-48da-b2cc-b4db9307d7f4")
			if err != nil {
				t.Fatalf("anonymizer initialization failure")
			}
			a.UpdateKeys(Keys[:])
			for i, c := range pCallIds {
				_ = WithDebug && Dbg("test case Call-ID: %s", string(callIds[i]))
				a.CallId.PField = c.CallID
				//anonym := make([]byte, 4*len(callIds[i])+NewEncoding().EncodedLen(CallIdCBC().Encrypter.BlockSize()))
				aBuf := NewAnonymizationBuf(len(callIds[i]))
				aCallId, err := a.CallId.Anonymize(aBuf, callIds[i])
				if err != nil {
					t.Fatalf("cannot anonymize Call-ID %s: %s", callIds[i], err.Error())
				}
				_ = WithDebug && Dbg("anonymized Call-ID: %v %s (len: %d)", aCallId, string(aCallId), len(aCallId))
				pBuf := NewAnonymizationBuf(len(aCallId))
				dCallId, err := a.CallId.Deanonymize(pBuf, aCallId)
				if err != nil {
					_ = WithDebug && Dbg("decrypted Call-ID: %v", pBuf)
					t.Fatalf("cannot decrypt Call-ID %s: %s", aCallId, err.Error())
				}
				_ = WithDebug && Dbg(`deanonymized Call-ID: %v "%s"`, dCallId, string(dCallId))
				if !bytes.Equal(callIds[i], dCallId) {
					t.Fatalf(`expected: "%s" got: "%s"`, callIds[i], string(dCallId))
				}
			}
		}
		GenerateAllKeysWithPassphrase(pass)
		for i := 0; i < n; i++ {
			go wt()
		}
	})
}
