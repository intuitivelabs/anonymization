package anonymization

import (
	"bytes"
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
				res, err := a.Uri.Anonymize(anonBuf[:], u)
				if err != nil {
					t.Fatalf("could not anonymize SIP URI %s: %s", u, err)
				}
				_ = WithDebug && Dbg("anonymized uri: %v %s", anonBuf, string(res))
				if _, err := a.Uri.Deanonymize(deanonBuf[:], res); err != nil {
					t.Fatalf(`could not deanonymize SIP URI "%s": %s`, string((a.Uri).Flat(deanonBuf[:])), err)
				}
				_ = WithDebug && Dbg("deanonymized uri: %v %s", deanonBuf, string((a.Uri).Flat(deanonBuf[:])))
				if !bytes.Equal(u, (a.Uri).Flat(deanonBuf[:])) {
					t.Fatalf(`expected: "%s" got: "%s"`, u, string((a.Uri).Flat(deanonBuf[:])))
				}
			}
		}
		GenerateAllKeysWithPassphrase(pass)
		for i := 0; i < n; i++ {
			go wt()
		}
	})
}
