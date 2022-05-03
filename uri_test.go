package anonymization

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

// static buffers for encryption, encoding, anonymization
var (
	encryptBuf [uriMaxBufSize]byte
	decryptBuf [uriMaxBufSize]byte
	encodeBuf  [uriMaxBufSize]byte
	decodeBuf  [uriMaxBufSize]byte
	anonBuf    [uriMaxBufSize]byte
	deanonBuf  [uriMaxBufSize]byte
)

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

func TestUriBase32Codec(t *testing.T) {
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
	// tests
	t.Run("encoding", func(t *testing.T) {
		au := NewAnonymURI()
		for i, u := range uris {
			_ = WithDebug && Dbg("test case uri: %s", string(u))
			if err := au.Parse(u); err != nil {
				t.Fatalf("could not parse SIP URI %s: %s", string(u), err)
			}
			l := au.EncodedLen(u)
			_ = WithDebug && Dbg("encoded len: %d", l)
			encoded := make([]byte, l)
			if err := au.Encode(encoded, u); err != nil {
				t.Fatalf("cannot encode URI %s: %s", u, err.Error())
			}
			_ = WithDebug && Dbg("encoded URI: %v (len: %d)", encoded, len(encoded))
			_ = WithDebug && Dbg("encoded URI: %s", string(au.Flat(encoded)))
			l = au.DecodedLen(encoded)
			decoded := make([]byte, l)
			if err := au.Decode(decoded, encoded); err != nil {
				_ = WithDebug && Dbg("decoded URI: %v", decoded)
				t.Fatalf("cannot decode URI %s: %s", uris[i], err.Error())
			}
			_ = WithDebug && Dbg("decoded URI: %s", string(au.Flat(decoded)))
			if !bytes.Equal(uris[i], au.Flat(decoded)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(au.Flat(decoded)))
			}
		}
	})
}

func TestUriCBCEncrypt(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	ukey, _ := hex.DecodeString("6368616e676520746869732070617373")
	hkey, _ := hex.DecodeString("7368616e676520746869732070617374")
	var iv [16]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		t.Fatalf("could not init IV: %s", err)
	}
	InitUriKeys(iv[:], ukey, hkey)
	cipher := NewUriCBCWithKeys(GetUriKeys())
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
	// tests
	t.Run("dynamic memory", func(t *testing.T) {
		au := NewAnonymURI()
		au.cbc = *cipher
		for i, u := range uris {
			_ = WithDebug && Dbg("test case uri: %s", string(uris[i]))
			au.Parse(u)
			l, err := au.PaddedLen()
			if err != nil {
				t.Fatalf("cannot compute URI pad len %s: %s", uris[i], err.Error())
			}
			_ = WithDebug && Dbg("padded len: %d", l)
			ciphertxt := make([]byte, l)
			if err := au.Encrypt(ciphertxt, uris[i]); err != nil {
				t.Fatalf("cannot encrypt URI %s: %s", uris[i], err.Error())
			}
			_ = WithDebug && Dbg("encrypted URI: %v (len: %d)", ciphertxt, len(ciphertxt))
			plaintxt := make([]byte, len(ciphertxt))
			if err := au.Decrypt(plaintxt, ciphertxt); err != nil {
				_ = WithDebug && Dbg("decrypted URI: %v", plaintxt)
				t.Fatalf("cannot decrypt URI %s: %s", uris[i], err.Error())
			}
			_ = WithDebug && Dbg("decrypted URI: %v %s", (au).Flat(plaintxt), string((au).Flat(plaintxt)))
			if !bytes.Equal(u, (au).Flat(plaintxt)) {
				t.Fatalf(`expected: "%s" got: "%s"`, u, string((au).Flat(plaintxt)))
			}
		}
	})
	t.Run("static memory", func(t *testing.T) {
		au := NewAnonymURI()
		au.cbc = *cipher
		for i, u := range uris {
			_ = WithDebug && Dbg("test case uri: %s", string(u))
			au.Parse(u)
			l, err := au.PaddedLen()
			if err != nil {
				t.Fatalf("cannot compute URI pad len %s: %s", u, err.Error())
			}
			_ = WithDebug && Dbg("padded len: %d", l)
			ciphertxt := EncryptBuf()
			if err := au.Encrypt(ciphertxt, u); err != nil {
				t.Fatalf("cannot encrypt URI %s: %s", u, err.Error())
			}
			_ = WithDebug && Dbg("encrypted URI: %v (len: %d)", (au).Flat(ciphertxt), len((au).Flat(ciphertxt)))
			plaintxt := DecryptBuf()
			if err := au.Decrypt(plaintxt, ciphertxt); err != nil {
				_ = WithDebug && Dbg("decrypted URI: %v", plaintxt)
				t.Fatalf("cannot decrypt URI %s: %s", u, err.Error())
			}
			_ = WithDebug && Dbg("decrypted URI: %v %s", (au).Flat(plaintxt), string((au).Flat(plaintxt)))
			if !bytes.Equal(u, (au).Flat(plaintxt)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string((au).Flat(plaintxt)))
			}
		}
	})
	t.Run("parameters", func(t *testing.T) {
		au := NewAnonymURI()
		au.cbc = *cipher
		for i, u := range urisPPH {
			_ = WithDebug && Dbg("test case uri: %s", string(urisPPH[i]))
			au.Parse(u)
			l, err := au.PaddedLen()
			if err != nil {
				t.Fatalf("cannot compute URI pad len %s: %s", urisPPH[i], err.Error())
			}
			_ = WithDebug && Dbg("padded len: %d", l)
			ciphertxt := EncryptBuf()
			// host only encryption
			if err := au.Encrypt(ciphertxt, urisPPH[i], true); err != nil {
				t.Fatalf("cannot encrypt URI %s: %s", urisPPH[i], err.Error())
			}
			_ = WithDebug && Dbg("encrypted URI: %v (len: %d)", (au).Flat(ciphertxt), len((au).Flat(ciphertxt)))
			plaintxt := DecryptBuf()
			if err := au.Decrypt(plaintxt, ciphertxt); err != nil {
				_ = WithDebug && Dbg("decrypted URI: %v", plaintxt)
				t.Fatalf("cannot decrypt URI %s: %s", urisPPH[i], err.Error())
			}
			_ = WithDebug && Dbg("decrypted URI: %v %s", (au).Flat(plaintxt), string((au).Flat(plaintxt)))
			if !bytes.Equal(urisPPH[i], (au).Flat(plaintxt)) {
				t.Fatalf(`expected: "%s" got: "%s"`, urisPPH[i], string((au).Flat(plaintxt)))
			}
		}
	})
	// clean-up
}

func TestUriAnonymization(t *testing.T) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	var encKey [EncryptionKeyLen]byte
	pass := "foobar"
	GenerateKeyFromPassphraseAndCopy(pass, EncryptionKeyLen, encKey[:])

	// initialize the URI CBC based encryption
	InitUriKeysFromMasterKey(encKey[:])
	cipher := NewUriCBCWithKeys(GetUriKeys())
	GenerateAllKeysWithPassphrase(pass)
	// test case data
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
		[]byte("sip:0049567683269215869@188.74.3.208:3894"),
		[]byte("sip:0049567683269215000@188.74.3.208:3894"),
		[]byte("sip:004924554390004@85.212.141.52"),
	}
	// tests
	t.Run("CBC state", func(t *testing.T) {
		au := NewAnonymURI()
		au.cbc = *cipher
		for i, u := range uris {
			_ = WithDebug && Dbg("test case uri: %s", string(uris[i]))
			au.Parse(u)
			anon := AnonymizeBuf()
			res, err := au.Anonymize(anon, uris[i], true)
			if err != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
			}
			_ = WithDebug && Dbg("anonymized uri: %v %s", au.Flat(anon), string(au.Flat(anon)))
			dupAnon := make([]byte, len(anon))
			dupAu := NewAnonymURI()
			dupAu.cbc = *cipher
			dupRes, dupErr := dupAu.Anonymize(dupAnon, uris[i], true)
			if dupErr != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], dupErr)
			}
			_ = WithDebug && Dbg("duplicated anonymized uri: %v %s", au.Flat(dupAnon), string(dupAu.Flat(dupAnon)))
			if !bytes.Equal(res, dupRes) {
				t.Fatalf(`expected: "%s" got: "%s"`, res, dupRes)
			}
		}
	})
	// anonymize everything including parameters
	t.Run("CBC everything", func(t *testing.T) {
		au := NewAnonymURI()
		au.cbc = *cipher
		for i, u := range uris {
			_ = WithDebug && Dbg("test case uri: %s", string(uris[i]))
			anonBuf := AnonymizeBuf()
			res, err := au.Anonymize(anonBuf, u)
			if err != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
			}
			_ = WithDebug && Dbg("anonymized uri: %v %s", au.Flat(anonBuf), string(au.Flat(anonBuf)))
			deanonBuf := DeanonymizeBuf()
			if _, err := au.Deanonymize(deanonBuf, res); err != nil {
				t.Fatalf(`could not deanonymize SIP URI "%s": %s`, string(au.Flat(deanonBuf)), err)
			}
			_ = WithDebug && Dbg("deanonymized uri: %v %s", au.Flat(deanonBuf), string(au.Flat(deanonBuf)))
			if !bytes.Equal(uris[i], au.Flat(deanonBuf)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(au.Flat(deanonBuf)))
			}
		}
	})
	// anonymize only the host part
	t.Run("CBC host only", func(t *testing.T) {
		au := NewAnonymURI()
		au.cbc = *cipher
		for i, u := range uris {
			_ = WithDebug && Dbg("test case uri: %s", string(uris[i]))
			au.Parse(u)
			anonBuf := AnonymizeBuf()
			res, err := au.Anonymize(anonBuf, uris[i], true)
			if err != nil {
				t.Fatalf("could not anonBufymize SIP URI %s: %s", uris[i], err)
			}
			_ = WithDebug && Dbg("anonymized uri: %v %s", au.Flat(anonBuf), string(au.Flat(anonBuf)))
			deanonBuf := DeanonymizeBuf()
			if _, err := au.Deanonymize(deanonBuf, res); err != nil {
				t.Fatalf("could not deanonBufymize SIP URI %s: %s", string(au.Flat(deanonBuf)), err)
			}
			_ = WithDebug && Dbg("deanonymized uri: %v %s", au.Flat(deanonBuf), string(au.Flat(deanonBuf)))
			if !bytes.Equal(uris[i], au.Flat(deanonBuf)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(au.Flat(deanonBuf)))
			}
		}
	})
	t.Run("CBC deanonymize", func(t *testing.T) {
		pass := "reallyworks?"
		//pass := "foobar"
		GenerateKeyFromPassphraseAndCopy(pass, EncryptionKeyLen, encKey[:])
		// generate IV for CBC
		InitUriKeysFromMasterKey(encKey[:])
		cipher := NewUriCBCWithKeys(GetUriKeys())
		anonUris := [...][]byte{
			//[]byte("sip:7FIQTTVPC65OONS0H7B1O9EAE8------@86O14ERFB383DT1IOALB79L798------"),
			//[]byte("sip:A772DEUD3QBO8KNHHNA74OUVES------@JPPO6K1G21K9I2SIN5CV46RIT8------"),
			//[]byte("sip:JCTP1JJ8TG2ACGR8F6KNDEG64HFT06M1DT1U78G0MJN632OQA9K0----@NPIR7UEGG8PMB8CSH9HV2FI418------"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=udp"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------:5060"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------:52451"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=TCP"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=udp"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=udp"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=udp"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------;transport=UDP"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------;transport=UDP"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------"),
			[]byte("sip:8NIPFUI4FUGSLPKFGR259U2DP0------:5060"),
			[]byte("sip:6EDC39UMVHBNMPSLTE6JTP10T8------:5060"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=udp"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------"),
			[]byte("sip:8NIPFUI4FUGSLPKFGR259U2DP0------:5060"),
			[]byte("sip:6EDC39UMVHBNMPSLTE6JTP10T8------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:ON38L4CVRHPFBCMT80VKDMT6C7760E94I956159PN4QG7LVC1ARK18FCNVSAGKQDDNSJKSARB72MA---@QBBQFEF02K3ME7NNRLEH8K74SO------;transport=tcp"),
			[]byte("sip:H6H9BJD7GMFGP4JCO203D7U9714AGSL19F133EN4CAV4QEI5K0A09BD32HOGI5T657N49OR2CQHBA---@5814S48BAJN4J7I5IT78I2UP58------:6060;transport=udp"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------;transport=udp"),
			[]byte("sip:8NIPFUI4FUGSLPKFGR259U2DP0------:5060"),
			[]byte("sip:H6H9BJD7GMFGP4JCO203D7U9714AGSL19F133EN4CAV4QEI5K0A09BD32HOGI5T657N49OR2CQHBA---@5814S48BAJN4J7I5IT78I2UP58------:6060;transport=udp"),
			[]byte("sip:ON38L4CVRHPFBCMT80VKDMT6C7760E94I956159PN4QG7LVC1ARK18FCNVSAGKQDDNSJKSARB72MA---@QBBQFEF02K3ME7NNRLEH8K74SO------;transport=tcp"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------:5060"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------:5060"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------:5060"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=udp"),
			[]byte("sip:8VDBLC53S5QFOR9P66FBFU4QSESSSHAKPK7DL5T7040L8C0F1MAA8124N6786SO4LAD2773KORSCK---@QBBQFEF02K3ME7NNRLEH8K74SO------;transport=tcp"),
			[]byte("sip:8QU3C0LRJNRFMMEVDVQ1MV4BV7PGTEGM1J0DCDA545FF151KUV49M01DRUPN9T5ALDOV47F0I9N8U---@5814S48BAJN4J7I5IT78I2UP58------:6060;transport=udp"),
			[]byte("sip:F1DE003325Q2CJ31078SIHF3GS------@7HA830BV110MUUI2BQS6ND460S------;transport=tcp"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------;transport=udp"),
			[]byte("sip:QBBQFEF02K3ME7NNRLEH8K74SO------"),
			[]byte("sip:3RM2IBPBINP51Q5LVDSLB9IR898LQKD3V4RLFSSIDIFEGOSOVRO014F9CJNOA82CI2S9NJ5N1Q584---@QBBQFEF02K3ME7NNRLEH8K74SO------;transport=tcp"),
			[]byte("sip:7C6T7T9T0FE0DAKQ5EVNCKT2FDB98SONEEUSEEG2V4PFNU7SU26CCKK5MNVPUU1Q3F353HDJBBMEC---@5814S48BAJN4J7I5IT78I2UP58------:6060;transport=udp"),
			[]byte("sip:N3LNAR532OE76RC1R2NU6EJA94------@D787LEH7Q5HD0B6GDBUDEH2U7O------:5072;ob"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060;transport=udp"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:SFGMAPUB715DRE02K54NHL4MQ0------@A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=tcp"),
			[]byte("sip:SFGMAPUB715DRE02K54NHL4MQ0------@A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=tcp"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060;transport=udp"),
			[]byte("sip:SFGMAPUB715DRE02K54NHL4MQ0------@A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=tcp"),
			[]byte("sip:SFGMAPUB715DRE02K54NHL4MQ0------@A31DOJ6AEUIUPE2MFCGO5ESAH0------;transport=tcp"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------:5060"),
			[]byte("sip:NPIR7UEGG8PMB8CSH9HV2FI418------;transport=udp"),
			[]byte("sip:A31DOJ6AEUIUPE2MFCGO5ESAH0------:5060;transport=udp"),
		}
		for i, u := range anonUris {
			au := NewAnonymURI()
			au.cbc = *cipher
			au.WithBase32Codec()
			_ = WithDebug && Dbg("test case uri: %s", string(anonUris[i]))
			au.Parse(u)
			deanon := DeanonymizeBuf()
			if _, err := au.Deanonymize(deanon, anonUris[i]); err != nil {
				t.Fatalf("could not deanonymize SIP URI %s: %s", anonUris[i], err)
			}
			_ = WithDebug && Dbg("deanonymized uri: %v %s", au.Flat(deanon), string(au.Flat(deanon)))
		}
	})
	t.Run("Pan everything", func(t *testing.T) {
		au := NewAnonymURI()
		au.WithHexCodec()
		au.WithKeyingMaterial(Keys[:])
		au.WithPan()
		for i, u := range uris {
			_ = WithDebug && Dbg("test case uri: %s", string(uris[i]))
			anonBuf := AnonymizeBuf()
			res, err := au.Anonymize(anonBuf, u)
			if err != nil {
				t.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
			}
			_ = WithDebug && Dbg("anonymized uri: %v %s", au.Flat(anonBuf), string(au.Flat(anonBuf)))
			deanonBuf := DeanonymizeBuf()
			if _, err := au.Deanonymize(deanonBuf, res); err != nil {
				t.Fatalf(`could not deanonymize SIP URI "%s": %s`, string(au.Flat(deanonBuf)), err)
			}
			_ = WithDebug && Dbg("deanonymized uri: %v %s", au.Flat(deanonBuf), string(au.Flat(deanonBuf)))
			if !bytes.Equal(uris[i], au.Flat(deanonBuf)) {
				t.Fatalf(`expected: "%s" got: "%s"`, uris[i], string(au.Flat(deanonBuf)))
			}
		}
	})
}

func BenchmarkUriAnonymization(b *testing.B) {
	// init
	df := DbgOn()
	defer DbgRestore(df)
	var encKey [EncryptionKeyLen]byte
	pass := "foobar"
	// initialize the URI CBC based encryption
	GenerateKeyFromPassphraseAndCopy(pass, EncryptionKeyLen, encKey[:])
	InitUriKeysFromMasterKey(encKey[:])
	cipher := NewUriCBCWithKeys(GetUriKeys())
	auCBC := NewAnonymURI()
	auCBC.cbc = *cipher
	// initialize the URI Pan based encryption
	GenerateAllKeysWithPassphrase(pass)
	auPan := AnonymURI{}
	auPan.WithKeyingMaterial(Keys[:])
	auPan.WithPan()
	// test case data
	uris := [...][]byte{
		[]byte("sip:004956768326@188.74.3.208:3894"),
		[]byte("sip:004956768326@188.74.3.208:3894"),
		[]byte("sip:004956769215869@188.74.3.208:3894"),
	}
	b.Run("CBC", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for i, u := range uris {
				auCBC.Parse(u)
				anon := make([]byte, 3000)
				if _, err := auCBC.Anonymize(anon, uris[i], true); err != nil {
					b.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
				}
			}
		}
	})
	b.Run("pan", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for i, u := range uris {
				auPan.Parse(u)
				anon := make([]byte, 3000)
				if _, err := auPan.Anonymize(anon, uris[i], true); err != nil {
					b.Fatalf("could not anonymize SIP URI %s: %s", uris[i], err)
				}
			}
		}
	})
}
