package anonymization

import (
	"bytes"
	"net"
	"testing"
)

func TestPanIPv4(t *testing.T) {
	// set-up if needed
	key := [16]byte{21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16}
	iv := [16]byte{216, 152, 143, 131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2}
	var encKey [EncryptionKeyLen]byte
	pass := "reallyworks?"
	GenerateKeyFromPassphraseAndCopy(pass, EncryptionKeyLen, encKey[:])
	t.Run("random keys", func(t *testing.T) {
		var enc, dec net.IP
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
			[]byte{1, 2, 3, 4},
			[]byte{1, 5, 6, 7},
			[]byte{1, 2, 8, 9},
			[]byte{1, 2, 3, 10},
		}
		pan := GetPan4().WithKeyAndIV(key, iv).WithBitsPrefixBoundary(EightBitsPrefix)
		enc = make([]byte, net.IPv4len)
		dec = make([]byte, net.IPv4len)
		for _, c := range cases {
			pan.Encrypt(enc, c)
			t.Logf("plain: %s encrypted: %s", c.String(), enc.String())
			pan.Decrypt(dec, enc)
			t.Logf("encrypted: %s decrypted: %s", enc.String(), dec.String())
			if !bytes.Equal(dec, c) {
				t.Errorf("expected: %s have: %s (enc: %s)", c.String(), dec.String(), enc.String())
			}
		}
	})
	t.Run("password keys", func(t *testing.T) {
		var enc, dec net.IP
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
			[]byte{1, 2, 3, 4},
			[]byte{1, 5, 6, 7},
			[]byte{1, 2, 8, 9},
			[]byte{1, 2, 3, 10},
			[]byte{85, 2, 3, 10},
		}
		pan := GetPan4().WithMasterKey(encKey[:]).WithBitsPrefixBoundary(EightBitsPrefix)
		enc = make([]byte, net.IPv4len)
		dec = make([]byte, net.IPv4len)
		for _, c := range cases {
			pan.Encrypt(enc, c)
			t.Logf("plain: %s encrypted: %s", c.String(), enc.String())
			pan.Decrypt(dec, enc)
			t.Logf("encrypted: %s decrypted: %s", enc.String(), dec.String())
			if !bytes.Equal(dec, c) {
				t.Errorf("expected: %s have: %s (enc: %s)", c.String(), dec.String(), enc.String())
			}
		}
	})
	t.Run("strings", func(t *testing.T) {
		cases := []string{
			"24.5.0.80",
			"22.11.33.44",
			"255.0.255.241",
			"1.2.3.4",
			"1.5.6.7",
			"1.2.8.9",
			"1.2.3.10",
			"85.2.3.10",
		}
		pan := GetPan4().WithMasterKey(encKey[:]).WithBitsPrefixBoundary(EightBitsPrefix)
		for _, c := range cases {
			enc, err := pan.EncryptStr(c)
			if err != nil {
				t.Errorf("encryption error for ip address: %s", c)
			}
			t.Logf("plain: %s encrypted: %s", c, enc)
			dec, err := pan.DecryptStr(enc)
			if err != nil {
				t.Errorf("decryption error for plain ip address: %s", c)
			}
			t.Logf("encrypted: %s decrypted: %s", enc, dec)
			if dec != c {
				t.Errorf("expected: %s have: %s (enc: %s)", c, dec, enc)
			}
		}
	})
}

func BenchmarkPanIP(b *testing.B) {
	// set-up if needed
	df := DbgOff()
	defer DbgRestore(df)
	key := [16]byte{21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16}
	iv := [16]byte{216, 152, 143, 131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2}
	pan := GetPan4().WithKeyAndIV(key, iv)
	b.Run("IPv4 1 bit boundary", func(b *testing.B) {
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			//[]byte{24, 5, 56, 22},
			//[]byte{22, 11, 33, 44},
			//[]byte{255, 0, 255, 241},
		}
		pan = GetPan4().WithBitsPrefixBoundary(OneBitPrefix)
		var enc net.IP
		enc = make([]byte, net.IPv4len)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				pan.Encrypt(enc, c)
			}
		}
	})
	b.Run("IPv4 2 bits boundary", func(b *testing.B) {
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			//[]byte{24, 5, 56, 22},
			//[]byte{22, 11, 33, 44},
			//[]byte{255, 0, 255, 241},
		}
		var enc net.IP
		pan = GetPan4().WithBitsPrefixBoundary(TwoBitsPrefix)
		enc = make([]byte, net.IPv4len)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				pan.Encrypt(enc, c)
			}
		}
	})
	b.Run("IPv4 4 bits boundary", func(b *testing.B) {
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			//[]byte{24, 5, 56, 22},
			//[]byte{22, 11, 33, 44},
			//[]byte{255, 0, 255, 241},
		}
		var enc net.IP
		pan = GetPan4().WithBitsPrefixBoundary(FourBitsPrefix)
		enc = make([]byte, net.IPv4len)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				pan.Encrypt(enc, c)
			}
		}
	})
	b.Run("IPv4 8 bits boundary", func(b *testing.B) {
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			//[]byte{24, 5, 56, 22},
			//[]byte{22, 11, 33, 44},
			//[]byte{255, 0, 255, 241},
		}
		var enc net.IP
		pan = GetPan4().WithBitsPrefixBoundary(EightBitsPrefix)
		enc = make([]byte, net.IPv4len)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				pan.Encrypt(enc, c)
			}
		}
	})
}
