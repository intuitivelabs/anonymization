package anonymization

import (
	"bytes"
	"net"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// initialize whatever needs to be initialized
	os.Exit(m.Run())
}

func TestEncryptIP(t *testing.T) {
	// set-up if needed
	t.Run("IPv4, passphrase", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			[]byte{198, 41, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		passphrase := "justapassword"
		var key [16]byte
		GenerateKeyFromPassphraseAndCopy(passphrase, EncryptionKeyLen, key[:])
		var enc, dec net.IP
		enc = make([]byte, net.IPv4len)
		dec = make([]byte, net.IPv4len)
		for _, c := range cases {
			if err := EncryptIP(key, enc, c); err != nil {
				t.Fatalf("encryption error %s for IP %s", err, c.String())
			}
			if err := DecryptIP(key, dec, enc); err != nil {
				t.Fatalf("decryption error %s for IP %s", err, c.String())
			}
			if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
	t.Run("IPv4, key", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			[]byte{198, 41, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		var key [16]byte = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		var enc, dec net.IP
		enc = make([]byte, net.IPv4len)
		dec = make([]byte, net.IPv4len)
		for _, c := range cases {
			if err := EncryptIP(key, enc, c); err != nil {
				t.Fatalf("encryption error %s for IP %s", err, c.String())
			}
			if err := DecryptIP(key, dec, enc); err != nil {
				t.Fatalf("decryption error %s for IP %s", err, c.String())
			}
			if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
	t.Run("IPv6, passphrase", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4, 255, 0, 255, 241, 251, 6, 245, 231, 51, 60, 145, 231},
			[]byte{198, 41, 56, 22, 123, 10, 133, 144, 98, 4, 11, 12, 13, 18, 15, 164},
			[]byte{22, 11, 33, 44, 255, 30, 255, 241, 20, 101, 6, 8, 250, 0, 75, 61},
			[]byte{255, 0, 255, 241, 210, 20, 155, 241, 75, 40, 235, 221, 225, 50, 215, 141},
		}
		passphrase := "anotherlongpassword"
		var key [16]byte
		GenerateKeyFromPassphraseAndCopy(passphrase, EncryptionKeyLen, key[:])
		var enc, dec net.IP
		enc = make([]byte, net.IPv6len)
		dec = make([]byte, net.IPv6len)
		for _, c := range cases {
			if err := EncryptIP(key, enc, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			}
			if err := DecryptIP(key, dec, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			}
			if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
	t.Run("IPv6, key", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4, 255, 0, 255, 241, 251, 6, 245, 231, 51, 60, 145, 231},
			[]byte{198, 41, 56, 22, 123, 10, 133, 144, 98, 4, 11, 12, 13, 18, 15, 164},
			[]byte{22, 11, 33, 44, 255, 30, 255, 241, 20, 101, 6, 8, 250, 0, 75, 61},
			[]byte{255, 0, 255, 241, 210, 20, 155, 241, 75, 40, 235, 221, 225, 50, 215, 141},
		}
		var key [16]byte = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		var enc, dec net.IP
		enc = make([]byte, net.IPv6len)
		dec = make([]byte, net.IPv6len)
		for _, c := range cases {
			if err := EncryptIP(key, enc, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			}
			if err := DecryptIP(key, dec, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			}
			if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
}

func TestDecryptIP(t *testing.T) {
	// encryption and decryption are symmetrical
	TestEncryptIP(t)
}

func TestEncryptedIP(t *testing.T) {
	// set-up if needed
	t.Run("IPv4, passphrase", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			[]byte{198, 41, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		passphrase := "justapassword"
		var key [16]byte
		GenerateKeyFromPassphraseAndCopy(passphrase, EncryptionKeyLen, key[:])
		for _, c := range cases {
			if enc, err := EncryptedIP(key, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if dec, err := DecryptedIP(key, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			} else if decStr, err := DecryptedIPString(key, enc.String()); err != nil {
				t.Fatalf("decryption error: %s for string IP %s", err, c.String())
			} else if c.String() != decStr {
				t.Errorf("expected %s have %s:", c.String(), decStr)
			}
		}
	})
	t.Run("IPv4, key", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			[]byte{198, 41, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		var key [16]byte = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		for _, c := range cases {
			if enc, err := EncryptedIP(key, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if dec, err := DecryptedIP(key, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
	t.Run("IPv6, passphrase", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4, 255, 0, 255, 241, 251, 6, 245, 231, 51, 60, 145, 231},
			[]byte{198, 41, 56, 22, 123, 10, 133, 144, 98, 4, 11, 12, 13, 18, 15, 164},
			[]byte{22, 11, 33, 44, 255, 30, 255, 241, 20, 101, 6, 8, 250, 0, 75, 61},
			[]byte{255, 0, 255, 241, 210, 20, 155, 241, 75, 40, 235, 221, 225, 50, 215, 141},
		}
		passphrase := "anotherlongpassword"
		var key [16]byte
		GenerateKeyFromPassphraseAndCopy(passphrase, EncryptionKeyLen, key[:])
		for _, c := range cases {
			if enc, err := EncryptedIP(key, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if dec, err := DecryptedIP(key, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
	t.Run("IPv6, key", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4, 255, 0, 255, 241, 251, 6, 245, 231, 51, 60, 145, 231},
			[]byte{198, 41, 56, 22, 123, 10, 133, 144, 98, 4, 11, 12, 13, 18, 15, 164},
			[]byte{22, 11, 33, 44, 255, 30, 255, 241, 20, 101, 6, 8, 250, 0, 75, 61},
			[]byte{255, 0, 255, 241, 210, 20, 155, 241, 75, 40, 235, 221, 225, 50, 215, 141},
		}
		var key [16]byte = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		for _, c := range cases {
			if enc, err := EncryptedIP(key, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if dec, err := DecryptedIP(key, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
}

func TestDecryptedIP(t *testing.T) {
	// encryption and decryption are symmetrical
	TestEncryptedIP(t)
}

func TestEncryptIPInPlace(t *testing.T) {
	// set-up if needed
	t.Run("IPv4, passphrase", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			[]byte{198, 41, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		passphrase := "justapassword"
		var key [16]byte
		GenerateKeyFromPassphraseAndCopy(passphrase, EncryptionKeyLen, key[:])
		var tmpIP net.IP
		tmpIP = make([]byte, net.IPv4len)
		for _, c := range cases {
			copy(tmpIP, c)
			if err := EncryptIPInPlace(key, tmpIP); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if err := DecryptIPInPlace(key, tmpIP); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(tmpIP, c) {
				t.Errorf("expected %s have %s:", c.String(), tmpIP.String())
			}
		}
	})
	t.Run("IPv4, key", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			[]byte{198, 41, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		var key [16]byte = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		for _, c := range cases {
			if enc, err := EncryptedIP(key, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if dec, err := DecryptedIP(key, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
	t.Run("IPv6, passphrase", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4, 255, 0, 255, 241, 251, 6, 245, 231, 51, 60, 145, 231},
			[]byte{198, 41, 56, 22, 123, 10, 133, 144, 98, 4, 11, 12, 13, 18, 15, 164},
			[]byte{22, 11, 33, 44, 255, 30, 255, 241, 20, 101, 6, 8, 250, 0, 75, 61},
			[]byte{255, 0, 255, 241, 210, 20, 155, 241, 75, 40, 235, 221, 225, 50, 215, 141},
		}
		passphrase := "anotherlongpassword"
		var key [16]byte
		GenerateKeyFromPassphraseAndCopy(passphrase, EncryptionKeyLen, key[:])
		for _, c := range cases {
			if enc, err := EncryptedIP(key, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if dec, err := DecryptedIP(key, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
	t.Run("IPv6, key", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4, 255, 0, 255, 241, 251, 6, 245, 231, 51, 60, 145, 231},
			[]byte{198, 41, 56, 22, 123, 10, 133, 144, 98, 4, 11, 12, 13, 18, 15, 164},
			[]byte{22, 11, 33, 44, 255, 30, 255, 241, 20, 101, 6, 8, 250, 0, 75, 61},
			[]byte{255, 0, 255, 241, 210, 20, 155, 241, 75, 40, 235, 221, 225, 50, 215, 141},
		}
		var key [16]byte = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		for _, c := range cases {
			if enc, err := EncryptedIP(key, c); err != nil {
				t.Fatalf("encryption error: %s for IP %s", err, c.String())
			} else if dec, err := DecryptedIP(key, enc); err != nil {
				t.Fatalf("decryption error: %s for IP %s", err, c.String())
			} else if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
}

func TestDecryptIPInPlace(t *testing.T) {
	// encryption and decryption are symmetrical
	TestEncryptIPInPlace(t)
}

func TestEncrypt(t *testing.T) {
	passphrase := "justalonglongpasswordforanonymization"
	ipCipher, err := NewPassphraseCipher(passphrase)
	if err != nil {
		t.Errorf("ipcipher error: %s ", err)
	}
	t.Run("IPv4", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			[]byte{198, 41, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		var enc, dec net.IP
		enc = make([]byte, net.IPv4len)
		dec = make([]byte, net.IPv4len)
		for _, c := range cases {
			ipCipher.Encrypt(enc, c)
			ipCipher.Decrypt(dec, enc)
			if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
			var decStr string
			ipCipher.Encrypt(enc, c)
			decStr = ipCipher.(*Ipcipher).DecryptStr(enc.String())
			if decStr != c.String() {
				t.Errorf("expected %s have %s:", c.String(), decStr)
			}
		}
	})
	t.Run("IPv6", func(t *testing.T) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4, 255, 0, 255, 241, 251, 6, 245, 231, 51, 60, 145, 231},
			[]byte{198, 41, 56, 22, 123, 10, 133, 144, 98, 4, 11, 12, 13, 18, 15, 164},
			[]byte{22, 11, 33, 44, 255, 30, 255, 241, 20, 101, 6, 8, 250, 0, 75, 61},
			[]byte{255, 0, 255, 241, 210, 20, 155, 241, 75, 40, 235, 221, 225, 50, 215, 141},
		}
		var enc, dec net.IP
		enc = make([]byte, net.IPv6len)
		dec = make([]byte, net.IPv6len)
		for _, c := range cases {
			ipCipher.Encrypt(enc, c)
			ipCipher.Decrypt(dec, enc)
			if !bytes.Equal(dec, c) {
				t.Errorf("expected %s have %s:", c.String(), dec.String())
			}
		}
	})
}

func TestDecrypt(t *testing.T) {
	TestEncrypt(t)
}

func BenchmarkEncryptIP(b *testing.B) {
	// set-up if needed
	key := [16]byte{21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16}
	b.Run("IPv4, passphrase", func(b *testing.B) {
		cases := []net.IP{
			[]byte{1, 2, 3, 4},
			//[]byte{198, 41, 56, 22},
			//[]byte{22, 11, 33, 44},
			//[]byte{255, 0, 255, 241},
		}
		var enc net.IP
		enc = make([]byte, net.IPv4len)
		b.ResetTimer()
		for _, c := range cases {
			for i := 0; i < b.N; i++ {
				if err := EncryptIP(key, enc, c); err != nil {
					b.Fatalf("encryption error %s for IP %s", err, c.String())
				}
			}
		}
	})
}
