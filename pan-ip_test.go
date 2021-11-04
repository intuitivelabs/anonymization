package anonymization

import (
	"bytes"
	"net"
	"testing"
)

func TestPanIP(t *testing.T) {
	// set-up if needed
	key := [16]byte{21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16}
	iv := [16]byte{216, 152, 143, 131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2}
	pan, err := NewPanIPv4(key, iv)
	if err != nil {
		t.Fatalf("prefix-preserving IP address anonymizer initialization error")
	}
	t.Run("IPv4", func(t *testing.T) {
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			[]byte{24, 5, 56, 22},
			[]byte{22, 11, 33, 44},
			[]byte{255, 0, 255, 241},
		}
		var enc, dec net.IP
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
}

func BenchmarkPanIP(b *testing.B) {
	// set-up if needed
	df := DbgOff()
	defer DbgRestore(df)
	key := [16]byte{21, 34, 23, 141, 51, 164, 207, 128, 19, 10, 91, 22, 73, 144, 125, 16}
	iv := [16]byte{216, 152, 143, 131, 121, 121, 101, 39, 98, 87, 76, 45, 42, 132, 34, 2}
	pan, err := NewPanIPv4(key, iv)
	if err != nil {
		b.Fatalf("prefix-preserving IP address anonymizer initialization error")
	}
	b.Run("IPv4", func(b *testing.B) {
		cases := []net.IP{
			[]byte{24, 5, 0, 80},
			//[]byte{24, 5, 56, 22},
			//[]byte{22, 11, 33, 44},
			//[]byte{255, 0, 255, 241},
		}
		var enc net.IP
		enc = make([]byte, net.IPv4len)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, c := range cases {
				pan.Encrypt(enc, c)
			}
		}
	})
}
