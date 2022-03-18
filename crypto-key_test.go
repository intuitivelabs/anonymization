package anonymization

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"os"
	"testing"
)

var (
	// controls the debug messages for tests
	debugTestOn bool = false
)

func debugTest(w *bufio.Writer, format string, args ...interface{}) {
	if debugTestOn {
		fmt.Fprintf(w, format, args...)
		w.Flush()
	}
}

func TestKeyValidationCode(t *testing.T) {
	df := DbgOn()
	defer DbgRestore(df)
	passphrases := [...]string{
		"foobar",
		"123456abcd78910aaaaabbb",
		"password",
	}
	t.Run("multiple threads compute key validation code", func(t *testing.T) {
		var ch chan int = make(chan int, len(passphrases))
		for _, p := range passphrases {
			go func() {
				k := GenerateKeyFromPassphrase(p, AuthenticationKeyLen)
				// local key validator with nonce
				if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, 0, "salt", NonceCounter, true, true); err != nil {
					t.Fatalf("validator initialization error %s", err)
				} else {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						_ = WithDebug && Dbg("key validation code: %s", c)
					}
				}
				// this thread is ready
				ch <- 1
			}()
		}
		// wait for all threads to finish
		for range passphrases {
			<-ch
		}
	})
	t.Run("multiple threads compute and verify key validation code", func(t *testing.T) {
		var ch chan int = make(chan int, len(passphrases))
		for _, p := range passphrases {
			go func() {
				k := GenerateKeyFromPassphrase(p, AuthenticationKeyLen)
				// local key validator with nonce
				if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, 0, "salt", NonceCounter, true, true); err != nil {
					t.Fatalf("validator initialization error %s", err)
				} else {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						_ = WithDebug && Dbg("key validation code: %s", c)
						if !validator.Validate(c) {
							t.Errorf("key is not valid")
						}
					}
				}
				// this thread is ready
				ch <- 1
			}()
		}
		// wait for all threads to finish
		for i, _ := range passphrases {
			<-ch
			_ = WithDebug && Dbg("thread %d finished", i)
		}
	})
	t.Run("one thread with pre-allocated validator", func(t *testing.T) {
		var ch chan int = make(chan int, len(passphrases))
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		go func() {
			// pre-allocated validator with nonce
			if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, 0, "salt", NonceCounter, true, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				for i := 0; i < 10; i++ {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						_ = WithDebug && Dbg("key validation code: %s", c)
						if !validator.Validate(c) {
							t.Errorf("key is not valid")
						}
					}
				}
			}
			// this thread is ready
			ch <- 1
		}()
		// wait for the thread to finish
		<-ch
	})
	t.Run("one thread with on-the-fly validator", func(t *testing.T) {
		var ch chan int = make(chan int, len(passphrases))
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		go func() {
			// on-the-fly key validator with nonce
			if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, 0, "salt", NonceCounter, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				for i := 0; i < 10; i++ {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						_ = WithDebug && Dbg("key validation code: %s", c)
						if !validator.Validate(c) {
							t.Errorf("key is not valid")
						}
					}
				}
			}
			// this thread is ready
			ch <- 1
		}()
		// wait for the thread to finish
		<-ch
	})
	t.Run("variable length", func(t *testing.T) {
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, l, "salt", NonceCounter, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					_ = WithDebug && Dbg("key validation code: %s", c)
					if !validator.Validate(c) {
						t.Errorf("key is not valid")
					}
				}
			}
		}
	})
	t.Run("auth key from passphrase no nonce", func(t *testing.T) {
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		_ = WithDebug && Dbg("authentication key: %v", k)
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, l, "salt", NonceNone, false); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					_ = WithDebug && Dbg("key validation code: %s", c)
					if !validator.Validate(c) {
						t.Errorf("key is not valid")
					}
				}
			}
		}
	})
	t.Run("auth key from passphrase no nonce, salt a86483ec-8568-48da-b2cc-b4db9307d7f4", func(t *testing.T) {
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		_ = WithDebug && Dbg("authentication key: %v", k)
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, l, "a86483ec-8568-48da-b2cc-b4db9307d7f4", NonceNone, false); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					_ = WithDebug && Dbg("key validation code: %s", c)
					if !validator.Validate(c) {
						t.Errorf("key is not valid")
					}
				}
			}
		}
	})
	t.Run("auth key from passphrase no nonce, no salt validate remote code", func(t *testing.T) {
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		_ = WithDebug && Dbg("authentication key: %v", k)
		if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, 5, "", NonceNone, false); err != nil {
			t.Fatalf("validator initialization error %s", err)
		} else {
			c := "5c9b4:a86483ec-8568-48da-b2cc-b4db9307d7f4"
			_ = WithDebug && Dbg("key validation code: %s", c)
			if !validator.Validate(c) {
				t.Fatalf("key validator failed")
			}
		}
	})
	t.Run("auth key from encryption key no nonce", func(t *testing.T) {
		encKey := GenerateKeyFromPassphrase(passphrases[0], EncryptionKeyLen)
		_ = WithDebug && Dbg("encryption key: %v", encKey)
		authKey := GenerateKeyFromBytes(encKey[:], AuthenticationKeyLen)
		_ = WithDebug && Dbg("authentication key: %v", authKey)
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewKeyValidatorWithKey(crypto.SHA256, authKey, l, "salt", NonceNone, false); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					_ = WithDebug && Dbg("key validation code: %s", c)
					if !validator.Validate(c) {
						t.Errorf("key is not valid")
					}
				}
			}
		}
	})
}

func TestHexDecoder(t *testing.T) {
	df := DbgOff()
	defer DbgRestore(df)
	key := [...]byte{
		74,
		170,
		234,
		9,
		98,
		105,
		110,
		92,
		187,
		206,
		133,
		246,
		34,
		130,
		175,
		176,
	}
	t.Run("decode hex key", func(t *testing.T) {
		if decoded, err := hex.DecodeString("4aaaea0962696e5cbbce85f62282afb0"); err != nil {
			t.Fatalf("hex decoder error %s", err)
		} else {
			for i, d := range decoded {
				if key[i] != d {
					t.Fatalf("expected %d got %d", key[i], d)
				}
			}
		}
	})
}

func BenchmarkKeyValidationCode(b *testing.B) {
	stdout := bufio.NewWriter(os.Stdout)
	passphrases := [...]string{
		"foobar",
		"123456abcd78910aaaaabbb",
		"password",
	}
	b.Run("pre-allocated validator one compute op", func(b *testing.B) {
		defer stdout.Flush()
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		// pre-allocated validator with nonce
		if validator, err := NewKeyValidatorWithKey(crypto.SHA256, k, 0, uuid.New().String(), NonceCounter, true, true); err != nil {
			b.Fatalf("validator initialization error %s", err)
		} else {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if c := validator.Compute(); len(c) == 0 {
					b.Errorf("validator code len is 0")
				}
			}
		}
	})
}
