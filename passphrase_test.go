package anonymization

import (
	"bufio"
	"crypto"
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
	}
}

func TestKeyValidationCode(t *testing.T) {
	stdout := bufio.NewWriter(os.Stdout)
	passphrases := [...]string{
		"foobar",
		"123456abcd78910aaaaabbb",
		"password",
	}
	var ch chan int = make(chan int, len(passphrases))
	t.Run("multiple threads compute key validation code", func(t *testing.T) {
		defer stdout.Flush()
		for _, p := range passphrases {
			go func() {
				k := GenerateKeyFromPassphrase(p, AuthenticationKeyLen)
				// local key validator with nonce
				if validator, err := NewKeyValidator(crypto.SHA256, k, 0, "salt", NonceCounter, true, true); err != nil {
					t.Fatalf("validator initialization error %s", err)
				} else {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debugTest(stdout, "key validation code: %s\n", c)
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
		defer stdout.Flush()
		for _, p := range passphrases {
			go func() {
				k := GenerateKeyFromPassphrase(p, AuthenticationKeyLen)
				// local key validator with nonce
				if validator, err := NewKeyValidator(crypto.SHA256, k, 0, "salt", NonceCounter, true, true); err != nil {
					t.Fatalf("validator initialization error %s", err)
				} else {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debugTest(stdout, "key validation code: %s\n", c)
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
		for range passphrases {
			<-ch
		}
	})
	t.Run("one thread with pre-allocated validator", func(t *testing.T) {
		defer stdout.Flush()
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		go func() {
			// pre-allocated validator with nonce
			if validator, err := NewKeyValidator(crypto.SHA256, k, 0, "salt", NonceCounter, true, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				for i := 0; i < 10; i++ {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debugTest(stdout, "key validation code: %s\n", c)
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
		defer stdout.Flush()
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		go func() {
			// on-the-fly key validator with nonce
			if validator, err := NewKeyValidator(crypto.SHA256, k, 0, "salt", NonceCounter, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				for i := 0; i < 10; i++ {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debugTest(stdout, "key validation code: %s\n", c)
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
		defer stdout.Flush()
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewKeyValidator(crypto.SHA256, k, l, "salt", NonceCounter, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					debugTest(stdout, "key validation code: %s\n", c)
					if !validator.Validate(c) {
						t.Errorf("key is not valid")
					}
				}
			}
		}
	})
	t.Run("no nonce", func(t *testing.T) {
		defer stdout.Flush()
		k := GenerateKeyFromPassphrase(passphrases[0], AuthenticationKeyLen)
		debugTest(stdout, "authentication key: %v\n", k)
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewKeyValidator(crypto.SHA256, k, l, "salt", NonceNone, false); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					debugTest(stdout, "key validation code: %s\n", c)
					if !validator.Validate(c) {
						t.Errorf("key is not valid")
					}
				}
			}
		}
	})
	t.Run("passphrase validator", func(t *testing.T) {
		defer stdout.Flush()
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewPassphraseValidator(passphrases[0], l, "salt"); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					debugTest(stdout, "key validation code: %s\n", c)
					if !validator.Validate(c) {
						t.Errorf("key is not valid")
					}
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
		if validator, err := NewKeyValidator(crypto.SHA256, k, 0, uuid.New().String(), NonceCounter, true, true); err != nil {
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
