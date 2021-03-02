package anonymization

import (
	"bufio"
	"crypto"
	"fmt"
	"os"
	"testing"
)

var (
	// controls the debug messages for tests
	DebugOn bool = false
)

func debug(w *bufio.Writer, format string, args ...interface{}) {
	if DebugOn {
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
				k := GenerateKeyFromPassphrase(p)
				// local key validator with nonce
				if validator, err := NewKeyValidator(crypto.SHA256, k, 0, true, true); err != nil {
					t.Fatalf("validator initialization error %s", err)
				} else {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debug(stdout, "key validation code: %s\n", c)
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
				k := GenerateKeyFromPassphrase(p)
				// local key validator with nonce
				if validator, err := NewKeyValidator(crypto.SHA256, k, 0, true, true); err != nil {
					t.Fatalf("validator initialization error %s", err)
				} else {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debug(stdout, "key validation code: %s\n", c)
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
		k := GenerateKeyFromPassphrase(passphrases[0])
		go func() {
			// pre-allocated validator with nonce
			if validator, err := NewKeyValidator(crypto.SHA256, k, 0, true, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				for i := 0; i < 10; i++ {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debug(stdout, "key validation code: %s\n", c)
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
		k := GenerateKeyFromPassphrase(passphrases[0])
		go func() {
			// on-the-fly key validator with nonce
			if validator, err := NewKeyValidator(crypto.SHA256, k, 0, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				for i := 0; i < 10; i++ {
					if c := validator.Compute(); len(c) == 0 {
						t.Errorf("validator code len is 0")
					} else {
						debug(stdout, "key validation code: %s\n", c)
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
		k := GenerateKeyFromPassphrase(passphrases[0])
		for l := 0; l <= crypto.SHA256.Size(); l++ {
			if validator, err := NewKeyValidator(crypto.SHA256, k, l, true); err != nil {
				t.Fatalf("validator initialization error %s", err)
			} else {
				if c := validator.Compute(); len(c) == 0 {
					t.Errorf("validator code len is 0")
				} else {
					debug(stdout, "key validation code: %s\n", c)
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
		k := GenerateKeyFromPassphrase(passphrases[0])
		// pre-allocated validator with nonce
		if validator, err := NewKeyValidator(crypto.SHA256, k, 0, true, true); err != nil {
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
