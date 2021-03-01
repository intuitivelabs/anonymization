// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// see ipcipher specification here:
// https://powerdns.org/ipcipher/ipcipher.md.html

package anonymization

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strconv"
	"strings"
	"sync/atomic"
)

var (
	ErrParseValidationCode = errors.New("Validation code parse error")
)

const (
	Salt = "ipcipheripcipher"
	// key length is in bytes
	EncryptionKeyLen = 16
	IterationCount   = 50000
	// checksum size is in bytes
	ChecksumMaxSize   = 64
	ChecksumMinLength = 5
	// maximum length of an base 10 32 bit integer in ASCII characters
	MaxUintLen = 10
	// separator used in key validation code
	Separator = ':'
)

// KeyValidation is used for validating an encryption key
type KeyValidation struct {
	// is nonce used?
	withNonce bool
	// a random number
	nonce uint32
	// binary validation code - it is the output of hash function
	code []byte
	// hexadecimal encoded validation code; may not be fully encoded (it may have an odd number of bytes)
	hexCode []byte
	// how many bytes of the hexCode are used for validating the key
	length int
}

type Validator interface {
	// computes key validation code
	Compute() (code string)
	// validates a key against a received key validation code
	Validate(code string) (isValid bool)
	String() string
}

type KeyValidator struct {
	// binary key to be validated
	key  []byte
	hash crypto.Hash
	// can be either pre-allocated or allocated on-the-fly when the checksum is computed
	mac hash.Hash
	// how much of the key validation code is used for validation
	length    int
	withNonce bool
	nonce     uint32
}

func GenerateKeyFromPassphrase(passphrase string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte(Salt), IterationCount, EncryptionKeyLen, sha1.New)
}

func GenerateKeyFromPassphraseAndCopy(passphrase string, key []byte) {
	tmpKey := GenerateKeyFromPassphrase(passphrase)
	subtle.ConstantTimeCopy(1, key[:], tmpKey[:])
	return
}

// getNonce parses the string representation of the key validation code and returns the contained nonce if found; if
// there is no nonce in the code it sets the 'hasNonce' flag to false
// 'code' format: hexadecimal_hmac[:base10_32bit_nonce]
func getNonce(code string) (nonce uint32, hasNonce bool) {
	hasNonce = false
	if checksumLen := strings.IndexByte(code, Separator); checksumLen == -1 {
		return
	} else if tmp, err := strconv.Atoi(code[checksumLen+1:]); err != nil {
		return
	} else {
		nonce = uint32(tmp)
	}
	hasNonce = true
	return
}

// randomUint32 generates a random unsigned integer
func randomUint32() (n uint32, err error) {
	var buf [4]byte
	if _, err = rand.Read(buf[:]); err != nil {
		n = 0
		return
	}
	n = 0
	for i, b := range buf {
		n = n | uint32(b)<<(8*uint32(i))
	}
	return
}

func registerHashFunctions() {
	crypto.RegisterHash(crypto.SHA256, sha256.New)
}

// NewKeyValidator returns a key validator which be used either globally or in its own thread.
// length indicates how much of the key checksum hexadecimal encoding is used for validation (0 < length <= 2*cryptoHash.Size())
// flags: nonce | pre-allocated validator
func NewKeyValidator(cryptoHash crypto.Hash, key []byte, length int, flags ...bool) (Validator, error) {
	var (
		nonce     uint32    = 0
		nonceFlag bool      = false
		mac       hash.Hash = nil
		err       error     = nil
	)
	registerHashFunctions()
	switch len(flags) {
	case 0:
		// nonce not used, on-the-fly validator
		nonceFlag = false
		mac = nil
	case 1:
		// nonce flag specified, on-the-fly validator
		nonceFlag = flags[0]
		mac = nil
	case 2:
		// nonce flag specified, pre-allocated validator flag specified
		fallthrough
	default:
		nonceFlag = flags[0]
		if flags[1] {
			// pre-allocated validator
			mac = hmac.New(cryptoHash.New, key)
		} else {
			// on-the-fly validator
			mac = nil
		}
	}
	if nonceFlag {
		// generate a random nonce
		if nonce, err = randomUint32(); err != nil {
			return nil, err
		}
	}
	if length < ChecksumMinLength {
		length = ChecksumMinLength
	} else if length > 2*cryptoHash.Size() {
		length = 2 * cryptoHash.Size()
	}
	return &KeyValidator{key, cryptoHash, mac, length, nonceFlag, nonce}, nil
}

// computeWithNonce computes the validation code using an optional nonce specified as parameter
func (vtor *KeyValidator) computeWithNonce(nonce ...uint32) (kv KeyValidation) {
	mac := vtor.mac
	if mac == nil {
		// allocate an "ephemeral" hmac object
		mac = hmac.New(vtor.hash.New, vtor.key)
	}
	mac.Reset()
	mac.Write(vtor.key)
	if len(nonce) > 0 {
		var b [4]byte
		kv.nonce = nonce[0]
		kv.withNonce = true
		// use the nonce in big endian format
		binary.BigEndian.PutUint32(b[0:], kv.nonce)
		// append it to the buffer over which the hash is computed
		mac.Write(b[:])
	}
	kv.code = mac.Sum(nil)[:]
	kv.length = vtor.length
	return
}

// compute computes the key validation
func (vtor *KeyValidator) compute() (kv KeyValidation) {
	if vtor.withNonce {
		return vtor.computeWithNonce(atomic.AddUint32(&vtor.nonce, 1))
	}
	return vtor.computeWithNonce()
}

// Compute computes the key validation and returns its string representation
func (vtor *KeyValidator) Compute() (code string) {
	kv := vtor.compute()
	return kv.String()
}

func (vtor *KeyValidator) String() string {
	if vtor.withNonce {
		return fmt.Sprintf("%v:%s:%d", vtor.key, vtor.hash, vtor.nonce)
	}
	return fmt.Sprintf("%v:%s", vtor.key, vtor.hash)
}

func (vtor *KeyValidator) Validate(code string) (isValid bool) {
	var kv KeyValidation
	if n, hasNonce := getNonce(code); hasNonce {
		kv = vtor.computeWithNonce(n)
	} else {
		kv = vtor.computeWithNonce()
	}
	isValid = (subtle.ConstantTimeCompare([]byte(code), []byte(kv.String())) == 1)
	return
}

func (kv KeyValidation) initFromCode(code string) (err error) {
	var checksumLen int = 0
	err = nil
	kv.code = make([]byte, ChecksumMaxSize)
	if checksumLen = strings.IndexByte(code, Separator); checksumLen == -1 {
		// without nonce
		kv.withNonce = false
		checksumLen = len(code)
	} else {
		kv.withNonce = true
	}
	// store the bytes of the hexadecimal encoding
	kv.hexCode = []byte(code[:checksumLen])
	if len(code[:checksumLen])%2 == 0 {
		// checksum has even length; try to decode as hexadecimal
		if kv.code, err = hex.DecodeString(code[:checksumLen]); err != nil {
			err = ErrParseValidationCode
			return err
		}
	}
	if kv.withNonce {
		if tmp, err := strconv.Atoi(code[checksumLen+1:]); err != nil {
			err = ErrParseValidationCode
			return err
		} else {
			kv.nonce = uint32(tmp)
		}
	}
	return
}

// Bytes returns the byte array representation of a key validation code
// Format: hexadecimal_hmac[:base10_32bit_nonce]
func (kv KeyValidation) Bytes() []byte {
	dst := make([]byte, hex.EncodedLen(len(kv.code))+1+MaxUintLen)
	n := hex.Encode(dst, kv.code)
	kv.hexCode = dst[0:n]
	length := kv.length
	if length > n {
		length = n
	}
	if kv.withNonce {
		dst[length] = ':'
		dst = strconv.AppendUint(dst[0:length+1], uint64(kv.nonce), 10)
	}
	return dst
}

// String returns the string representation of a key validation code
// Format: hexadecimal_hmac[:base10_32bit_nonce]
func (kv KeyValidation) String() string {
	return string(kv.Bytes())
}
