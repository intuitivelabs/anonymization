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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// errors
var (
	ErrParseValidationCode = errors.New("Validation code parse error")
)

var (
	// separator used in key validation code
	Separator string = ":"
)

// KeyValidation is used for validating an encryption key
type KeyValidation struct {
	// is nonce used?
	withNonce bool
	// a random number
	nonce uint32
	// a random, possible constant string
	challenge []byte
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
	// returns the validator respresentation as a string
	String() string
	// returns the last validation code which was computed
	Code() string
	// recomputes the authentication HMAC using the specified key
	WithKey(key []byte) Validator
}

type KeyValidator struct {
	hash crypto.Hash
	// is mac preallocated and computed?
	withMac bool
	// can be either pre-allocated or allocated on-the-fly when the HMAC is computed
	mac hash.Hash
	// binary key to be validated
	key []byte
	// how much of the key validation code is used for validation
	length int
	// challenge
	challenge []byte
	// is nonce used?
	withNonce bool
	nonceType NonceType
	noncer    Noncer
	// last computed key validation code
	kv   KeyValidation
	code string
}

func NewKeyValidator(cryptoHash crypto.Hash, length int, challenge string, nonceType NonceType, flags ...bool) (Validator, error) {
	var (
		withNonce bool   = false
		withMac   bool   = false
		noncer    Noncer = nil
		err       error  = nil
	)
	registerHashFunctions()
	switch len(flags) {
	case 0:
		// nonce not used, on-the-fly validator
		withNonce = false
	case 1:
		// nonce flag specified, on-the-fly validator
		withNonce = flags[0]
	case 2:
		// nonce flag specified, pre-allocated validator flag specified
		fallthrough
	default:
		withNonce = flags[0]
		withMac = flags[1]
	}
	if length < ChecksumMinLength {
		length = ChecksumMinLength
	} else if length > 2*cryptoHash.Size() {
		length = 2 * cryptoHash.Size()
	}
	if withNonce {
		if noncer, err = NewNoncer(nonceType); err != nil {
			return nil, err
		}
	}
	vtor := &KeyValidator{
		hash:      cryptoHash,
		length:    length,
		challenge: []byte(challenge),
		withNonce: withNonce,
		withMac:   withMac,
		nonceType: nonceType,
		noncer:    noncer,
	}
	_ = WithDebug && Dbg("challenge: %v", vtor.challenge)
	return vtor, nil
}

// NewKeyValidatorWithKey returns a key validator which be used either globally or in its own thread.
// length indicates how much of the key checksum hexadecimal encoding is used for validation (0 < length <= 2*cryptoHash.Size())
// flags: nonce | pre-allocated validator
func NewKeyValidatorWithKey(cryptoHash crypto.Hash, key []byte, length int, challenge string, nonceType NonceType, flags ...bool) (Validator, error) {
	vtor, err := NewKeyValidator(cryptoHash, length, challenge, nonceType, flags...)
	if err != nil {
		return vtor, err
	}
	vtor.WithKey(key)
	// compute the "initial" value of the key validation; it is reusable if the nonce is not used
	vtor.Compute()
	return vtor, nil
}

// NewKeyValidatorWithPassphrase returns a new key validator for a key generated from the passphrase.
// Validation checksum is generated using HMAC(SHA256) with the key over the challenge
func NewKeyValidatorWithPassphrase(passphrase string, length int, challenge string) (Validator, error) {
	var key [AuthenticationKeyLen]byte
	GenerateKeyFromPassphraseAndCopy(passphrase, AuthenticationKeyLen, key[:])
	return NewKeyValidatorWithKey(crypto.SHA256, key[:], length, challenge, NonceNone, false, true)
}

// WithKey initializes the hashed message authentication code using the 'key' parameter
func (vtor *KeyValidator) WithKey(key []byte) Validator {
	vtor.mac = hmac.New(vtor.hash.New, key)
	vtor.Compute()
	return vtor
}

// computeWithChallengeAndNonce computes the validation code using up to two parameters: a challenge and an optional nonce.
func (vtor *KeyValidator) computeWithChallengeAndNonce(challenge []byte, nonce ...uint32) (kv KeyValidation) {
	mac := vtor.mac
	if mac == nil {
		// allocate an "ephemeral" hmac object
		mac = hmac.New(vtor.hash.New, vtor.key)
	}
	mac.Reset()
	kv.challenge = challenge
	mac.Write(kv.challenge)
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
	if vtor.withNonce && vtor.noncer != nil {
		nonce, _ := vtor.noncer.NextNonce()
		return vtor.computeWithChallengeAndNonce(vtor.challenge, nonce)
	}
	return vtor.computeWithChallengeAndNonce(vtor.challenge)
}

// Compute computes the local key validation code and returns its string representation.
func (vtor *KeyValidator) Compute() (code string) {
	vtor.kv = vtor.compute()
	vtor.code = vtor.kv.String()
	return vtor.code
}

// String returns the string representation of the KeyValidator
func (vtor *KeyValidator) String() string {
	if vtor.withNonce {
		return fmt.Sprintf("%v:%s:%s:%s", vtor.key, vtor.hash, vtor.challenge, vtor.noncer.String())
	}
	return fmt.Sprintf("%v:%s:%s", vtor.key, vtor.hash, vtor.challenge)
}

// Validate the remote key validation code by:
//  1. parsing it (expected format is HMAC:challenge)
//  2. computing the local HMAC over the code's challenge
//  3. compare the remote HMAC (code's HMAC) with the local one
// The code parameter is valid when the two HMACs are equal. In this case the function returns true; otherwise it returns false.
func (vtor *KeyValidator) Validate(code string) (isValid bool) {
	var kvLocal, kvRemote KeyValidation
	if err := (&kvRemote).parseCode(code); err != nil {
		return false
	}
	if kvRemote.withNonce {
		_ = WithDebug && Dbg("compute with nonce:%d", kvRemote.nonce)
		kvLocal = vtor.computeWithChallengeAndNonce(kvRemote.challenge, kvRemote.nonce)
	} else {
		kvLocal = vtor.computeWithChallengeAndNonce(kvRemote.challenge)
	}
	_ = WithDebug && Dbg("remote: \"%s\" local: \"%s\"", code, kvLocal.String())
	isValid = (subtle.ConstantTimeCompare([]byte(code), []byte(kvLocal.String())) == 1)
	return
}

func (vtor *KeyValidator) Code() string {
	return vtor.code
}

// Bytes returns the byte array representation of a key validation code
// Format: hexadecimal_hmac:challenge:[:base10_32bit_nonce]
func (kv *KeyValidation) Bytes() []byte {
	dstLen := hex.EncodedLen(len(kv.code)) + 1 + len(kv.challenge) + 1 + MaxUintLen
	_ = WithDebug && Dbg("dstLen: %d", dstLen)
	dst := make([]byte, dstLen)
	// hexadecimal encoding of the mac
	n := hex.Encode(dst, kv.code)
	kv.hexCode = dst[0:n]
	// store in the representation only the amount specified in kv.length
	length := kv.length
	if length > n {
		length = n
	}
	dst = append(dst[0:length], ':')
	length++
	dst = append(dst[0:length], kv.challenge...)
	length += len(kv.challenge)
	_ = WithDebug && Dbg("length: %d", length)
	if kv.withNonce {
		dst = append(dst[0:length], ':')
		length++
		dst = strconv.AppendUint(dst[0:length], uint64(kv.nonce), 10)
	}
	return dst
}

// String returns the string representation of a key validation code
// Format: hexadecimal_hmac:challenge:[:base10_32bit_nonce]
func (kv KeyValidation) String() string {
	return string((&kv).Bytes())
}

func registerHashFunctions() {
	crypto.RegisterHash(crypto.SHA256, sha256.New)
}

// parseCode parses the string representation of the key validation code and returns the contained checksum (hmac), challenge, nonce.
// 'code' format: hexadecimal_hmac:challenge[:base10_32bit_nonce]
func (kv *KeyValidation) parseCode(code string) (err error) {
	err = nil
	s := strings.Split(code, Separator)
	_ = WithDebug && Dbg("len:%d %q", len(s), s)
	kv.withNonce = false
	switch len(s) {
	case 2:
		kv.hexCode = []byte(s[0])
		kv.challenge = []byte(s[1])
	case 3:
		kv.hexCode = []byte(s[0])
		kv.challenge = []byte(s[1])
		kv.withNonce = true
		if tmp, err := strconv.Atoi(s[2]); err != nil {
			err = ErrParseValidationCode
			return err
		} else {
			kv.nonce = uint32(tmp)
		}
	default:
		err = ErrParseValidationCode
	}
	return
}
