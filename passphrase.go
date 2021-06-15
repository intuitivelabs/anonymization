// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// see ipcipher specification here:
// https://powerdns.org/ipcipher/ipcipher.md.html

package anonymization

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltIpcipher = "ipcipheripcipher"
	SaltUriIV    = "1190e68008426899bc48fe7719c2ffb7"
	SaltUriUK    = "e3ab68497b69d87ddf6b5d97e24b6bb1"
	SaltUriHK    = "23c1be46c4af62a6c6be8c860e2f13bc"
	// key lengths are in bytes
	EncryptionKeyLen     = 16
	AuthenticationKeyLen = 32
	IterationCount       = 50000
	// checksum size is in bytes
	ChecksumMaxSize   = 64
	ChecksumMinLength = 5
	// maximum length of an base 10 32 bit integer in ASCII characters
	MaxUintLen = 10
)

func GenerateKeyWithSalt(salt string, bytes []byte, keyLen int) ([]byte, error) {
	decoded, err := hex.DecodeString(salt)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(bytes, decoded, IterationCount, keyLen, sha1.New), nil
}

func GenerateKeyWithSaltAndCopy(salt string, bytes []byte, keyLen int, key []byte) error {
	tmpKey, err := GenerateKeyWithSalt(salt, bytes, keyLen)
	if err != nil {
		return err
	}
	subtle.ConstantTimeCopy(1, key[:], tmpKey[:])
	return nil
}

// generate IV for CBC
func GenerateIV(bytes []byte, ivLen int, iv []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltUriIV, bytes, ivLen, iv)
}

// generate key for URI's user part
func GenerateURIUserKey(bytes []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltUriUK, bytes, keyLen, key)
}

// generate key for URI's host part
func GenerateURIHostKey(bytes []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltUriHK, bytes, keyLen, key)
}

func GenerateKeyFromBytes(bytes []byte, keyLen int) []byte {
	return pbkdf2.Key(bytes, []byte(SaltIpcipher), IterationCount, keyLen, sha1.New)
}

func GenerateKeyFromBytesAndCopy(bytes []byte, keyLen int, key []byte) {
	tmpKey := GenerateKeyFromBytes(bytes, keyLen)
	subtle.ConstantTimeCopy(1, key[:], tmpKey[:])
	return
}

func GenerateKeyFromPassphrase(passphrase string, keyLen int) []byte {
	return GenerateKeyFromBytes([]byte(passphrase), keyLen)
}

func GenerateKeyFromPassphraseAndCopy(passphrase string, keyLen int, key []byte) {
	GenerateKeyFromBytesAndCopy([]byte(passphrase), keyLen, key)
	return
}
