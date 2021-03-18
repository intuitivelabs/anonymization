// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// see ipcipher specification here:
// https://powerdns.org/ipcipher/ipcipher.md.html

package anonymization

import (
	"bufio"
	"crypto/sha1"
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"os"
)

const (
	Salt = "ipcipheripcipher"
	// key lengths are in bytes
	EncryptionKeyLen     = 16
	AuthenticationKeyLen = 32
	IterationCount       = 50000
	// checksum size is in bytes
	ChecksumMaxSize   = 64
	ChecksumMinLength = 5
	// maximum length of an base 10 32 bit integer in ASCII characters
	MaxUintLen = 10
	debugOn    = false
)

func debug(format string, args ...interface{}) {
	stdout := bufio.NewWriter(os.Stdout)
	defer stdout.Flush()
	if debugOn {
		fmt.Fprintf(stdout, format, args...)
	}
}

func GenerateKeyFromBytes(bytes []byte, keyLen int) []byte {
	return pbkdf2.Key(bytes, []byte(Salt), IterationCount, keyLen, sha1.New)
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
