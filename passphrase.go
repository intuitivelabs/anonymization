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
	// key length is in bytes
	EncryptionKeyLen = 16
	IterationCount   = 50000
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

func GenerateKeyFromPassphrase(passphrase string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte(Salt), IterationCount, EncryptionKeyLen, sha1.New)
}

func GenerateKeyFromPassphraseAndCopy(passphrase string, key []byte) {
	tmpKey := GenerateKeyFromPassphrase(passphrase)
	subtle.ConstantTimeCopy(1, key[:], tmpKey[:])
	return
}
