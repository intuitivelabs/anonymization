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
	"golang.org/x/crypto/pbkdf2"
)

const (
	Salt             = "ipcipheripcipher"
	EncryptionKeyLen = 16
	IterationCount   = 50000
)

func GenerateKeyFromPassphrase(passphrase string) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte(Salt), IterationCount, EncryptionKeyLen, sha1.New)
}

func GenerateKeyFromPassphraseAndCopy(passphrase string, key []byte) {
	tmpKey := GenerateKeyFromPassphrase(passphrase)
	subtle.ConstantTimeCopy(1, key[:], tmpKey[:])
	return
}
