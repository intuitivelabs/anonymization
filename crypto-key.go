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
	// salt used for generating IP encryption keys
	SaltIpcipher = "ipcipheripcipher"
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

type Salt struct {
	// salt used for generating the key
	Key string
	// salt used for generating the initialization vector
	IV string
}

var Salts = [...]Salt{
	IpcipherSalt,
	IpcipherSalt,
	PanSalt,
	UriUsernameSalt,
	UriHostSalt,
	CallIdSalt,
}

// indices for Keys
const (
	FirstKey, ValidationKey = iota, iota
	_, IpcipherKey
	_, PanKey
	_, UriUsernameKey
	_, UriHostKey
	_, CallIdKey
	LastKey, _ // marker, not used
)

// keying material used for crypto algorithms: authentican key, encryption key, IV
type KeyingMaterial struct {
	Master [EncryptionKeyLen]byte
	Auth   [AuthenticationKeyLen]byte
	Enc    [EncryptionKeyLen]byte
	IV     [EncryptionKeyLen]byte
}

var Keys [LastKey]KeyingMaterial

func GetKeys() []KeyingMaterial {
	return Keys[:]
}

func NewKeyingMaterial(masterKey []byte, salt *Salt) *KeyingMaterial {
	km := KeyingMaterial{}
	df := DbgOn()
	defer DbgRestore(df)
	km.generate(masterKey, salt)
	return &km
}

// generate the keying material (authentication, encryption key and initialization vector) based on masterKey and salt.
func (km *KeyingMaterial) generate(masterKey []byte, salt *Salt) *KeyingMaterial {
	df := DbgOn()
	defer DbgRestore(df)
	subtle.ConstantTimeCopy(1, km.Master[:], masterKey[:])
	// generate IV
	if err := GenerateKeyWithSaltAndCopy(salt.IV, masterKey[:], EncryptionKeyLen, km.IV[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("IV: %v", km.IV[:])
	// generate encryption key
	if err := GenerateKeyWithSaltAndCopy(salt.Key, masterKey[:], EncryptionKeyLen, km.Enc[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("encryption key: %v", km.Enc[:])
	// generate authentication key
	GenerateKeyFromBytesAndCopy(masterKey[:], AuthenticationKeyLen, km.Auth[:])
	_ = WithDebug && Dbg("authentication key: %v", km.Auth[:])
	return km
}

func GenerateAllKeys(masterKey []byte) {
	for i := FirstKey; i < LastKey; i++ {
		Keys[i] = *NewKeyingMaterial(masterKey, &Salts[i])
	}
}

func GenerateAllKeysWithHexMasterKey(masterKey string) error {
	decoded, err := hex.DecodeString(masterKey)
	if err != nil {
		return err
	}
	for i := FirstKey; i < LastKey; i++ {
		Keys[i] = *NewKeyingMaterial(decoded, &Salts[i])
	}
	return nil
}

func GenerateAllKeysWithPassphrase(passphrase string) {
	var masterKey [EncryptionKeyLen]byte
	// generate the master key from passphrase
	GenerateKeyFromPassphraseAndCopy(passphrase, len(masterKey), masterKey[:])
	for i := FirstKey; i < LastKey; i++ {
		Keys[i] = *NewKeyingMaterial(masterKey[:], &Salts[i])
	}
}

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
