// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package anonymization

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
)

// This module should be used for generating cryptographic keying material:
//  - encryption keys
//  - authentication keys (used for password validation)
//  - initialization vectors
//
// Keying material derivation algorithm.
// 1. Input: a passphrase.
//   1.1. generate the master key from passphrase using `PBKDF2` key derivation function with HMAC-SHA1 and `IpcipherSalt` salt;
// 2. Input: a master key
//   2.1. (optional) if the master key is encoded using hex format decoded it first to get the key in binary format;
//   2.2. generate the authentication key from the master key using `PBKDF2` key derivation function with HMAC-SHA1 and 'IpcipherSalt';
//   2.3. generate the PAN encryption key and IV from the master key using `PBKDF2` key derivation function with HMAC-SHA1 and `PanSalt` salt;
//   2.4. generate the URI Username encryption key and IV from the master key using `PBKDF2` key derivation function with HMAC-SHA1 and `UriUsernameSalt` salt;
//   2.5. generate the URI Host encryption key and IV from the master key using `PBKDF2` key derivation function with HMAC-SHA1 and `UriHostSalt` salt;
//   2.6. generate the Call-ID encryption key and IV from the master key using `PBKDF2` key derivation function with HMAC-SHA1 and `CallIdSalt` salt;

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
	_, PanIPv4Key
	_, UriUsernameKey
	_, UriHostKey
	_, CallIdKey
	LastKey, _ // marker, not used
)

// keying material used for crypto algorithms: authentication key, encryption key, IV
type KeyingMaterial struct {
	Master [EncryptionKeyLen]byte
	Auth   [AuthenticationKeyLen]byte
	Enc    [EncryptionKeyLen]byte
	IV     [EncryptionKeyLen]byte
}

// Keys stores global keying material used for encryption and authentication algorithms.
// Use GenerateAllKeys to derive all necessary keys.
var Keys [LastKey]KeyingMaterial

// GetKeys returns the global array storing all the keying material (encryption, authentication keys and IVs)
func GetKeys() []KeyingMaterial {
	return Keys[:]
}

// NewKeyingMaterial generates new keys using `masterKey`, `salt` and PBKDF2 with HMAC-SHA1
// masterKey is copied in the returned KeyingMaterial.
func NewKeyingMaterial(masterKey []byte, salt *Salt) *KeyingMaterial {
	km := KeyingMaterial{}
	df := DbgOn()
	defer DbgRestore(df)
	km.SetMasterKey(masterKey)
	km.Generate(salt)
	return &km
}

// SetMasterKey copies the key into km.Master. km.Master is going to be used as a master key from which all the other keys are derived.
func (km *KeyingMaterial) SetMasterKey(key []byte) {
	subtle.ConstantTimeCopy(1, km.Master[:], key[:])
}

// Generate generates the keying material (authentication, encryption key and initialization vector) based
// on salt and the internally stored master key.
func (km *KeyingMaterial) Generate(salt *Salt) *KeyingMaterial {
	df := DbgOn()
	defer DbgRestore(df)
	// generate IV
	if err := GenerateKeyWithSaltAndCopy(salt.IV, km.Master[:], EncryptionKeyLen, km.IV[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("IV: %v", km.IV[:])
	// generate encryption key
	if err := GenerateKeyWithSaltAndCopy(salt.Key, km.Master[:], EncryptionKeyLen, km.Enc[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("encryption key: %v", km.Enc[:])
	// generate authentication key
	GenerateKeyFromBytesAndCopy(km.Master[:], AuthenticationKeyLen, km.Auth[:])
	_ = WithDebug && Dbg("authentication key: %v", km.Auth[:])
	return km
}

// GenerateAllKeys derives all the keying material using the `masterKey`. Generated keys, IVs are stored in the global arrays `Keys`.
// Use this API when the `masterKey` has a raw binary format.
func GenerateAllKeys(masterKey []byte) {
	for i := FirstKey; i < LastKey; i++ {
		Keys[i] = *NewKeyingMaterial(masterKey, &Salts[i])
	}
}

// GenerateAllKeysWithHexMasterKey derives all the keying material using the `masterKey`. Generated keys, IVs are stored in the global arrays `Keys`.
// Use this API when the `masterKey` has a hex string format. If the `masterKey` cannot be decoded from the hex encoding, the function returns an error.
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

// GenerateAllKeysWithPassphrase derives all the keying material from a passphrase (i.e. a password).
// Generated keys, IVs are stored in the global arrays `Keys`.
func GenerateAllKeysWithPassphrase(passphrase string) {
	var masterKey [EncryptionKeyLen]byte
	// generate the master key from passphrase
	GenerateKeyFromPassphraseAndCopy(passphrase, len(masterKey), masterKey[:])
	for i := FirstKey; i < LastKey; i++ {
		Keys[i] = *NewKeyingMaterial(masterKey[:], &Salts[i])
	}
}

// GenerateKeyWithSalt derives a key using:
// - salt which is a hex encoded string
// - bytes which is the input "password"
// The key is derived using PBKDF2 with HMAC-SHA1, iteration count being the constant 'IterationCount'
// and returned as a byte slice.
func GenerateKeyWithSalt(salt string, bytes []byte, keyLen int) ([]byte, error) {
	decoded, err := hex.DecodeString(salt)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(bytes, decoded, IterationCount, keyLen, sha1.New), nil
}

// GenerateKeyWithSaltAndCopy derives a key using:
// - salt which is a hex encoded string
// - bytes which is the input "password"
// The key is derived using PBKDF2 with HMAC-SHA1, iteration count being the constant 'IterationCount'
// and copied in the provided byte slice.
func GenerateKeyWithSaltAndCopy(salt string, bytes []byte, keyLen int, key []byte) error {
	tmpKey, err := GenerateKeyWithSalt(salt, bytes, keyLen)
	if err != nil {
		return err
	}
	subtle.ConstantTimeCopy(1, key[:], tmpKey[:])
	return nil
}

// GenerateKeyFromBytes derives a key using:
// - binary constant `SaltIpcipher` salt
// - bytes which is the input "password"
// The key is derived using PBKDF2 with HMAC-SHA1, iteration count being the constant 'IterationCount'
// and returned as a byte slice.
func GenerateKeyFromBytes(bytes []byte, keyLen int) []byte {
	return pbkdf2.Key(bytes, []byte(SaltIpcipher), IterationCount, keyLen, sha1.New)
}

// GenerateKeyFromBytesAndCopy derives a key using:
// - binary constant `SaltIpcipher` salt
// - bytes which is the input "password"
// The key is derived using PBKDF2 with HMAC-SHA1, iteration count being the constant 'IterationCount'
// and copied in the provided byte slice.
func GenerateKeyFromBytesAndCopy(bytes []byte, keyLen int, key []byte) {
	tmpKey := GenerateKeyFromBytes(bytes, keyLen)
	subtle.ConstantTimeCopy(1, key[:], tmpKey[:])
	return
}

// GenerateKeyFromPassphrase derives a key using:
// - binary constant `SaltIpcipher` salt
// - passphrase which is the input "password"
// The key is derived using PBKDF2 with HMAC-SHA1, iteration count being the constant 'IterationCount'
// and returned as a byte slice.
func GenerateKeyFromPassphrase(passphrase string, keyLen int) []byte {
	return GenerateKeyFromBytes([]byte(passphrase), keyLen)
}

// GenerateKeyFromPassphraseAndCopy derives a key using:
// - binary constant `SaltIpcipher` salt
// - bytes which is the input "password"
// The key is derived using PBKDF2 with HMAC-SHA1, iteration count being the constant 'IterationCount'
// and copied in the provided byte slice.
func GenerateKeyFromPassphraseAndCopy(passphrase string, keyLen int, key []byte) {
	GenerateKeyFromBytesAndCopy([]byte(passphrase), keyLen, key)
	return
}
