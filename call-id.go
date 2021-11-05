package anonymization

import (
	"crypto/aes"
)

const (
	// maximum size allowed for an anonymized Call-Id
	callIdMaxBufSize int = 4096
	// salt used for generating Call-ID encryption keys
	SaltCallIdIV  = "ea3f055967db474b9f3bf4afc9c2c712"
	SaltCallIdKey = "26ef0bb4d6e45cb90a6bb2a121b4a683"
)

type CallIdKeys struct {
	// initialization vector
	IV [EncryptionKeyLen]byte
	// encryption key used
	Key [EncryptionKeyLen]byte
}

var (
	callIdCBC  = BlockModeCipher{}
	callIdKeys = CallIdKeys{}
)

func GenerateCallIdIV(masterKey []byte, ivLen int, iv []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltCallIdIV, masterKey, ivLen, iv)
}

func GenerateCallIdKey(masterKey []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltCallIdKey, masterKey, keyLen, key)
}

func GetCallIdKeys() *CallIdKeys {
	return &callIdKeys
}

func InitCallIdKeys(iv []byte, k []byte) {
	copy(GetCallIdKeys().IV[:], iv)
	copy(GetCallIdKeys().Key[:], k)
}

func InitCallIdKeysFromMasterKey(masterKey []byte) {
	df := DbgOn()
	defer DbgRestore(df)
	// generate Call-ID IV for CBC
	GenerateCallIdIV(masterKey[:], EncryptionKeyLen, GetCallIdKeys().IV[:])
	Dbg("Call-ID IV: %v", GetCallIdKeys().IV)
	// generate key for Call-ID
	GenerateCallIdKey(masterKey[:], EncryptionKeyLen, GetCallIdKeys().Key[:])
	Dbg("Call-ID Key: %v", GetCallIdKeys().Key)
}

func NewCallIdCBC(keys *CallIdKeys) *BlockModeCipher {
	if block, err := aes.NewCipher(keys.Key[:]); err != nil {
		panic(err)
	} else {
		callIdCBC.Init(keys.IV[:], keys.Key[:], block)
	}
	return &callIdCBC
}

func CallIdCBC() *BlockModeCipher {
	return &callIdCBC
}
