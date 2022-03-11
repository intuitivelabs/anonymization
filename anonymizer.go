package anonymization

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
	"errors"
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

// keying material used for pan crypto algorithm: encryption key, IV
type KeyingMaterial struct {
	Key [BlockSize]byte
	IV  [BlockSize]byte
}

var Keys [LastKey]KeyingMaterial

func NewKeyingMaterial(masterKey []byte, salt *Salt) *KeyingMaterial {
	km := KeyingMaterial{}
	df := DbgOn()
	defer DbgRestore(df)
	km.generate(masterKey, salt)
	return &km
}

// generate the keying material (encryption key and initialization vector) based on masterKey and salt.
func (km *KeyingMaterial) generate(masterKey []byte, salt *Salt) *KeyingMaterial {
	df := DbgOn()
	defer DbgRestore(df)
	// generate IV
	if err := GenerateKeyWithSaltAndCopy(salt.IV, masterKey[:], EncryptionKeyLen, km.IV[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("IV: %v", km.IV[:])
	// generate key
	if err := GenerateKeyWithSaltAndCopy(salt.Key, masterKey[:], EncryptionKeyLen, km.Key[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("Key: %v", km.Key[:])
	return km
}

func GenerateAllKeys(masterKey []byte) {
	for i := FirstKey; i < LastKey; i++ {
		Keys[i] = *NewKeyingMaterial(masterKey, &Salts[i])
	}
}

type Anonymizer struct {
	Validator Validator
	Ipcipher  *Ipcipher
	Pan       *PanIPv4
	Uri       *AnonymURI
	CallId    *AnonymPField
}

func NewAnonymizerWithPassphrase(challenge, passphrase string) (*Anonymizer, error) {
	var key [EncryptionKeyLen]byte
	GenerateKeyFromPassphraseAndCopy(passphrase,
		EncryptionKeyLen, key[:])
	return NewAnonymizer(challenge, key[:])
}

func NewAnonymizerWithKey(challenge, key string) (*Anonymizer, error) {
	var encKey [EncryptionKeyLen]byte

	// copy the configured key into the one used during realtime processing
	if decoded, err := hex.DecodeString(key); err != nil {
		return nil, err
	} else {
		subtle.ConstantTimeCopy(1, encKey[:], decoded)
	}
	return NewAnonymizer(challenge, encKey[:])
}

func NewAnonymizer(challenge string, key []byte) (*Anonymizer, error) {
	var authKey [AuthenticationKeyLen]byte
	var anonymizer Anonymizer = Anonymizer{}

	if len(challenge) == 0 {
		return nil, errors.New("initEncryption: challenge for" +
			" password validation is missing")
	}

	// generate authentication (HMAC) key from encryption key
	GenerateKeyFromBytesAndCopy(key[:], AuthenticationKeyLen, authKey[:])
	// validation code is the first 5 bytes of HMAC(SHA256) of random nonce; each thread needs its own validator!
	if validator, err := NewKeyValidator(crypto.SHA256, 5 /*length*/, challenge, NonceNone, false /*withNonce*/); err != nil {
		return nil, err
	} else {
		anonymizer.Validator = validator
	}

	if ipcipher, err := NewCipher(key[:]); err != nil {
		return nil, err
	} else {
		anonymizer.Ipcipher = ipcipher.(*Ipcipher)
	}

	// initialize the IP Prefix-preserving anonymization
	anonymizer.Pan = NewPanIPv4()

	// initialize the URI CBC based encryption
	anonymizer.Uri = NewAnonymURI()

	// initialize the Call-ID CBC based encryption
	anonymizer.CallId = NewAnonymCallId()

	return &anonymizer, nil
}

func (a *Anonymizer) UpdateKeys(challenge string, keys [LastKey]KeyingMaterial) *Anonymizer {
	for i, key := range keys {
		switch i {
		case ValidationKey:
			a.Validator.WithKey(key.Key[:])
		case IpcipherKey:
		case PanKey:
			a.Pan.WithKeyingMaterial(&key)
		case UriUsernameKey:
			// initialize both username and host keys
			a.Uri.WithKeyingMaterial(keys[i : i+2])
		case UriHostKey:
		case CallIdKey:
		}
	}
	return a
}
