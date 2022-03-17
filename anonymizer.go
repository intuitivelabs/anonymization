package anonymization

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
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

func GenerateAllKeysWithPassphrase(passphrase string) {
	var masterKey [EncryptionKeyLen]byte
	// generate the master key from passphrase
	GenerateKeyFromPassphraseAndCopy(passphrase, len(masterKey), masterKey[:])
	for i := FirstKey; i < LastKey; i++ {
		Keys[i] = *NewKeyingMaterial(masterKey[:], &Salts[i])
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
	return NewAnonymizerWithKey(challenge, key[:])
}

func NewAnonymizerWithHexKey(challenge, key string) (*Anonymizer, error) {
	var encKey [EncryptionKeyLen]byte

	// copy the configured key into the one used during realtime processing
	if decoded, err := hex.DecodeString(key); err != nil {
		return nil, err
	} else {
		subtle.ConstantTimeCopy(1, encKey[:], decoded)
	}
	return NewAnonymizerWithKey(challenge, encKey[:])
}

func NewAnonymizerWithKey(challenge string, key []byte) (*Anonymizer, error) {
	var authKey [AuthenticationKeyLen]byte
	var anonymizer Anonymizer = Anonymizer{}

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

func NewAnonymizer(challenge string) (*Anonymizer, error) {
	var anonymizer Anonymizer = Anonymizer{}

	// validation code is the first 5 bytes of HMAC(SHA256) of random nonce; each thread needs its own validator!
	if validator, err := NewKeyValidator(crypto.SHA256, 5 /*length*/, challenge, NonceNone, false /*withNonce*/); err != nil {
		return nil, err
	} else {
		anonymizer.Validator = validator
	}

	anonymizer.Ipcipher = &Ipcipher{}
	// initialize the IP Prefix-preserving anonymization
	anonymizer.Pan = NewPanIPv4()

	// initialize the URI CBC based encryption
	anonymizer.Uri = NewAnonymURI()

	// initialize the Call-ID CBC based encryption
	anonymizer.CallId = NewAnonymCallId()

	return &anonymizer, nil
}

func (a *Anonymizer) UpdateKeys(keys []KeyingMaterial) (*Anonymizer, error) {
	for i, key := range keys {
		switch i {
		case ValidationKey:
			a.Validator.WithKey(key.Auth[:])
		case IpcipherKey:
			if _, err := a.Ipcipher.WithKey(key.Master[:]); err != nil {
				return nil, err
			}
		case PanKey:
			a.Pan.WithKeyingMaterial(&key)
		case UriUsernameKey:
			// initialize both username and host keys
			a.Uri.WithKeyingMaterial(keys[i : i+2])
		case UriHostKey:
		case CallIdKey:
			a.CallId.WithKeyingMaterial(&key)
		}
	}
	return a, nil
}
