package anonymization

import (
	"crypto"
	"encoding/hex"
)

func NewAnonymizationBuf(l int) []byte {
	if l < 32 {
		l = 32
	}
	return make([]byte, 3*l)
}

type Anonymizer struct {
	Validator Validator
	Ipcipher  *Ipcipher
	PanIPv4   *PanIPv4
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

	decoded, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return NewAnonymizerWithKey(challenge, decoded)
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
	anonymizer.PanIPv4 = NewPanIPv4()

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
	anonymizer.PanIPv4 = NewPanIPv4()

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
		case PanIPv4Key:
			((*Pan)(a.PanIPv4)).WithKeyingMaterial(&key)
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
