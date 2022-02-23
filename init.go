package anonymization

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

type Anonymizer struct {
	Validator Validator
	Ipcipher  *Ipcipher
	Pan       *PanIPv4
	Uri       *UriCBCMode
	CallId    *BlockModeCipher
}

func NewAnonymizerWithPassphrase(salt, passphrase string) (*Anonymizer, error) {
	var key [EncryptionKeyLen]byte
	GenerateKeyFromPassphraseAndCopy(passphrase,
		EncryptionKeyLen, key[:])
	return NewAnonymizer(salt, key[:])
}

func NewAnonymizerWithKey(salt, key string) (*Anonymizer, error) {
	var encKey [EncryptionKeyLen]byte

	// copy the configured key into the one used during realtime processing
	if decoded, err := hex.DecodeString(key); err != nil {
		return nil, err
	} else {
		subtle.ConstantTimeCopy(1, encKey[:], decoded)
	}
	return NewAnonymizer(salt, encKey[:])
}

func NewAnonymizer(salt string, key []byte) (*Anonymizer, error) {
	var encKey [EncryptionKeyLen]byte
	var authKey [AuthenticationKeyLen]byte
	var anonymizer Anonymizer = Anonymizer{}

	if len(salt) == 0 {
		return nil, errors.New("initEncryption: salt for" +
			" password validation is missing")
	}

	// generate authentication (HMAC) key from encryption key
	GenerateKeyFromBytesAndCopy(encKey[:], AuthenticationKeyLen, authKey[:])
	// validation code is the first 5 bytes of HMAC(SHA256) of random nonce; each thread needs its own validator!
	if validator, err := NewKeyValidator(crypto.SHA256, authKey[:],
		5 /*length*/, salt, NonceNone, false /*withNonce*/, true /*pre-allocated HMAC*/); err != nil {
		return nil, err
	} else {
		anonymizer.Validator = validator
	}

	if ipcipher, err := NewCipher(encKey[:]); err != nil {
		return nil, err
	} else {
		anonymizer.Ipcipher = ipcipher.(*Ipcipher)
	}

	// initialize the IP Prefix-preserving anonymization
	anonymizer.Pan = NewPanIPv4(encKey[:])

	// initialize the URI CBC based encryption
	anonymizer.Uri = NewUriCBCWithMasterKey(encKey[:])

	// initialize the Call-ID CBC based encryption
	anonymizer.CallId = NewCallIdCBCWithMasterKey(encKey[:])

	return &anonymizer, nil
}
