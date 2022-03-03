// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// IP address anonymization using block encryption.
// For details, see ipcipher specification here:
// https://powerdns.org/ipcipher/ipcipher.md.html

package anonymization

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"github.com/intuitivelabs/ipcrypt"
	"net"
)

var (
	ErrBrokenIP = errors.New("broken IP address")
	ErrKeySize  = errors.New("illegal key size")
)

const BlockSize = 16

// Ipcipher implements cipher.Block interface
type Ipcipher struct {
	key [BlockSize]byte
}

func (c *Ipcipher) BlockSize() int { return BlockSize }

func NewCipher(key []byte) (cipher.Block, error) {
	switch k := len(key); k {
	default:
		return nil, ErrKeySize
	case BlockSize:
		break
	}
	var a [BlockSize]byte
	for i, v := range key {
		a[i] = v
	}
	return &Ipcipher{a}, nil
}

func NewPassphraseCipher(passphrase string) (cipher.Block, error) {
	var key [EncryptionKeyLen]byte
	GenerateKeyFromPassphraseAndCopy(passphrase, EncryptionKeyLen, key[:])
	return NewCipher(key[:])
}

func (c *Ipcipher) Encrypt(dst, src []byte) {
	if err := EncryptIP(c.key, dst, src); err != nil {
		panic("anonymization: encrypt error")
	}
	return
}

func (c *Ipcipher) EncryptIPv6Str(src string) (dst string, err error) {
	if dst, err = EncryptedIPv6String(c.key, src); err != nil {
		return "", err
	}
	return dst, nil
}

func (c *Ipcipher) DecryptIPv6Str(src string) (dst string, err error) {
	if dst, err = DecryptedIPv6String(c.key, src); err != nil {
		return "", err
	}
	return dst, nil
}

func (c *Ipcipher) Decrypt(dst, src []byte) {
	if err := DecryptIP(c.key, dst, src); err != nil {
		panic("anonymization: decrypt error")
	}
	return
}

func (c *Ipcipher) DecryptStr(src string) (dst string) {
	var err error
	if dst, err = DecryptedIPString(c.key, src); err != nil {
		panic("anonymization: decrypt error")
	}
	return
}

// setIPv4Bytes sets the bytes of an IPv4 address preserving the format
// (i.e. either plain IPv4 or IPv4 address represented as an IPv6 address)
// it assumes "ip" is an IPv4 address
func setIPv4Bytes(IP net.IP, b [4]byte) (err error) {
	switch len(IP) {
	case net.IPv4len:
		copy(IP, b[:])
	case net.IPv6len:
		copy(IP[12:], b[:])
	default:
		err = ErrBrokenIP
	}
	return
}

// encryptIPv4 writes the anonymized (encrypted) IPv4 IP address into "encryptedIP"
func encryptIPv4(key [BlockSize]byte, encryptedIP, IP net.IP) (err error) {
	var c [net.IPv4len]byte
	if c, err = ipcrypt.EncryptBin(key, IP); err == nil {
		copy(encryptedIP, c[:])
	}
	return
}

// decryptIPv4 writes the plain (decrypted) IPv4 IP address into "IP"
func decryptIPv4(key [BlockSize]byte, IP, encryptedIP net.IP) (err error) {
	var c [net.IPv4len]byte
	if c, err = ipcrypt.DecryptBin(key, encryptedIP); err == nil {
		copy(IP, c[:])
	}
	return
}

// encryptedIPv4 returns the anonymized (encrypted) IPv4 address
func encryptedIPv4(key [BlockSize]byte, IP net.IP) (encryptedIP net.IP, err error) {
	var c [4]byte
	if c, err = ipcrypt.EncryptBin(key, IP); err == nil {
		encryptedIP = c[:]
	}
	return
}

// decryptedIPv4 returns the plain (decrypted) IPv4 address
func decryptedIPv4(key [BlockSize]byte, encryptedIP net.IP) (IP net.IP, err error) {
	var c [4]byte
	if c, err = ipcrypt.DecryptBin(key, encryptedIP); err == nil {
		IP = c[:]
	}
	return
}

// encryptIPv4InPlace anonymizes the IPv4 IP address by encrypting it in-place
func encryptIPv4InPlace(key [BlockSize]byte, IP net.IP) (err error) {
	var c [net.IPv4len]byte
	if c, err = ipcrypt.EncryptBin(key, IP); err == nil {
		err = setIPv4Bytes(IP, c)
	}
	return
}

// decryptIPv4InPlace uncovers the IPv4 IP address by decrypting it in-place
func decryptIPv4InPlace(key [BlockSize]byte, encryptedIP net.IP) (err error) {
	var c [net.IPv4len]byte
	if c, err = ipcrypt.DecryptBin(key, encryptedIP); err == nil {
		err = setIPv4Bytes(encryptedIP, c)
	}
	return
}

// encryptIPv6 writes the anonymized (encrypted) IPv6 IP address into "encryptedIP"
func encryptIPv6(key [BlockSize]byte, encryptedIP, IP net.IP) (err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err == nil {
		block.Encrypt(encryptedIP, IP)
	}
	return
}

// decryptIPv6 writes the plain (decrypted) IPv6 IP address into "IP"
func decryptIPv6(key [BlockSize]byte, IP, encryptedIP net.IP) (err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err == nil {
		block.Decrypt(IP, encryptedIP)
	}
	return
}

// encryptedIPv6 returns the anonymized (encrypted) IPv6 address
func encryptedIPv6(key [BlockSize]byte, IP net.IP) (encryptedIP net.IP, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err != nil {
		encryptedIP = []byte{}
	} else {
		encryptedIP = make([]byte, net.IPv6len)
		block.Encrypt(encryptedIP, IP)
	}
	return
}

// decryptedIPv6 returns the plain (decrypted) IPv6 address
func decryptedIPv6(key [BlockSize]byte, encryptedIP net.IP) (IP net.IP, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err != nil {
		IP = []byte{}
	} else {
		IP = make([]byte, net.IPv6len)
		block.Decrypt(IP, encryptedIP)
	}
	return
}

// encryptIPv6InPlace anonymizes the IPv6 IP address by encrypting it in-place
func encryptIPv6InPlace(key [BlockSize]byte, IP net.IP) (err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err == nil {
		var c [net.IPv6len]byte
		block.Encrypt(c[:], IP)
		copy(IP, c[:])
	}
	return
}

// decryptIPv6InPlace uncovers the IPv6 IP address by decrypting it in-place
func decryptIPv6InPlace(key [BlockSize]byte, encryptedIP net.IP) (err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err == nil {
		var c [net.IPv6len]byte
		block.Decrypt(c[:], encryptedIP)
		copy(encryptedIP, c[:])
	}
	return
}

// EncryptIP writes the anonymized (encrypted) IP address into encryptedIP
func EncryptIP(key [BlockSize]byte, encryptedIP, IP net.IP) (err error) {
	if IP.To4() != nil &&
		(len(encryptedIP) == net.IPv4len ||
			len(encryptedIP) == net.IPv6len) {
		err = encryptIPv4(key, encryptedIP, IP)
	} else if IP.To16() != nil &&
		len(encryptedIP) == net.IPv6len {
		err = encryptIPv6(key, encryptedIP, IP)
	} else {
		err = ErrBrokenIP
	}
	return
}

// DecryptIP writes the plain (decrypted) IP address into IP
func DecryptIP(key [BlockSize]byte, IP, encryptedIP net.IP) (err error) {
	if encryptedIP.To4() != nil &&
		(len(IP) == net.IPv4len ||
			len(IP) == net.IPv6len) {
		err = decryptIPv4(key, IP, encryptedIP)
	} else if encryptedIP.To16() != nil &&
		len(IP) == net.IPv6len {
		err = decryptIPv6(key, IP, encryptedIP)
	} else {
		err = ErrBrokenIP
	}
	return
}

// EncryptedIP returns the anonymized (encrypted) IP address
func EncryptedIP(key [BlockSize]byte, IP net.IP) (encryptedIP net.IP, err error) {
	if IP.To4() != nil {
		encryptedIP, err = encryptedIPv4(key, IP)
	} else if IP.To16() != nil {
		encryptedIP, err = encryptedIPv6(key, IP)
	} else {
		err = ErrBrokenIP
	}
	return
}

// DecryptedIP returns the plain (decrypted) IP address
func DecryptedIP(key [BlockSize]byte, encryptedIP net.IP) (IP net.IP, err error) {
	if encryptedIP.To4() != nil {
		IP, err = decryptedIPv4(key, encryptedIP)
	} else if encryptedIP.To16() != nil {
		IP, err = decryptedIPv6(key, encryptedIP)
	} else {
		err = ErrBrokenIP
	}
	return
}

// EncryptedIPv6 returns the encrypted IPv6 address as a string
func EncryptedIPv6String(key [BlockSize]byte, plain string) (encrypted string, err error) {
	encrypted = ""
	var IP net.IP
	plainIP := net.ParseIP(plain)
	if plainIP.To16() != nil {
		IP, err = encryptedIPv6(key, plainIP)
	} else {
		err = ErrBrokenIP
	}
	if err == nil {
		encrypted = IP.String()
	}
	return
}

// DecryptedIPv6 returns the encrypted IPv6 address as a string
func DecryptedIPv6String(key [BlockSize]byte, encrypted string) (decrypted string, err error) {
	decrypted = ""
	var IP net.IP
	encryptedIP := net.ParseIP(encrypted)
	if encryptedIP.To16() != nil {
		IP, err = decryptedIPv6(key, encryptedIP)
	} else {
		err = ErrBrokenIP
	}
	if err == nil {
		decrypted = IP.String()
	}
	return
}

func DecryptedIPString(key [BlockSize]byte, encrypted string) (decrypted string, err error) {
	decrypted = ""
	var IP net.IP
	encryptedIP := net.ParseIP(encrypted)
	if encryptedIP.To4() != nil {
		IP, err = decryptedIPv4(key, encryptedIP)
	} else if encryptedIP.To16() != nil {
		IP, err = decryptedIPv6(key, encryptedIP)
	} else {
		err = ErrBrokenIP
	}
	if err == nil {
		decrypted = IP.String()
	}
	return
}

// EncryptIPInPlace anonymizes the "IP" address by encrypting it in-place
func EncryptIPInPlace(key [BlockSize]byte, IP net.IP) (err error) {
	if IP.To4() != nil {
		err = encryptIPv4InPlace(key, IP)
	} else if IP.To16() != nil {
		err = encryptIPv6InPlace(key, IP)
	} else {
		err = ErrBrokenIP
	}
	return
}

// DecryptIPInPlace uncovers the "encryptedIP" address by de-encrypting it in-place
func DecryptIPInPlace(key [BlockSize]byte, encryptedIP net.IP) (err error) {
	if encryptedIP.To4() != nil {
		err = decryptIPv4InPlace(key, encryptedIP)
	} else if encryptedIP.To16() != nil {
		err = decryptIPv6InPlace(key, encryptedIP)
	} else {
		err = ErrBrokenIP
	}
	return
}
