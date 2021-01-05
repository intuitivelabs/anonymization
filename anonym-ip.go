// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// see ipcipher specification here:
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
)

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

// encryptIPv4 anonymizes the "IP" address by encrypting it
func encryptIPv4(key [16]byte, IP net.IP) (encryptedIP net.IP, err error) {
	var c [4]byte
	if c, err = ipcrypt.EncryptBin(key, IP); err == nil {
		encryptedIP = c[:]
	}
	return
}

func encryptIPv4InPlace(key [16]byte, IP net.IP) (err error) {
	var c [net.IPv4len]byte
	if c, err = ipcrypt.EncryptBin(key, IP); err == nil {
		err = setIPv4Bytes(IP, c)
	}
	return
}

func encryptIPv6(key [16]byte, IP net.IP) (encryptedIP net.IP, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err != nil {
		encryptedIP = []byte{}
	} else {
		encryptedIP = make([]byte, net.IPv6len)
		block.Encrypt(encryptedIP, IP)
	}
	return
}

func encryptIPv6InPlace(key [16]byte, IP net.IP) (err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key[:]); err == nil {
		var c [net.IPv6len]byte
		block.Encrypt(c[:], IP)
		copy(IP, c[:])
	}
	return
}

// EncryptIP returns the anonymized (encrypted) "IP" address
func EncryptIP(key [16]byte, IP net.IP) (encryptedIP net.IP, err error) {
	if IP.To4() != nil {
		encryptedIP, err = encryptIPv4(key, IP)
	} else if IP.To16() != nil {
		encryptedIP, err = encryptIPv6(key, IP)
	} else {
		err = ErrBrokenIP
	}
	return
}

// EncryptIPInPlace anonymizes the "IP" address by encrypting it
func EncryptIPInPlace(key [16]byte, IP net.IP) (err error) {
	if IP.To4() != nil {
		err = encryptIPv4InPlace(key, IP)
	} else if IP.To16() != nil {
		err = encryptIPv6InPlace(key, IP)
	} else {
		err = ErrBrokenIP
	}
	return
}
