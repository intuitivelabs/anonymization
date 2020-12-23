// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package anonymization

import (
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
// "encryptedIP" preserves the internal net.IP format of the input parameter "IP" address
func encryptIPv4(key [16]byte, IP net.IP) (encryptedIP net.IP, err error) {
	if c, err := ipcrypt.EncryptBin(key, IP); err == nil {
		err = setIPv4Bytes(encryptedIP, c)
	}
	return
}

func encryptIPv6(key [16]byte, IP net.IP) (encryptedIP net.IP, err error) {
	return
}

// EncryptIP anonymizes the "IP" address by encrypting it
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
