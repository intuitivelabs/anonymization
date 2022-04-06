// Copyright 2019-2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// Prefix-preserving IP address anonymization.
// For details, see the original published research paper here:
// http://conferences.sigcomm.org/imc/2001/imw2001-papers/69.pdf

package anonymization

import (
	"fmt"
	"net"
)

const (
	// salt used for generating Call-ID encryption keys
	SaltPanIPIV  = "533ff532e4135d19bb3b994fe0ec9271"
	SaltPanIPKey = "57b55181b65c5ea2e44f7f25bf3a7014"
)

// Prefix-preserving anonymizer for ip addresses
// it implements cipher.Block interface
type PanIPv4 Pan

var (
	PanSalt = Salt{
		Key: SaltPanIPKey,
		IV:  SaltPanIPIV,
	}
	pan4 PanIPv4
)

func GetPan4() *PanIPv4 {
	return &pan4
}

func GenerateIV(masterKey []byte, ivLen int, iv []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltPanIPIV, masterKey, ivLen, iv)
}

func GenerateKey(masterKey []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltPanIPKey, masterKey, keyLen, key)
}

func NewPanIPv4() *PanIPv4 {
	ip := &PanIPv4{}
	((*Pan)(ip)).WithBitsPrefixBoundary(EightBitsPrefix)
	return ip
}

func (ip PanIPv4) DecryptStr(src string) (dst string, err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var dstIP, srcIP net.IP
	err = nil
	dst = ""
	dstIP = make([]byte, net.IPv4len)
	srcIP = net.ParseIP(src).To4()
	if srcIP == nil {
		err = fmt.Errorf("anonymization/PanIPv4: %s not an IPv4 address", src)
		return
	}
	(Pan(ip)).Decrypt(dstIP, srcIP)
	dst = dstIP.String()
	return
}

func (ip PanIPv4) EncryptStr(src string) (dst string, err error) {
	df := DbgOn()
	defer DbgRestore(df)
	var dstIP, srcIP net.IP
	err = nil
	dst = ""
	dstIP = make([]byte, net.IPv4len)
	srcIP = net.ParseIP(src).To4()
	_ = WithDebug && Dbg("srcIP: %v", srcIP)
	if srcIP == nil {
		err = fmt.Errorf("anonymization/PanIPv4: %s not an IPv4 address", src)
		return
	}
	(Pan(ip)).Encrypt(dstIP, srcIP)
	dst = dstIP.String()
	return
}
