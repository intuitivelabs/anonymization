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
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// salt used for generating Call-ID encryption keys
	SaltPanIPIV  = "533ff532e4135d19bb3b994fe0ec9271"
	SaltPanIPKey = "57b55181b65c5ea2e44f7f25bf3a7014"
)

type BitPrefixLen int

// allowed minimum bit prefix lengths;
// all other bit prefix lengths are a multiple of the minimum bit prefix lengths
const (
	OneBitPrefix BitPrefixLen = 1 << iota
	TwoBitsPrefix
	FourBitsPrefix
	EightBitsPrefix
	SixteenBitsPrefix
)

// keying material used for pan crypto algorithm: encryption key, IV
type KeyingMaterial struct {
	Key [BlockSize]byte
	IV  [BlockSize]byte
}

// Prefix-preserving anonymizer for ip addresses
// it implements cipher.Block interface
type PanIPv4 struct {
	km    KeyingMaterial
	block cipher.Block
	pad   [BlockSize]byte
	// prefixFactor is the shortest preserved bit prefix.
	// all preserved bits prefixes are a multiple of the prefixFactor
	prefixFactor BitPrefixLen
	// bitmask used to get the prefix from the pseudorandom function result
	prfMask uint32
}

var (
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
	pan := PanIPv4{}
	pan.WithBitsPrefixBoundary(EightBitsPrefix)
	return &pan
}

func InitKeys(masterKey []byte, encKey []byte, iv []byte) {
	df := DbgOn()
	defer DbgRestore(df)
	// generate IV
	if err := GenerateIV(masterKey[:], EncryptionKeyLen, iv[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("IV: %v", iv[:])
	// generate key
	if err := GenerateKey(masterKey[:], EncryptionKeyLen, encKey[:]); err != nil {
		panic(err)
	}
	_ = WithDebug && Dbg("Key: %v", encKey[:])
}

func NewKeyingMaterial(masterKey []byte) *KeyingMaterial {
	km := KeyingMaterial{}
	df := DbgOn()
	defer DbgRestore(df)
	InitKeys(masterKey, km.Key[:], km.IV[:])
	return &km
}

func (pan *PanIPv4) WithMasterKey(key []byte) *PanIPv4 {
	var err error
	InitKeys(key[:], pan.km.Key[:], pan.km.IV[:])
	if pan.block, err = aes.NewCipher(pan.km.Key[:]); err != nil {
		panic(err)
	}
	pan.block.Encrypt(pan.pad[:], pan.km.IV[:])
	return pan
}

func (pan *PanIPv4) WithBitsPrefixBoundary(b BitPrefixLen) *PanIPv4 {
	switch b {
	case OneBitPrefix, TwoBitsPrefix, FourBitsPrefix,
		EightBitsPrefix, SixteenBitsPrefix:
		pan.prefixFactor = b
		// bitmask used to get the prefix from the pseudorandom function result
		pan.prfMask = ((0xffffffff >> (32 - pan.prefixFactor)) << (32 - pan.prefixFactor))
		return pan
	default:
		return nil
	}
}

func (pan *PanIPv4) WithKeyAndIV(key [BlockSize]byte, iv [BlockSize]byte) *PanIPv4 {
	var err error
	subtle.ConstantTimeCopy(1, pan.km.Key[:], key[:])
	subtle.ConstantTimeCopy(1, pan.km.IV[:], iv[:])
	if pan.block, err = aes.NewCipher(pan.km.Key[:]); err != nil {
		panic(err)
	}
	pan.block.Encrypt(pan.pad[:], pan.km.IV[:])
	return pan
}

func (pan *PanIPv4) WithKeyingMaterial(km *KeyingMaterial) *PanIPv4 {
	pan.WithKeyAndIV(km.Key, km.IV)
	return pan
}

func (pan *PanIPv4) BlockSize() int { return BlockSize }

func (pan *PanIPv4) Encrypt(dst, src []byte) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		cipher [BlockSize]byte
		plain  [BlockSize]byte

		result uint32 = 0
	)

	if len(dst) < net.IPv4len {
		panic("anonymization/PanIPv4: output's size incorrect")
	}
	if len(src) < net.IPv4len {
		panic("anonymization/PanIPv4: input's size incorrect")
	}
	// cco: "IV" is stored in pad
	copy(plain[:], pan.pad[:])

	// orig starts in network byte order, do all operations in
	// host byte order
	_ = WithDebug && Dbg("src: %v", src)
	orig := binary.BigEndian.Uint32(src[:])

	// cco: "IV" is stored in pad
	pad := binary.LittleEndian.Uint32(pan.pad[0:4])
	_ = WithDebug && Dbg("pad: %v, pad: %v", pan.pad[0:4], pad)

	// For each prefixes with length from 0 to 31, generate a bit
	// using the given cipher, which is used as a pseudorandom
	// function here. The bits generated in every rounds are combined
	// into a pseudorandom one-time-pad.
	for pos := BitPrefixLen(0); pos < BitPrefixLen(32)/pan.prefixFactor; pos++ {
		shift := uint32(pan.prefixFactor * pos)
		mask := uint32(0xffffffff << (32 - shift))
		// cco: rotate the "IV" bits
		newpad := (pad << shift) | (pad >> (32 - shift))
		if pos == 0 {
			mask = 0
			newpad = pad
		}

		// convert plain into network byte order to be encrypted
		// cco: newpad is a kind of "IV"; it is rotated with 1 bit at each iteration
		// cco: "IV" bits are XORed with the plain text like in the CBC mode
		// cco: see also https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
		//*(u_int32_t*)rin_input = htonl( newpad^(orig&mask));
		binary.BigEndian.PutUint32(plain[0:4], newpad^(orig&mask))

		_ = WithDebug && Dbg("newpad: %x, orig: %x, mask: %x, plain: %v", newpad, orig, mask, plain[0:4])

		// Encryption: The cipher is used as pseudorandom
		// function. During each round, only the first bit of
		// cipher is used.
		pan.block.Encrypt(cipher[:], plain[:])

		// treat cipher, the output of the encryptor as network byte order
		// Combination: the bits are combined into a pseudorandom one-time-pad
		//result |= ( (ntohl(*(u_int32_t*)cipher)) & 0x80000000) >> pos;
		result |= (binary.BigEndian.Uint32(cipher[0:4]) & pan.prfMask) >> shift
		_ = WithDebug && Dbg("result: %v", result)
	}

	// XOR the orginal address with the pseudorandom one-time-pad
	// convert result to network byte order before returning
	//return htonl( result ^ orig );
	binary.BigEndian.PutUint32(dst, result^orig)
}

func (pan *PanIPv4) Decrypt(dst, src []byte) {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		cipher [BlockSize]byte
		plain  [BlockSize]byte
	)

	if len(dst) < net.IPv4len {
		panic("anonymization/PanIPv4: output's size incorrect")
	}
	if len(src) < net.IPv4len {
		panic("anonymization/PanIPv4: input's size incorrect")
	}
	// cco: "IV" is stored in pad
	copy(plain[:], pan.pad[:])
	orig := binary.BigEndian.Uint32(src[:])
	// cco: "IV" is stored in pad
	pad := binary.LittleEndian.Uint32(pan.pad[0:4])
	_ = WithDebug && Dbg("pad: %v, pad: %v", pan.pad[0:4], pad)
	for pos := BitPrefixLen(0); pos < BitPrefixLen(32)/pan.prefixFactor; pos++ {
		shift := uint32(pan.prefixFactor * pos)
		mask := uint32(0xffffffff << (32 - shift))
		// cco: rotate the "IV" bits
		newpad := (pad << shift) | (pad >> (32 - shift))
		if pos == 0 {
			mask = 0
			newpad = pad
		}

		// convert plain into network byte order to be encrypted
		// cco: newpad is a kind of "IV"; it is rotated with 1 bit at each iteration
		// cco: "IV" bits are XORed with the plain text like in the CBC mode
		// cco: see also https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
		//*(u_int32_t*)rin_input = htonl( newpad^(orig&mask));
		binary.BigEndian.PutUint32(plain[0:4], newpad^(orig&mask))

		// Encryption: The cipher is used as pseudorandom
		// function. During each round, only the first bit of
		// cipher is used.
		pan.block.Encrypt(cipher[:], plain[:])

		// treat cipher, the output of the encryptor as network byte order
		// Combination: the bits are combined into a pseudorandom one-time-pad
		//orig ^= ((ntohl(*(u_int32_t*)rin_output)) & 0x80000000) >> pos;
		orig ^= (binary.BigEndian.Uint32(cipher[0:4]) & pan.prfMask) >> shift
		_ = WithDebug && Dbg("newpad: %v, plain: %v, cipher: %v, orig: %v", newpad, plain, cipher, orig)
	}
	binary.BigEndian.PutUint32(dst, orig)
}

func (pan *PanIPv4) DecryptStr(src string) (dst string, err error) {
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
	pan.Decrypt(dstIP, srcIP)
	dst = dstIP.String()
	return
}

func (pan *PanIPv4) EncryptStr(src string) (dst string, err error) {
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
	pan.Encrypt(dstIP, srcIP)
	dst = dstIP.String()
	return
}
