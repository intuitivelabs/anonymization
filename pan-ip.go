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

// Prefix-preserving anonymizer for ip addresses
// it implements cipher.Block interface
type PanIPv4 struct {
	block cipher.Block
	Key   [BlockSize]byte
	IV    [BlockSize]byte
	pad   [BlockSize]byte
	// prefixFactor is the shortest prefix. all bits prefixes are a multiple of the prefixFactor
	prefixFactor BitPrefixLen
}

var (
	pan4 PanIPv4
)

func NewPanIPv4(masterKey []byte) (pan *PanIPv4) {
	pan = GetPan4()
	pan.WithMasterKey(masterKey)
	pan.WithBitsPrefixBoundary(EightBitsPrefix)
	return
}

func GetPan4() *PanIPv4 {
	return &pan4
}

func GeneratePanIPIV(masterKey []byte, ivLen int, iv []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltPanIPIV, masterKey, ivLen, iv)
}

func GeneratePanIPKey(masterKey []byte, keyLen int, key []byte) error {
	return GenerateKeyWithSaltAndCopy(SaltPanIPKey, masterKey, keyLen, key)
}

func InitPanIPv4KeysFromMasterKey(masterKey []byte, encKey []byte, iv []byte) {
	df := DbgOn()
	defer DbgRestore(df)
	// generate IV
	if err := GeneratePanIPIV(masterKey[:], EncryptionKeyLen, iv[:]); err != nil {
		panic(err)
	}
	Dbg("IV: %v", iv[:])
	// generate key
	if err := GeneratePanIPKey(masterKey[:], EncryptionKeyLen, encKey[:]); err != nil {
		panic(err)
	}
	Dbg("Key: %v", encKey[:])
}

func (pan *PanIPv4) WithMasterKey(key []byte) *PanIPv4 {
	var err error
	InitPanIPv4KeysFromMasterKey(key[:], pan.Key[:], pan.IV[:])
	if pan.block, err = aes.NewCipher(pan.Key[:]); err != nil {
		panic(err)
	}
	pan.block.Encrypt(pan.pad[:], pan.IV[:])
	return pan
}

func (pan *PanIPv4) WithBitsPrefixBoundary(b BitPrefixLen) *PanIPv4 {
	switch b {
	case OneBitPrefix, TwoBitsPrefix, FourBitsPrefix,
		EightBitsPrefix, SixteenBitsPrefix:
		pan.prefixFactor = b
		return pan
	default:
		return nil
	}
}

func (pan *PanIPv4) WithKeyAndIV(key [BlockSize]byte, iv [BlockSize]byte) *PanIPv4 {
	var err error
	subtle.ConstantTimeCopy(1, pan.Key[:], key[:])
	subtle.ConstantTimeCopy(1, pan.IV[:], iv[:])
	if pan.block, err = aes.NewCipher(pan.Key[:]); err != nil {
		panic(err)
	}
	pan.block.Encrypt(pan.pad[:], pan.IV[:])
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

	// orig_addr starts in network byte order, do all operations in
	// host byte order
	orig_addr := binary.BigEndian.Uint32(src[:])

	// cco: "IV" is stored in pad
	pad32 := binary.LittleEndian.Uint32(pan.pad[0:4])
	if WithDebug {
		Dbg("pad: %v, pad32: %v", pan.pad[0:4], pad32)
	}

	// For each prefixes with length from 0 to 31, generate a bit
	// using the given cipher, which is used as a pseudorandom
	// function here. The bits generated in every rounds are combined
	// into a pseudorandom one-time-pad.
	for pos := BitPrefixLen(0); pos < BitPrefixLen(32)/pan.prefixFactor; pos++ {
		shift := uint32(pan.prefixFactor * pos)
		mask := uint32(0xffffffff << (32 - shift))
		// cco: rotate the "IV" bits
		newpad := (pad32 << shift) | (pad32 >> (32 - shift))
		if pos == 0 {
			mask = 0
			newpad = pad32
		}

		// convert plain into network byte order to be encrypted
		// cco: newpad is a kind of "IV"; it is rotated with 1 bit at each iteration
		// cco: "IV" bits are XORed with the plain text like in the CBC mode
		// cco: see also https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
		//*(u_int32_t*)rin_input = htonl( newpad^(orig_addr&mask));
		binary.BigEndian.PutUint32(plain[0:4], newpad^(orig_addr&mask))

		if WithDebug {
			Dbg("newpad: %v, plain: %v", newpad, plain[0:4])
		}

		// Encryption: The cipher is used as pseudorandom
		// function. During each round, only the first bit of
		// cipher is used.
		pan.block.Encrypt(cipher[:], plain[:])

		// treat cipher, the output of the encryptor as network byte order
		// Combination: the bits are combined into a pseudorandom one-time-pad
		//result |= ( (ntohl(*(u_int32_t*)cipher)) & 0x80000000) >> pos;
		result |= (binary.BigEndian.Uint32(cipher[0:4]) & 0xFF000000) >> shift
		if WithDebug {
			Dbg("result: %v", result)
		}
	}

	// XOR the orginal address with the pseudorandom one-time-pad
	// convert result to network byte order before returning
	//return htonl( result ^ orig_addr );
	binary.BigEndian.PutUint32(dst, result^orig_addr)
}

func (pan *PanIPv4) Decrypt(dst, src []byte) {
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
	orig_addr := binary.BigEndian.Uint32(src[:])
	// cco: "IV" is stored in pad
	pad32 := binary.LittleEndian.Uint32(pan.pad[0:4])
	if WithDebug {
		Dbg("pad: %v, pad32: %v", pan.pad[0:4], pad32)
	}
	for pos := BitPrefixLen(0); pos < BitPrefixLen(32)/pan.prefixFactor; pos++ {
		shift := uint32(pan.prefixFactor * pos)
		mask := uint32(0xffffffff << (32 - shift))
		// cco: rotate the "IV" bits
		newpad := (pad32 << shift) | (pad32 >> (32 - shift))
		if pos == 0 {
			mask = 0
			newpad = pad32
		}

		// convert plain into network byte order to be encrypted
		// cco: newpad is a kind of "IV"; it is rotated with 1 bit at each iteration
		// cco: "IV" bits are XORed with the plain text like in the CBC mode
		// cco: see also https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
		//*(u_int32_t*)rin_input = htonl( newpad^(orig_addr&mask));
		binary.BigEndian.PutUint32(plain[0:4], newpad^(orig_addr&mask))

		// Encryption: The cipher is used as pseudorandom
		// function. During each round, only the first bit of
		// cipher is used.
		pan.block.Encrypt(cipher[:], plain[:])

		// treat cipher, the output of the encryptor as network byte order
		// Combination: the bits are combined into a pseudorandom one-time-pad
		//orig_addr ^= ((ntohl(*(u_int32_t*)rin_output)) & 0x80000000) >> pos;
		orig_addr ^= (binary.BigEndian.Uint32(cipher[0:4]) & 0xFF000000) >> shift
	}
	binary.BigEndian.PutUint32(dst, orig_addr)
}
