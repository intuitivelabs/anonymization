// Copyright 2019-2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// Prefix-preserving anonymization.
// For details, see the original published research paper here:
// http://conferences.sigcomm.org/imc/2001/imw2001-papers/69.pdf

package anonymization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

type BitPrefixLen int

// errors
var (
	ErrSmallOutput     = errors.New("anonymization/pan: output smaller than input")
	ErrInvalidInputLen = errors.New("anonymization/pan: invalid input length (should be a multiple of 4 bytes)")
)

// allowed minimum bit prefix lengths;
// all other bit prefix lengths are a multiple of the minimum bit prefix lengths
const (
	OneBitPrefix BitPrefixLen = 1 << iota
	TwoBitsPrefix
	FourBitsPrefix
	EightBitsPrefix
	SixteenBitsPrefix
)

// Prefix-preserving anonymizer
// It implements cipher.Block interface
type Pan struct {
	km    KeyingMaterial
	block cipher.Block
	pad   [BlockSize]byte
	// prefixFactor is the shortest preserved bit prefix.
	// all preserved bits prefixes are a multiple of the prefixFactor
	prefixFactor BitPrefixLen
	// bitmask used to get the prefix from the pseudorandom function result
	prfMask uint32
}

func NewPan() *Pan {
	pan := Pan{}
	pan.WithBitsPrefixBoundary(EightBitsPrefix)
	return &pan
}

// WithMasterKey generates Pan's keying material using the key parameter and the PanSalt
func (pan *Pan) WithMasterKey(key []byte) *Pan {
	var err error
	//InitKeys(key[:], pan.km.Key[:], pan.km.IV[:])
	pan.km = *NewKeyingMaterial(key[:], &PanSalt)
	if pan.block, err = aes.NewCipher(pan.km.Enc[:]); err != nil {
		panic(err)
	}
	pan.block.Encrypt(pan.pad[:], pan.km.IV[:])
	return pan
}

func (pan *Pan) WithBitsPrefixBoundary(b BitPrefixLen) *Pan {
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

func (pan *Pan) WithKeyAndIV(key [BlockSize]byte, iv [BlockSize]byte) *Pan {
	var err error
	subtle.ConstantTimeCopy(1, pan.km.Enc[:], key[:])
	subtle.ConstantTimeCopy(1, pan.km.IV[:], iv[:])
	if pan.block, err = aes.NewCipher(pan.km.Enc[:]); err != nil {
		panic(err)
	}
	pan.block.Encrypt(pan.pad[:], pan.km.IV[:])
	return pan
}

func (pan *Pan) WithKeyingMaterial(km *KeyingMaterial) *Pan {
	pan.WithKeyAndIV(km.Enc, km.IV)
	return pan
}

func (pan Pan) BlockSize() int { return BlockSize }

func (pan Pan) Encrypt(dst, src []byte) error {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		cipher [BlockSize]byte
		plain  [BlockSize]byte

		result uint32 = 0
	)

	if len(dst) < len(src) {
		return ErrSmallOutput
	}
	// "IV" is stored in pad
	copy(plain[:], pan.pad[:])

	_ = WithDebug && Dbg("src: %v", src)
	// the algorithm encrypts 4 bytes (32 bit) integers at a time; compute the number of required iterations
	iterations := len(src) / 4
	if len(src)%4 > 0 {
		if len(dst) < (len(src) + 4 - len(src)%4) {
			return ErrSmallOutput
		}
		iterations++
	}
	for i := 0; i < iterations; i++ {
		var orig uint32
		// orig starts in network byte order, do all operations in host byte order
		if (i + 4) > len(src) {
			// in case the length of src is not an multiple of 4, pad the missing bytes with '0'
			var tmp [4]byte
			copy(tmp[:], src[i:])
			orig = binary.BigEndian.Uint32(tmp[:])
		} else {
			orig = binary.BigEndian.Uint32(src[i : i+4])
		}

		// "IV" is stored in pad
		pad := binary.LittleEndian.Uint32(pan.pad[0:4])
		_ = WithDebug && Dbg("pad: %v, pad: %v", pan.pad[0:4], pad)

		// For each prefixes with length from 0 to 31, generate a bit
		// using the given cipher, which is used as a pseudorandom
		// function here. The bits generated in every rounds are combined
		// into a pseudorandom one-time-pad.
		for pos := BitPrefixLen(0); pos < BitPrefixLen(32)/pan.prefixFactor; pos++ {
			shift := uint32(pan.prefixFactor * pos)
			mask := uint32(0xffffffff << (32 - shift))
			// rotate the "IV" bits
			newpad := (pad << shift) | (pad >> (32 - shift))
			if pos == 0 {
				mask = 0
				newpad = pad
			}

			// convert plain into network byte order to be encrypted
			// newpad is a kind of "IV"; it is rotated with 1 bit at each iteration
			// "IV" bits are XORed with the plain text like in the CBC mode
			// see also https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
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
		binary.BigEndian.PutUint32(dst[i:i+4], result^orig)
	}
	return nil
}

func (pan Pan) Decrypt(dst, src []byte) error {
	df := DbgOn()
	defer DbgRestore(df)
	var (
		cipher [BlockSize]byte
		plain  [BlockSize]byte
	)

	// the length of the source slice should be a multiple of 4 bytes
	if len(src)%4 != 0 {
		return ErrInvalidInputLen
	}
	if len(dst) < len(src) {
		return ErrSmallOutput
	}
	// "IV" is stored in pad
	copy(plain[:], pan.pad[:])
	// the algorithm decrypts 4 bytes (32 bit) integers at a time; compute the number of required iterations
	iterations := len(src) / 4
	for i := 0; i < iterations; i++ {
		orig := binary.BigEndian.Uint32(src[i : i+4])
		// "IV" is stored in pad
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
		binary.BigEndian.PutUint32(dst[i:i+4], orig)
	}
	return nil
}
