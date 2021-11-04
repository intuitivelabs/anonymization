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
	"encoding/binary"
	"net"
)

// Prefix-preserving anonymizer for ip addresses
// it implements cipher.Block interface
type PanIPv4 struct {
	block cipher.Block
	key   [BlockSize]byte
	iv    [BlockSize]byte
	pad   [BlockSize]byte
}

func NewPanIPv4(key [BlockSize]byte, iv [BlockSize]byte) (pan *PanIPv4, err error) {
	pan = &PanIPv4{
		key: key,
		iv:  iv,
	}
	if pan.block, err = aes.NewCipher(key[:]); err != nil {
		return nil, err
	}
	pan.block.Encrypt(pan.pad[:], pan.iv[:])
	return
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
	Dbg("pad: %v, pad32: %v", pan.pad[0:4], pad32)

	// For each prefixes with length from 0 to 31, generate a bit
	// using the given cipher, which is used as a pseudorandom
	// function here. The bits generated in every rounds are combined
	// into a pseudorandom one-time-pad.
	for pos := 0; pos < 32; pos++ {

		mask := uint32(0xffffffff << (32 - pos))
		// cco: rotate the "IV" bits
		newpad := (pad32 << pos) | (pad32 >> (32 - pos))
		if pos == 0 {
			mask = 0
			newpad = pad32
		}
		Dbg("newpad: %v", newpad)

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
		//result |= ( (ntohl(*(u_int32_t*)cipher)) & 0x80000000) >> pos;
		result |= (binary.BigEndian.Uint32(cipher[0:4]) & 0x80000000) >> pos
		Dbg("result: %v", result)
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
	Dbg("pad: %v, pad32: %v", pan.pad[0:4], pad32)
	for pos := 0; pos < 32; pos++ {

		mask := uint32(0xffffffff << (32 - pos))
		// cco: rotate the "IV" bits
		newpad := (pad32 << pos) | (pad32 >> (32 - pos))
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
		orig_addr ^= (binary.BigEndian.Uint32(cipher[0:4]) & 0x80000000) >> pos
	}
	binary.BigEndian.PutUint32(dst, orig_addr)
}
