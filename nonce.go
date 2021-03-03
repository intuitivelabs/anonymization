// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

// see ipcipher specification here:
// https://powerdns.org/ipcipher/ipcipher.md.html

package anonymization

import (
	"crypto/rand"
	"strconv"
	"sync/atomic"
	"time"
)

type NonceType int

// nonce type
const (
	NonceRandom NonceType = iota
	NonceCounter
	NonceTimestamp
)

var NoncerNames = [...]string{NonceRandom: "Random nonce", NonceCounter: "Counter nonce", NonceTimestamp: "Timestamp nonce"}

// randomUint32 generates a random unsigned integer
func randomUint32() (n uint32, err error) {
	var buf [4]byte
	if _, err = rand.Read(buf[:]); err != nil {
		n = 0
		return
	}
	n = 0
	for i, b := range buf {
		n = n | uint32(b)<<(8*uint32(i))
	}
	return
}

type Noncer interface {
	NextNonce() (uint32, error)
	String() string
}

type RandomNoncer struct {
	nonce uint32
}

func (rn RandomNoncer) NextNonce() (uint32, error) {
	var err error
	rn.nonce, err = randomUint32()
	return rn.nonce, err
}

func (rn RandomNoncer) String() string {
	return strconv.FormatUint(uint64(rn.nonce), 10)
}

type CountNoncer struct {
	nonce uint32
}

func (cn CountNoncer) NextNonce() (uint32, error) {
	nonce := atomic.AddUint32(&cn.nonce, 1)
	return nonce, nil
}

func (cn CountNoncer) String() string {
	return strconv.FormatUint(uint64(cn.nonce), 10)
}

type TimeNoncer struct {
	nonce uint32
}

func (tn TimeNoncer) NextNonce() (uint32, error) {
	tn.nonce = uint32(time.Now().Unix())
	return tn.nonce, nil
}

func (tn TimeNoncer) String() string {
	return strconv.FormatUint(uint64(tn.nonce), 10)
}

func NewNoncer(nonceType NonceType) (Noncer, error) {
	var (
		nonce  uint32 = 0
		noncer Noncer = nil
		err    error  = nil
	)
	switch nonceType {
	case NonceRandom:
		if nonce, err = randomUint32(); err == nil {
			noncer = RandomNoncer{nonce}
		}
	case NonceTimestamp:
		noncer = TimeNoncer{0}
		noncer.NextNonce()
	case NonceCounter:
		if nonce, err = randomUint32(); err == nil {
			noncer = CountNoncer{nonce}
		}
	}
	return noncer, err
}
