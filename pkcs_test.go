package anonymization

import (
	"bytes"
	"testing"
)

type BlockPair struct {
	padded   []byte
	unpadded []byte
}

func TestPKCSPad(t *testing.T) {
	df := DbgOff()
	defer DbgRestore(df)
	oneBlockPairs := [...]BlockPair{
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 5, 5, 5},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 6, 6, 6, 6, 6},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	twoBlockPairs := [...]BlockPair{
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	manyBlockPairs := [...]BlockPair{
		{
			padded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2},
			unpadded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			unpadded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3},
			unpadded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			unpadded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			unpadded: []byte{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	broken := [...][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
		{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3},
		{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17},
	}
	t.Run("only one block un-padding", func(t *testing.T) {
		df := DbgOff()
		defer DbgRestore(df)
		for i, pair := range oneBlockPairs {
			Dbg("i: %d, padded: %v", i, pair.padded)
			if u, err := PKCSUnpad(pair.padded, 16); err != nil {
				t.Fatalf("unpadding error: %s", err)
			} else if !bytes.Equal(u, pair.unpadded[:16-1-i]) {
				t.Fatalf("expected %v got %v", pair.unpadded[:16-1-i], u)
			}
		}
	})
	t.Run("only one block padding", func(t *testing.T) {
		df := DbgOff()
		defer DbgRestore(df)
		for i, pair := range oneBlockPairs {
			Dbg("i: %d, padded: %v", i, pair.padded)
			if p, err := PKCSPad(pair.unpadded, 0, len(pair.unpadded)-1-i, 16); err != nil {
				t.Fatalf("padding error: %s", err)
			} else if !bytes.Equal(p[0:16], pair.padded) {
				t.Fatalf("expected %v got %v", pair.padded, p[0:16])
			}
		}
	})
	t.Run("only one block padding, preallocated memory", func(t *testing.T) {
		var mem []byte
		for i, pair := range oneBlockPairs {
			mem = bytes.Repeat([]byte{0}, 16)
			pair.unpadded = mem
			if p, err := PKCSPad(pair.unpadded, 0, len(pair.unpadded)-1-i, 16); err != nil {
				t.Fatalf("padding error: %s", err)
			} else if !bytes.Equal(p[0:16], pair.padded) {
				t.Fatalf("expected %v (len: %d) got %v (len: %d)", pair.padded, len(pair.padded), p[0:16], len(pair.padded))
			}
		}
	})
	t.Run("two block un-padding", func(t *testing.T) {
		for _, pair := range twoBlockPairs {
			if u, err := PKCSUnpad(pair.padded, 16); err != nil {
				t.Fatalf("unpadding error: %s", err)
			} else if !bytes.Equal(u, pair.unpadded[0:16]) {
				t.Fatalf("expected %v got %v", pair.unpadded, u)
			}
		}
	})
	t.Run("two block padding", func(t *testing.T) {
		for _, pair := range twoBlockPairs {
			if p, err := PKCSPad(pair.unpadded, 0, 16, 16); err != nil {
				t.Fatalf("padding error: %s", err)
			} else if !bytes.Equal(p[0:32], pair.padded) {
				t.Fatalf("expected %v got %v", pair.padded, p[0:32])
			}
		}
	})
	t.Run("many blocks un-padding", func(t *testing.T) {
		for _, pair := range manyBlockPairs {
			if u, err := PKCSUnpad(pair.padded, 16); err != nil {
				t.Fatalf("unpadding error: %s", err)
			} else if !bytes.Equal(u, pair.unpadded[:len(u)]) {
				t.Fatalf("expected %v got %v", pair.unpadded[:len(u)], u)
			}
		}
	})
	t.Run("many blocks padding", func(t *testing.T) {
		df := DbgOff()
		defer DbgRestore(df)
		for i, pair := range manyBlockPairs {
			Dbg("i: %d, padded: %v", i, pair.padded)
			u, err := PKCSUnpad(pair.padded, 16)
			if err != nil {
				t.Fatalf("unpadding error: %s", err)
			}
			if p, err := PKCSPad(pair.unpadded, 0, len(u), 16); err != nil {
				t.Fatalf("padding error: %s", err)
			} else if !bytes.Equal(p, pair.padded) {
				t.Fatalf("expected %v got %v", pair.padded, p)
			}
		}
	})
	t.Run("broken padding", func(t *testing.T) {
		for _, b := range broken {
			Dbg("block: %v", b)
			if _, err := PKCSUnpad(b, 16); err == nil {
				t.Fatalf("expecting error while unpadding %v", b)
			}
		}
	})
}
