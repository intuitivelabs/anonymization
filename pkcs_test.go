package anonymization

import (
	"bufio"
	"bytes"
	"os"
	"testing"
)

type BlockPair struct {
	padded   []byte
	unpadded []byte
}

func TestPKCSPad(t *testing.T) {
	debugTestOn = true
	stdout := bufio.NewWriter(os.Stdout)
	oneBlockPairs := [...]BlockPair{
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 5, 5, 5},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 6, 6, 6, 6, 6},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10},
			unpadded: []byte{0, 0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 0, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11},
			unpadded: []byte{0, 0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 0, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
			unpadded: []byte{0, 0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 0, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13},
			unpadded: []byte{0, 0, 0},
		},
		{
			padded:   []byte{0, 0, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14},
			unpadded: []byte{0, 0},
		},
		{
			padded:   []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15},
			unpadded: []byte{0},
		},
	}
	twoBlockPairs := [...]BlockPair{
		{
			padded:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
			unpadded: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	broken := [...][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
	}
	t.Run("only one block un-padding", func(t *testing.T) {
		for _, pair := range oneBlockPairs {
			if u, err := PKCSUnpad(pair.padded, 16); err != nil {
				t.Fatalf("unpadding error: %s", err)
			} else if !bytes.Equal(u, pair.unpadded) {
				t.Fatalf("expected %v got %v", pair.unpadded, u)
			}
		}
	})
	t.Run("only one block padding", func(t *testing.T) {
		for _, pair := range oneBlockPairs {
			if p, err := PKCSPad(pair.unpadded, 16); err != nil {
				t.Fatalf("padding error: %s", err)
			} else if !bytes.Equal(p[0:16], pair.padded) {
				t.Fatalf("expected %v got %v", pair.padded, p[0:16])
			}
		}
	})
	t.Run("two block un-padding", func(t *testing.T) {
		for _, pair := range twoBlockPairs {
			if u, err := PKCSUnpad(pair.padded, 16); err != nil {
				t.Fatalf("unpadding error: %s", err)
			} else if !bytes.Equal(u, pair.unpadded) {
				t.Fatalf("expected %v got %v", pair.unpadded, u)
			}
		}
	})
	t.Run("two block padding", func(t *testing.T) {
		for _, pair := range twoBlockPairs {
			if p, err := PKCSPad(pair.unpadded, 16); err != nil {
				t.Fatalf("padding error: %s", err)
			} else if !bytes.Equal(p[0:32], pair.padded) {
				t.Fatalf("expected %v got %v", pair.padded, p[0:32])
			}
		}
	})
	t.Run("broken padding", func(t *testing.T) {

		for _, b := range broken {
			debugTest(stdout, "block: %v\n", b)
			if _, err := PKCSUnpad(b, 16); err == nil {
				t.Fatalf("expecting error while unpadding %v", b)
			}
		}
	})
	debugTestOn = false
}
