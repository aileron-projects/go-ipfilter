package ipfilter

import (
	"slices"
	"testing"

	"github.com/aileron-projects/go-tester"
)

func flipLowerBits(ip []byte, n int) []byte {
	b := slices.Clone(ip)
	if n < 0 || n > len(b)*8 {
		panic("invalid input")
	}
	bytePos := n / 8
	bitPos := n % 8
	if bitPos != 0 {
		mask := byte((1 << (8 - bitPos)) - 1)
		b[bytePos] ^= mask
		bytePos++
	}
	for i := bytePos; i < len(b); i++ {
		b[i] = ^b[i]
	}
	return b
}

func TestTrieNode_ipv4(t *testing.T) {
	t.Parallel()
	v4Zero := []byte{0, 0, 0, 0}
	v4Max := []byte{255, 255, 255, 255}
	t.Run("zero node", func(t *testing.T) {
		node := &rootNode{}
		tester.AssertEqual(t, false, node.contains(v4Zero))
		tester.AssertEqual(t, false, node.contains(v4Max))
	})
	t.Run("0 bits", func(t *testing.T) {
		node := &rootNode{}
		node.add(0, []byte{0, 0, 0, 1})
		for bits := range 8*4 + 1 {
			tester.AssertEqual(t, true, node.contains(flipLowerBits(v4Zero, bits)))
			tester.AssertEqual(t, true, node.contains(flipLowerBits(v4Max, bits)))
		}
	})
	t.Run("max bits", func(t *testing.T) {
		node := &rootNode{}
		node.add(32, []byte{127, 0, 0, 1})
		for bits := range 8*4 + 1 {
			tester.AssertEqual(t, false, node.contains(flipLowerBits(v4Zero, bits)))
			tester.AssertEqual(t, false, node.contains(flipLowerBits(v4Max, bits)))
		}
		tester.AssertEqual(t, true, node.contains([]byte{127, 0, 0, 1}))
	})
	t.Run("any bits v4Zero", func(t *testing.T) {
		for bits := 1; bits <= 8*4; bits++ {
			node := &rootNode{}
			node.add(bits, v4Zero)
			for i := bits; i <= 32; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, true, node.contains(flipLowerBits(v4Zero, i)))
			}
			for i := range bits {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v4Zero, i)))
			}
			for i := 1; i <= 32; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v4Max, i)))
			}
		}
	})
	t.Run("any bits v4Max", func(t *testing.T) {
		for bits := 1; bits <= 8*4; bits++ {
			node := &rootNode{}
			node.add(bits, v4Max)
			for i := bits; i <= 32; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, true, node.contains(flipLowerBits(v4Max, i)))
			}
			for i := range bits {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v4Max, i)))
			}
			for i := 1; i <= 32; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v4Zero, i)))
			}
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		node := &rootNode{}
		node.add(16, []byte{127, 0, 0, 1})
		node.add(16, []byte{127, 0, 0, 1})
		tester.AssertEqual(t, true, node.contains([]byte{127, 0, 0, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{127, 1, 0, 1}))
	})
	t.Run("parent child", func(t *testing.T) {
		node := &rootNode{}
		node.add(16, []byte{127, 0, 0, 1})
		node.add(24, []byte{127, 1, 0, 1})
		tester.AssertEqual(t, true, node.contains([]byte{127, 0, 0, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{127, 0, 1, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{127, 1, 0, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{127, 1, 1, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{127, 2, 0, 1}))
	})
	t.Run("child parent", func(t *testing.T) {
		node := &rootNode{}
		node.add(24, []byte{127, 1, 0, 1})
		node.add(16, []byte{127, 0, 0, 1})
		tester.AssertEqual(t, true, node.contains([]byte{127, 0, 0, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{127, 0, 1, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{127, 1, 0, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{127, 1, 1, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{127, 2, 0, 1}))
	})
	t.Run("invalid bits -1", func(t *testing.T) {
		node := &rootNode{}
		node.add(-1, v4Zero)
		tester.AssertEqual(t, false, node.contains(v4Zero))
		tester.AssertEqual(t, false, node.contains(v4Max))
	})
	t.Run("invalid bits max+1", func(t *testing.T) {
		node := &rootNode{}
		node.add(8*4+1, v4Zero)
		tester.AssertEqual(t, false, node.contains(v4Zero))
		tester.AssertEqual(t, false, node.contains(v4Max))
	})
}

func TestTrieNode_ipv6(t *testing.T) {
	t.Parallel()
	v6Zero := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	v6Max := []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	t.Run("zero node", func(t *testing.T) {
		node := &rootNode{}
		tester.AssertEqual(t, false, node.contains(v6Zero))
		tester.AssertEqual(t, false, node.contains(v6Max))
	})
	t.Run("0 bits", func(t *testing.T) {
		node := &rootNode{}
		node.add(0, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		for bits := range 8*16 + 1 {
			tester.AssertEqual(t, true, node.contains(flipLowerBits(v6Zero, bits)))
			tester.AssertEqual(t, true, node.contains(flipLowerBits(v6Max, bits)))
		}
	})
	t.Run("max bits", func(t *testing.T) {
		node := &rootNode{}
		node.add(8*16, []byte{127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		for bits := range 8*16 + 1 {
			tester.AssertEqual(t, false, node.contains(flipLowerBits(v6Zero, bits)))
			tester.AssertEqual(t, false, node.contains(flipLowerBits(v6Max, bits)))
		}
		tester.AssertEqual(t, true, node.contains([]byte{127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}))
	})
	t.Run("any bits v6Zero", func(t *testing.T) {
		for bits := 1; bits <= 8*16; bits++ {
			node := &rootNode{}
			node.add(bits, v6Zero)
			for i := bits; i <= 8*16; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, true, node.contains(flipLowerBits(v6Zero, i)))
			}
			for i := range bits {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v6Zero, i)))
			}
			for i := 1; i <= 8*16; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v6Max, i)))
			}
		}
	})
	t.Run("any bits v6Max", func(t *testing.T) {
		for bits := 1; bits <= 8*16; bits++ {
			node := &rootNode{}
			node.add(bits, v6Max)
			for i := bits; i <= 8*16; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, true, node.contains(flipLowerBits(v6Max, i)))
			}
			for i := range bits {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v6Max, i)))
			}
			for i := 1; i <= 8*16; i++ {
				t.Log("bits=", bits, "target=", i)
				tester.AssertEqual(t, false, node.contains(flipLowerBits(v6Zero, i)))
			}
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		node := &rootNode{}
		node.add(8*15, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		node.add(8*15, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}))
	})
	t.Run("parent child", func(t *testing.T) {
		node := &rootNode{}
		node.add(8*14, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
		node.add(8*15, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1})
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}))
	})
	t.Run("child parent", func(t *testing.T) {
		node := &rootNode{}
		node.add(8*15, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1})
		node.add(8*14, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1}))
		tester.AssertEqual(t, true, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 1}))
		tester.AssertEqual(t, false, node.contains([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}))
	})
	t.Run("invalid bits -1", func(t *testing.T) {
		node := &rootNode{}
		node.add(-1, v6Zero)
		tester.AssertEqual(t, false, node.contains(v6Zero))
		tester.AssertEqual(t, false, node.contains(v6Max))
	})
	t.Run("invalid bits max+1", func(t *testing.T) {
		node := &rootNode{}
		node.add(8*16+1, v6Zero)
		tester.AssertEqual(t, false, node.contains(v6Zero))
		tester.AssertEqual(t, false, node.contains(v6Max))
	})
}
