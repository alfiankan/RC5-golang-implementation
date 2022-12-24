package rc5

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

var (
	w    = 32                                    // word plaintext size is 32 bit or 4 byte each (8 byte)
	mod  = int(math.Pow(float64(2), float64(w))) // using an arithmetic progression modulo w determined by the magic constants
	mask = mod - 1
)

// magic constant for 32 bit
const (
	p = 0xb7e15163
	q = 0x9e3779b9
)

func modulo(a, b int) int {
	return (a%b + b) % b
}

func shiftLeft(val, n int) int {
	n = modulo(n, w)
	return ((val << n) & mask) | ((val & mask) >> (w - n))
}

func shiftRight(val, n int) int {
	n = modulo(n, w)
	return ((val & mask) >> n) | (val << (w - n) & mask)
}

type RC5 struct {
	key []byte // key
	r   int    // round
	t   int    // length of expanded table
	b   int    // length of key
	S   []int  // expanded table
	u   int    // word size
	c   int    // number of words in key
}

type RC5SimpleConfig struct {
	Key   []byte
	Round int
}

func NewRC532(config *RC5SimpleConfig) *RC5 {

	instance := &RC5{
		key: config.Key,
		r:   config.Round,
		t:   2 * (config.Round + 1),
		b:   len(config.Key),
		u:   w / 8,
	}
	instance.c = int(math.Ceil(float64(instance.b) / float64(instance.u)))
	instance.S = make([]int, instance.t)

	// make L table
	L := make([]int, instance.c)

	for i := (instance.b - 1); i >= 0; i-- {
		L[i/instance.u] = (L[i/instance.u] << 8) + int(instance.key[i])
	}

	for i := 0; i < instance.t; i++ {
		instance.S[i] = modulo((p + (q * i)), mod)
	}

	i := 0
	j := 0
	A := 0
	B := 0

	for k := 0; k < 3*int(math.Max(float64(instance.c), float64(instance.t))); k++ {
		instance.S[i] = shiftLeft((instance.S[i] + A + B), 3)
		A = instance.S[i]
		L[j] = shiftLeft((L[j] + A + B), (A + B))
		B = L[j]

		i = modulo((i + 1), instance.t)
		j = modulo((j + 1), instance.c)

	}

	return instance
}

func (this *RC5) GetExpandedKeys() []int {
	return this.S
}

func (this *RC5) Encrypt(plainText []byte) (chiper []byte) {
	A := int(binary.LittleEndian.Uint32([]byte(plainText[:4])))

	B := int(binary.LittleEndian.Uint32([]byte(plainText[4:])))

	fmt.Println(plainText[:4], []byte(plainText[:4]), A)
	fmt.Println(plainText[4:], []byte(plainText[4:]), B)

	A = modulo((A + this.S[0]), mod)

	B = modulo((B + this.S[1]), mod)

	for i := 1; i <= this.r; i++ {
		A = modulo((shiftLeft(A^B, B) + this.S[2*i]), mod)
		B = modulo((shiftLeft(B^A, A) + this.S[2*i+1]), mod)
	}

	cp1 := big.NewInt(int64(A)).Bytes()
	cp2 := big.NewInt(int64(B)).Bytes()

	fmt.Println("CHIPER_TEXT : ", cp1, cp2)

	return
}
