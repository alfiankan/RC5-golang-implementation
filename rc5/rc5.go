package rc5

import (
	"encoding/binary"
	"log"
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
	key   []byte // key
	r     int    // round
	t     int    // length of expanded table
	b     int    // length of key
	S     []int  // expanded table
	u     int    // word size
	c     int    // number of words in key
	debug bool
}

type RC5SimpleConfig struct {
	Key   []byte
	Round int
	Debug bool
}

func NewRC532(config *RC5SimpleConfig) *RC5 {
	instance := &RC5{
		key:   config.Key,
		r:     config.Round,
		t:     2 * (config.Round + 1),
		b:     len(config.Key),
		u:     w / 8,
		debug: config.Debug,
	}
	instance.c = int(math.Ceil(float64(instance.b) / float64(instance.u)))

	// make L table
	L := make([]int, instance.c)

	for i := (instance.b - 1); i >= 0; i-- {
		L[i/instance.u] = (L[i/instance.u] << 8) + int(instance.key[i])
	}

	instance.S = make([]int, instance.t)

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

func (this *RC5) EncryptBlock(plainText []byte) (chiper []byte) {
	A := int(binary.LittleEndian.Uint32([]byte(plainText[:4])))

	B := int(binary.LittleEndian.Uint32([]byte(plainText[4:])))

	A = modulo((A + this.S[0]), mod)
	B = modulo((B + this.S[1]), mod)

	for i := 1; i <= this.r; i++ {
		A = modulo((shiftLeft(A^B, B) + this.S[2*i]), mod)
		B = modulo((shiftLeft(B^A, A) + this.S[2*i+1]), mod)
	}

	cp1 := big.NewInt(int64(A)).Bytes()
	cp2 := big.NewInt(int64(B)).Bytes()

	cp1 = append(cp1, cp2...)
	chiper = cp1
	return
}

func (this *RC5) DecryptBlock(chipertext []byte) (plainText []byte) {

	A := int(binary.BigEndian.Uint32(chipertext[:4]))

	B := int(binary.BigEndian.Uint32(chipertext[4:]))

	for i := this.r; i >= 1; i-- {
		B = shiftRight((B-this.S[2*i+1]), int(A)) ^ A
		A = shiftRight((A-this.S[2*i]), int(B)) ^ B
	}

	B = modulo((B - this.S[1]), mod)
	A = modulo((A - this.S[0]), mod)

	decrypted1 := big.NewInt(int64(A)).Bytes()
	decrypted2 := big.NewInt(int64(B)).Bytes()

	for i := len(decrypted1) - 1; i >= 0; i-- {
		plainText = append(plainText, decrypted1[i])
	}

	for i := len(decrypted2) - 1; i >= 0; i-- {
		plainText = append(plainText, decrypted2[i])
	}

	return
}

func (this *RC5) Encrypt(plainText []byte) (chiperText []byte) {

	pad := len(plainText) % 8

	plainText = append(plainText, make([]byte, pad)...)

	for i := 0; i < len(plainText); i += 8 {
		chiperText = append(chiperText, this.EncryptBlock(plainText[i:i+8])...)
	}

	return
}

func (this *RC5) Decrypt(chiperText []byte) (plainText []byte) {
	for i := 0; i < len(chiperText); i += 8 {
		plainText = append(plainText, this.DecryptBlock(chiperText[i:i+8])...)
	}
	return
}
