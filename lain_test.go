package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"testing"
	"unsafe"

	"github.com/alfiankan/rc5/rc5"
)

const (
	w2 = 32
)

var mod = math.Pow(float64(2), float64(w2))

func RoToLeft(val, n int) int {
	n = modulo(n, w2)
	mask := int(math.Pow(float64(2), float64(w2))) - 1
	return ((val << n) & mask) | ((val & mask) >> (w2 - n))
}

func RoToRight(val, n int) int {
	n = modulo(n, w2)
	mask := int(math.Pow(float64(2), float64(w2))) - 1

	return ((val & mask) >> n) | (val << (w2 - n) & mask)
}

func modulo(a, b int) int {
	return (a%b + b) % b
}

func IntToByteArray(num int64, size int) []byte {
	arr := make([]byte, size)
	for i := 0; i < size; i++ {
		byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&num)) + uintptr(i)))
		arr[i] = byt
	}
	return arr
}

func TestHelloWorld(tst *testing.T) {

	key := []byte("2023Makmur\n")
	plainText := "alfiann\n"
	// calculate bits
	bits := len(plainText) * 8
	fmt.Println(bits)

	w := 32
	r := 12
	b := len(key)

	fmt.Println(w, r, b)

	// converting byte to word

	u := w / 8
	c := int(math.Ceil(float64(b) / float64(u)))
	fmt.Println("u", u, "c", c)

	L := make([]int, c)

	for i := (b - 1); i >= 0; i-- {
		L[i/u] = (L[i/u] << 8) + int(key[i])
	}

	fmt.Println(L)

	// initializing S array

	// magic constant
	p := 0xb7e15163
	q := 0x9e3779b9

	t := 2 * (r + 1)

	S := make([]int, t)

	for i := 0; i < t; i++ {
		S[i] = modulo((p + (q * i)), int(mod))
	}

	// mixing secret key and S array

	i := 0
	j := 0
	A := 0
	B := 0

	for k := 0; k < 3*int(math.Max(float64(c), float64(t))); k++ {
		S[i] = RoToLeft((S[i] + A + B), 3)
		A = S[i]
		L[j] = RoToLeft((L[j] + A + B), (A + B))
		B = L[j]

		i = modulo((i + 1), t)
		j = modulo((j + 1), c)

	}

	fmt.Println(S)
	fmt.Println(L)

	// encryption

	plainA := int(binary.LittleEndian.Uint32([]byte(plainText[:4])))

	plainB := int(binary.LittleEndian.Uint32([]byte(plainText[4:])))

	fmt.Println(plainText[:4], []byte(plainText[:4]), plainA)
	fmt.Println(plainText[4:], []byte(plainText[4:]), plainB)

	plainA = modulo((plainA + S[0]), int(mod))

	plainB = modulo((plainB + S[1]), int(mod))

	for i := 1; i <= r; i++ {
		plainA = modulo((RoToLeft(int(plainA^plainB), int(plainB)) + S[2*i]), int(mod))
		plainB = modulo((RoToLeft(int(plainB^plainA), int(plainA)) + S[2*i+1]), int(mod))
	}

	cp1 := big.NewInt(int64(plainA)).Bytes()
	cp2 := big.NewInt(int64(plainB)).Bytes()

	fmt.Println("CHIPER_TEXT : ", cp1, cp2, plainA, plainB)

	// decryption

	chiperA := plainA

	chiperB := plainB

	for i := r; i >= 1; i-- {
		chiperB = RoToRight((chiperB-S[2*i+1]), int(chiperA)) ^ chiperA
		chiperA = RoToRight((chiperA-S[2*i]), int(chiperB)) ^ chiperB
	}

	fmt.Println(chiperB-S[1], int(mod))

	fmt.Println(chiperA-S[0], int(mod))

	chiperB = modulo((chiperB - S[1]), int(mod))
	chiperA = modulo((chiperA - S[0]), int(mod))

	fmt.Println("AFTER : ", chiperA, chiperB)

	decrypted1 := big.NewInt(int64(chiperA)).Bytes()
	decrypted2 := big.NewInt(int64(chiperB)).Bytes()

	fmt.Println("===========")

	for i := len(decrypted1) - 1; i >= 0; i-- {
		fmt.Printf("%c", decrypted1[i])
	}
	for i := len(decrypted2) - 1; i >= 0; i-- {
		fmt.Printf("%c", decrypted2[i])
	}
	fmt.Println()

}

func TestRc5(t *testing.T) {

	config := rc5.RC5SimpleConfig{}
	config.Key = []byte("2023Makmur\n")
	config.Round = 12

	cobaRC5 := rc5.NewRC532(&config)

	fmt.Println(cobaRC5.GetExpandedKeys())

}
