package main

import (
	"fmt"
	"testing"
)

/*
 */

const (
	w = 32
	r = 12
	b = 16
	c = 4
	t = 26
	p = 0xb7e15163
	q = 0x9e3779b9
)

var S [t]int

func ROTL(x, y int) int {
	return x<<(y&(w-1)) | x>>(w-(y&(w-1)))
}

func Encrypt(plainText []int, chiperText *[]int) {

	A := plainText[0] + S[0]
	B := plainText[1] + S[1]

	for i := 0; i < r; i++ {

		A = ROTL(A^B, B) + S[2*i]
		B = ROTL(B^A, A) + S[2*i+1]

	}

	fmt.Println("==========")
	fmt.Println(A, B)

	for k := 0; k < w; k += 8 {
		fmt.Printf("%x", (A>>k)&0xff)
	}
	fmt.Println("=====")
	for k := 0; k < w; k += 8 {
		fmt.Printf("%x", (B>>k)&0xff)
	}

}

func Decrypt(chiperText []int) {

	A := chiperText[0]
	B := chiperText[1]

	for i := r; i > 0; i-- {

		if A < 0 {
			B = ((B - S[2*i+1]) >> 0) ^ A
		} else {
			B = ((B - S[2*i+1]) >> A) ^ A
		}

		if B < 0 {
			A = ((A - S[2*i]) >> 0) ^ B
		} else {
			A = ((A - S[2*i]) >> B) ^ B
		}

	}

	pt := []int{}
	pt[0] = A - S[0]
	pt[1] = B - S[1]

	fmt.Println(pt)
}

func Setup(K []int) {

	var i, j, k int

	u := w / 8

	var A, B int

	var L [c]int

	L[c-1] = 0
	for i := (b - 1); i != -1; i-- {
		L[i/u] = (L[i/u] << 8) + K[i]
	}

	S[0] = p
	for k = 1; k < 3*t; k++ {

		S[i] = ROTL(S[i]+(A+B), 3)
		A = S[i]

		L[j] = ROTL(L[j]+(A+B), A+B)

		i = (i + 1) % t
		j = (j + 1) % c
	}

}

func TestCrypto(tst *testing.T) {
	//	key := []byte{0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15, 0x31, 0x25}
	// plain = 650178B284D197CC
	fmt.Println([]byte{0x65, 0x01, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC})
	Setup([]int{82, 105, 241, 73, 212, 27, 160, 21, 36, 151, 87, 77, 127, 21, 49, 37})
	fmt.Println(S)

	var chiper []int
	Encrypt([]int{101, 1, 120, 178, 132, 209, 151, 204}, &chiper)

	//Decrypt([]int{-8299725257517854719, 1945161710708403300})
}
