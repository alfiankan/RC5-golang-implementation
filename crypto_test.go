package main

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/alfiankan/rc5/rc5"
	"github.com/stretchr/testify/assert"
)

func BenchmarkRC5Decrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {

		cobaRC5 := rc5.NewRC532(&rc5.RC5SimpleConfig{
			Key:   []byte("CryptoClassUMS2022"),
			Round: 12,
		})

		chiper2 := cobaRC5.Encrypt([]byte("Happy New Year Eve 2023"))

		assert.Equal(b, "a2ORTDmgFTMVXiziosxt+IxH1SNFqriEVFV+5kFLuKI=", base64.StdEncoding.EncodeToString(chiper2))

	}
}

func TestRC5Encrypt(t *testing.T) {

	cobaRC5 := rc5.NewRC532(&rc5.RC5SimpleConfig{
		Key:   []byte("CryptoClassUMS2022"),
		Round: 12,
		Debug: true,
	})

	chiper2 := cobaRC5.Encrypt([]byte("Happy New Year Eve 2023"))

	fmt.Println(chiper2)

	readableChiper := base64.StdEncoding.EncodeToString(chiper2)

	fmt.Println(readableChiper)

	assert.Equal(t, "a2ORTDmgFTMVXiziosxt+IxH1SNFqriEVFV+5kFLuKI=", readableChiper)

	byteChiper, err := base64.StdEncoding.DecodeString("a2ORTDmgFTMVXiziosxt+IxH1SNFqriEVFV+5kFLuKI=")
	assert.Nil(t, err)

	decrypted := cobaRC5.Decrypt(byteChiper)

	assert.Equal(t, "Happy New Year Eve 2023", string(decrypted))

}

func TestRC5Decrypt(t *testing.T) {

	cobaRC5 := rc5.NewRC532(&rc5.RC5SimpleConfig{
		Key:   []byte("CryptoClassUMS2022"),
		Round: 12,
		Debug: true,
	})

	byteChiper, err := base64.StdEncoding.DecodeString("a2ORTDmgFTMVXiziosxt+IxH1SNFqriEVFV+5kFLuKI=")
	if err != nil {
		panic(err)
	}

	decrypted := cobaRC5.Decrypt(byteChiper)
	fmt.Println("DECRYPTED", string(decrypted))
	assert.Equal(t, "Happy New Year Eve 2023", string(decrypted))

}
