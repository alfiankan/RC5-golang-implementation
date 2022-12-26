# RC5-golang-implementation
RC5-golang-implementation simple version from https://github.com/tbb/pyRC5.git

References :
  - https://link.springer.com/content/pdf/10.1007/3-540-60590-8_7.pdf
  - https://github.com/tbb/pyRC5.git

## Encryption
```go

	cobaRC5 := rc5.NewRC532(&rc5.RC5SimpleConfig{
		Key:   []byte("CryptoClassUMS2022"),
		Round: 12,
		Debug: true,
	})

	chiper2 := cobaRC5.Encrypt([]byte("Happy New Year Eve 2023"))

	fmt.Println(chiper2)

	readableChiper := base64.StdEncoding.EncodeToString(chiper2) // encode to base64

	fmt.Println(readableChiper) // output : a2ORTDmgFTMVXiziosxt+IxH1SNFqriEVFV+5kFLuKI=


```

## Decryption
```go

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
	fmt.Println("DECRYPTED", string(decrypted)) // output: Happy New Year Eve 2023


```
