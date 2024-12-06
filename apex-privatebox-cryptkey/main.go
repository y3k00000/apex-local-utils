package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// func findInterfaceHWAddr(name string) (hwAddr string, err error) {
// 	interfaces, err := net.Interfaces()
// 	if err != nil {
// 		return "", err
// 	}
// 	for _, i := range interfaces {
// 		if i.Name == name {
// 			return i.HardwareAddr.String(), nil
// 		}
// 	}
// 	return "", fmt.Errorf("interface not found")
// }

// func aes_gcm_encrypt(plain string) (string, error) {
// 	// plain := "hello world"
// 	key_hex := "64cb5d3131ce0122f858ea27ea9ce209294cb19caef155132668ace5c4574d43"
// 	key, _ := hex.DecodeString(key_hex)
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}
// 	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
// 	if err != nil {
// 		return "", err
// 	}
// 	nonce := make([]byte, 12)
// 	rand.Read(nonce)
// 	// fmt.Println("nonce = ", hex.EncodeToString(nonce))
// 	encrypted := aesgcm.Seal(nil, nonce, []byte(plain), nil)
// 	// fmt.Println("encrypted = ", hex.EncodeToString(encrypted))
// 	encrypted_b64 := base64.StdEncoding.EncodeToString(append(nonce, encrypted...))
// 	return encrypted_b64, nil
// }

func aes_gcm_decrypt(encrypted_b64 string) (string, error) {
	// encrypted_b64 := "k6aa+zf8zL8c8l8vsX6VJFwWRiii7mYZH+T8D88J5LCz"
	encrypted, _ := base64.StdEncoding.DecodeString(encrypted_b64)
	// fmt.Printf("encrypted.lenth = %d\n", len(encrypted))
	// encrypted_hex := hex.EncodeToString(encrypted)
	// fmt.Println("encrypted = ", encrypted_hex)
	key_hex := "64cb5d3131ce0122f858ea27ea9ce209294cb19caef155132668ace5c4574d43"
	key, _ := hex.DecodeString(key_hex)
	// fmt.Printf("key.lenth = %d\n", len(key))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return "", err
	}
	iv := encrypted[:12]
	// fmt.Println("iv = ", hex.EncodeToString(iv))
	body := encrypted[12:]
	// fmt.Println("body = ", hex.EncodeToString(body))
	decrypted, err := aesgcm.Open(nil, iv, body, nil)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
	// fmt.Println(string(decrypted))
}

// func httpGet(url string) (string, error) {
// 	resp, err := http.Get(url)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()
// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(body), nil
// }

// func httpPostJson(url string, body map[string]interface{}) (string, error) {
// 	jsonBody, err := json.Marshal(body)
// 	if err != nil {
// 		return "", err
// 	}
// 	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()
// 	result_body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(result_body), nil
// }

func main() {
	debug := len(os.Args) > 1 && os.Args[1] == "debug"
	const (
		DATA_DIR       = "/etc/apex-privatebox/"
		CRYPT_KEY_FILE = DATA_DIR + "crypt_key"

		SUCCESS          = 0
		ERR_FILE_IO      = -1
		ERR_DECRYPT      = -2
		ERR_NOT_RESTERED = -3
		ERR_UNKNOWN      = -4
	)
	var err error
	var msg string
	var key_base64 string
	var result = ERR_UNKNOWN
	defer func() {
		exit_code := 0
		if err != nil {
			msg = err.Error()
			key_base64 = ""
			exit_code = 1
		}
		output, err := json.Marshal(map[string]interface{}{"msg": msg, "result": result, "key": key_base64})
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", output)
		os.Exit(exit_code)
	}()
	crypt_key_data, err := os.ReadFile(CRYPT_KEY_FILE)
	if debug {
		fmt.Println("crypt_key_data = ", crypt_key_data)
	}
	if err != nil {
		if os.IsNotExist(err) {
			if debug {
				fmt.Println("crypt key file not found")
			}
			result = ERR_NOT_RESTERED
			err = fmt.Errorf("crypt key file not found: %v", err)
		} else {
			result = ERR_FILE_IO
			if debug {
				fmt.Println("read crypt key failed: ", err)
			}
			err = fmt.Errorf("read crypt key failed: %v", err)
		}
		return
	}
	key_base64, err = aes_gcm_decrypt(string(crypt_key_data))
	if debug {
		fmt.Println("key_base64 = ", key_base64)
	}
	if err != nil {
		result = ERR_DECRYPT
		err = fmt.Errorf("crypt key decryption failed: %v", err)
		return
	}
	result = SUCCESS
	msg = "success"
}
