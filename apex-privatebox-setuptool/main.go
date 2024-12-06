package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/corvus-ch/shamir"
)

func findInterfaceHWAddr(name string) (hwAddr string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range interfaces {
		if i.Name == name {
			return i.HardwareAddr.String(), nil
		}
	}
	return "", fmt.Errorf("interface not found")
}

func aes_gcm_encrypt(plain string) (string, error) {
	// plain := "hello world"
	key_hex := "64cb5d3131ce0122f858ea27ea9ce209294cb19caef155132668ace5c4574d43"
	key, _ := hex.DecodeString(key_hex)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	// fmt.Println("nonce = ", hex.EncodeToString(nonce))
	encrypted := aesgcm.Seal(nil, nonce, []byte(plain), nil)
	// fmt.Println("encrypted = ", hex.EncodeToString(encrypted))
	encrypted_b64 := base64.StdEncoding.EncodeToString(append(nonce, encrypted...))
	return encrypted_b64, nil
}

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

func httpGet(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func httpPostJson(url string, body map[string]interface{}) (string, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	result_body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(result_body), nil
}

func getAsusEthMac() (string, error) {
	// return "a0:36:bc:57:47:48", nil
	mac, err := findInterfaceHWAddr("enp3s0")
	if err != nil {
		return "", fmt.Errorf("findInterfaceHWAddr failed: %v, The Device may not be correct", err)
	}
	return mac, nil
}

func getAsusWifiMac() (string, error) {
	// return "c8:cb:9e:f8:e5:53", nil
	mac, err := findInterfaceHWAddr("wlo1")
	if err != nil {
		return "", fmt.Errorf("findInterfaceHWAddr failed: %v, The Device may not be correct", err)
	}
	return mac, nil
}

type RegisterResponse struct {
	Result  int    `json:"result"`
	Message string `json:"message"`
}

func registerMAC(ethMac string, wifiMac string) (result RegisterResponse, err error) {
	ethMac_encrypted, err := aes_gcm_encrypt(ethMac)
	if err != nil {
		return
	}
	wifiMac_encrypted, err := aes_gcm_encrypt(wifiMac)
	if err != nil {
		return
	}
	post_body_json := map[string]interface{}{"type": "local_register", "mac": ethMac_encrypted, "wifi_mac": wifiMac_encrypted}
	result_string, err := httpPostJson("https://apex.cmoremap.com.tw/pm_apex/bundle_aws.php", post_body_json)
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(result_string), &result)
	if err != nil {
		return
	}
	return
}

func main() {
	const (
		SUCCESS         = 0
		ERR_NETWORK     = -1
		ERR_DEVICE_INFO = -2
		ERR_FILE_IO     = -3
		ERR_REGISTER    = -4
		ERR_ENCRYPT     = -5
	)
	var err error
	var msg string
	var result int = SUCCESS
	var register_result RegisterResponse
	defer func() {
		exit_code := 0
		if err != nil {
			msg = err.Error()
			exit_code = 1
		}
		output, err := json.Marshal(map[string]interface{}{"msg": msg, "result": result, "data": register_result})
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", output)
		os.Exit(exit_code)
	}()
	// testAesDecrypt()
	// testListInterfaces()
	mac, err := getAsusEthMac()
	if err != nil {
		result = ERR_DEVICE_INFO
		// mac = "00:00:00:00:00:00"
		// return
	}
	wifiMac, err := getAsusWifiMac()
	if err != nil {
		result = ERR_DEVICE_INFO
		// wifiMac = "00:00:00:00:00:00"
		return
	}
	register_result, err = registerMAC(mac, wifiMac)
	if err != nil {
		result = ERR_REGISTER
		return
	} else if register_result.Result != 0 {
		result = ERR_REGISTER
		return
	}
	device_info, err := json.Marshal(map[string]string{"mac": mac, "wifi-mac": wifiMac})
	if err != nil {
		result = ERR_DEVICE_INFO
		return
	}
	device_info_encrypted, err := aes_gcm_encrypt(string(device_info))
	if err != nil {
		result = ERR_ENCRYPT
		return
	}
	device_info_encrypted_raw := []byte(device_info_encrypted)
	const DEVICE_INFO_SPLITS = 10
	splits, err := shamir.Split(device_info_encrypted_raw, DEVICE_INFO_SPLITS, 4)
	if err != nil {
		result = ERR_DEVICE_INFO
		return
	}
	for i, split := range splits {
		err = os.WriteFile(fmt.Sprintf("device_info_%02d.info", i), split, 0644)
		if err != nil {
			result = ERR_FILE_IO
			return
		}
	}
	device_info_splits := make([][]byte, 0)
	for i := 0; i < DEVICE_INFO_SPLITS; i++ {
		split, err := os.ReadFile(fmt.Sprintf("device_info_%02d.info", i))
		if err != nil {
			err = nil
			continue
		}
		device_info_splits = append(device_info_splits, split)
	}
	if len(device_info_splits) < 4 {
		result = ERR_DEVICE_INFO
		return
	}
	// fmt.Printf("length of device_info_splits = %d\n", len(device_info_splits))
	device_info_encrypted_raw, err = shamir.Combine(device_info_splits...)
	if err != nil {
		result = ERR_DEVICE_INFO
		return
	}
	device_info_encrypted = string(device_info_encrypted_raw)
	_, err = aes_gcm_decrypt(device_info_encrypted)
	if err != nil {
		result = ERR_ENCRYPT
		return
	}
	// fmt.Println(device_info_encrypted)
	msg = "Success"
}
