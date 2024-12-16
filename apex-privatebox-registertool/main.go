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
	"net/http"
	"os"
	"time"

	"github.com/lafriks/go-shamir"
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
	if len(encrypted) < 12 {
		return "", fmt.Errorf("encrypted data too short")
	}
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

type DeviceInfo struct {
	Mac     string `json:"mac"`
	WifiMac string `json:"wifi-mac"`
}

type RegisterResponse struct {
	Result      int                    `json:"result"`
	Expire      string                 `json:"expire"`
	Message     string                 `json:"message"`
	Left        int                    `json:"left"`
	License     map[string]interface{} `json:"license"`
	LicenseHash string                 `json:"license_hash"`
}

type License struct {
	Key      string                 `json:"key"`
	Expire   string                 `json:"expire"`
	Start    int64                  `json:"start"`
	Left     int                    `json:"left"`
	Meta     map[string]interface{} `json:"meta"`
	MetaHash string                 `json:"meta_hash"`
}

func (response *RegisterResponse) Decrypt() error {
	decrypted, err := aes_gcm_decrypt(response.Expire)
	if err != nil {
		return err
	}
	response.Expire = decrypted
	return nil
}

func registerSerial(ethMac string, serial string, debug bool) (result RegisterResponse, err error) {
	ethMac_encrypted, err := aes_gcm_encrypt(ethMac)
	if err != nil {
		return
	}
	serial_encrypted, err := aes_gcm_encrypt(serial)
	if err != nil {
		return
	}
	post_body_json := map[string]interface{}{"type": "local_apex", "mac": ethMac_encrypted, "serial": serial_encrypted}
	result_string, err := httpPostJson("https://apex.cmoremap.com.tw/pm_apex/bundle_aws.php", post_body_json)
	if debug {
		fmt.Println("register result_string = ", result_string)
		fmt.Printf("register err = %v\n", err)
	}
	if err != nil {
		return
	}
	var unparsedResult RegisterResponse = RegisterResponse{}
	err = json.Unmarshal([]byte(result_string), &unparsedResult)
	if debug {
		fmt.Printf("unparsedResult = %+v\n", unparsedResult)
	}
	result = unparsedResult
	if err != nil || result.Result != 0 {
		return
	}
	if debug {
		fmt.Printf("parsedResult = %+v\n", result)
	}
	err = result.Decrypt()
	if err != nil {
		return
	}
	return
}

func main() {
	const (
		DATA_DIR           = "/etc/apex-privatebox/"
		LICENSE_FILE       = DATA_DIR + "license"
		DEVICE_INFO_SPLITS = 10

		SUCCESS         = 0
		ERR_NETWORK     = -1
		ERR_DEVICE_INFO = -2
		ERR_FILE_IO     = -3
		ERR_REGISTER    = -4
		ERR_ENCRYPT     = -5
		ERR_REGISTERED  = -6
		ERR_INPUT       = -7
		ERR_UNKNOWN     = -8
	)
	var err error
	var msg string
	var key_base64 string
	var result = ERR_UNKNOWN
	var registerResult RegisterResponse
	if len(os.Args) < 2 || os.Args[1] == "" {
		result = ERR_INPUT
		err = fmt.Errorf("provided serial is empty")
		return
	}
	serial := os.Args[1]
	debug := len(os.Args) > 2 && os.Args[2] == "debug"
	defer func() {
		exit_code := 0
		if err != nil {
			msg = err.Error()
			key_base64 = ""
			exit_code = 1
		}
		output, err := json.Marshal(map[string]interface{}{"msg": msg, "result": result, "key": key_base64, "data": registerResult})
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", output)
		os.Exit(exit_code)
	}()
	_, err = os.ReadFile(LICENSE_FILE)
	if err == nil {
		result = ERR_REGISTERED
		err = fmt.Errorf("already registered")
		if debug {
			fmt.Println("already registered")
		}
		return
	} else if !os.IsNotExist(err) {
		result = ERR_FILE_IO
		err = fmt.Errorf("read crypt key failed: %v", err)
		if debug {
			fmt.Println("read crypt key failed")
		}
		return
	}
	device_info_splits := make([][]byte, 0)
	for i := 0; i < DEVICE_INFO_SPLITS; i++ {
		split, err := os.ReadFile(fmt.Sprintf("%sdevice_info_%02d.info", DATA_DIR, i))
		if err != nil {
			err = nil
			continue
		}
		device_info_splits = append(device_info_splits, split)
	}
	if debug {
		fmt.Printf("length of device_info_splits = %d\n", len(device_info_splits))
	}
	device_info_encrypted_raw, err := shamir.Combine(device_info_splits...)
	if err != nil {
		result = ERR_DEVICE_INFO
		err = fmt.Errorf("device info recovery failed: %v", err)
		return
	}
	device_info_encrypted := string(device_info_encrypted_raw)
	if debug {
		fmt.Printf("device_info_encrypted = %s\n", device_info_encrypted)
	}
	device_info_decrypted, err := aes_gcm_decrypt(device_info_encrypted)
	if err != nil {
		result = ERR_ENCRYPT
		err = fmt.Errorf("device info decryption failed: %v", err)
		return
	}
	if debug {
		fmt.Printf("device_info_decrypted = %s\n", device_info_decrypted)
	}
	var device_info DeviceInfo = DeviceInfo{}
	err = json.Unmarshal([]byte(device_info_decrypted), &device_info)
	if err != nil {
		result = ERR_DEVICE_INFO
		err = fmt.Errorf("device info unmarshal failed: %v", err)
		return
	}
	now := time.Now()
	now_epoch := now.Unix()
	registerResult, err = registerSerial(device_info.Mac, serial, debug)
	if debug {
		fmt.Printf("registerResult = %+v\n", registerResult)
	}
	if err != nil || registerResult.Result != 0 {
		result = ERR_REGISTER
		err = fmt.Errorf("register failed: %v", err)
		return
	}
	crypt_key := make([]byte, 32)
	rand.Read(crypt_key)
	key_base64 = base64.URLEncoding.EncodeToString(crypt_key)
	if debug {
		fmt.Println("key_base64 = ", key_base64)
	}
	// TODO: save license to file
	license := License{Key: key_base64}
	license_encrypted, err := aes_gcm_encrypt(key_base64)
	if err != nil {
		result = ERR_ENCRYPT
		err = fmt.Errorf("license encryption failed: %v", err)
		return
	}
	fmt.Println(string(device_info_decrypted))
	err = os.WriteFile(CRYPT_KEY_FILE, []byte(key_encrypted), 0644)
	if err != nil {
		if debug {
			fmt.Printf("write crypt key failed: %v\n", err)
		}
		err = fmt.Errorf("write crypt key failed: %v", err)
		result = ERR_FILE_IO
		return
	}
	if debug {
		fmt.Println("register success, serial = ", serial)
	}
	result = SUCCESS
	msg = fmt.Sprintf("register success, serial = %s", serial)
}
