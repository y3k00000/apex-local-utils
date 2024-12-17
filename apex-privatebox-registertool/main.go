package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"core"

	"github.com/lafriks/go-shamir"
)

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

func pseudoResponse() (string, error) {
	expoire_encrypted, _ := core.AesGcmEncrypt("2025-10-10 00:00:00")
	left_encrypted, _ := core.AesGcmEncrypt(fmt.Sprintf("%d", 720*24*60*60))
	license := map[string]interface{}{"seller": "順發3D", "name": "華碩電惱", "total_pieces": 1000}
	license_json, _ := json.Marshal(license)
	license_encrypted, _ := core.AesGcmEncrypt(string(license_json))
	license_hash := sha256.Sum256(license_json)
	response := core.RegisterResponse{Result: 0, Expire: expoire_encrypted, Left: left_encrypted, License: license_encrypted, LicenseHash: base64.URLEncoding.EncodeToString(license_hash[:]), Message: "0"}
	response_json, _ := json.Marshal(response)
	return string(response_json), nil
}

func registerSerial(ethMac string, serial string, debug bool) (result *core.RegisterResponse, err error) {
	// ethMac_encrypted, err := core.AesGcmEncrypt(ethMac)
	// if err != nil {
	// 	return
	// }
	// serial_encrypted, err := aes_gcore.AesGcmEncryptcm_encrypt(serial)
	// if err != nil {
	// 	return
	// }
	// post_body_json := map[string]interface{}{"type": "local_apex", "mac": ethMac_encrypted, "serial": serial_encrypted}
	// result_string, err := httpPostJson("https://apex.cmoremap.com.tw/pm_apex/bundle_aws.php", post_body_json)
	result_string, err := pseudoResponse()
	if debug {
		fmt.Println("register result_string = ", result_string)
		fmt.Printf("register err = %v\n", err)
	}
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(result_string), &result)
	if debug {
		fmt.Printf("unparsedResult = %+v\n", result)
	}
	if err != nil || result.Result != 0 {
		if debug {
			fmt.Printf("register failed: %v\n%v\n", err, result_string)
		}
		return nil, err
	}
	if debug {
		fmt.Printf("parsedResult = %+v\n", result)
	}
	return
}

func main() {
	const (
		DATA_DIR           = "./"
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
	var license *core.License = nil
	var result = ERR_UNKNOWN
	var registerResult *core.RegisterResponse
	defer func() {
		exit_code := 0
		if err != nil {
			msg = err.Error()
			license = nil
			exit_code = 1
		}
		output, err := json.Marshal(map[string]interface{}{"msg": msg, "result": result, "token": "valid", "data": registerResult})
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", output)
		os.Exit(exit_code)
	}()
	if len(os.Args) < 2 || os.Args[1] == "" {
		result = ERR_INPUT
		err = fmt.Errorf("provided serial is empty")
		return
	}
	serial := os.Args[1]
	debug := len(os.Args) > 2 && os.Args[2] == "debug"
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
	device_info_decrypted, err := core.AesGcmDecrypt(device_info_encrypted)
	if err != nil {
		result = ERR_ENCRYPT
		err = fmt.Errorf("device info decryption failed: %v", err)
		return
	}
	if debug {
		fmt.Printf("device_info_decrypted = %s\n", device_info_decrypted)
	}
	var device_info core.DeviceInfo = core.DeviceInfo{}
	err = json.Unmarshal([]byte(device_info_decrypted), &device_info)
	if err != nil {
		result = ERR_DEVICE_INFO
		err = fmt.Errorf("device info unmarshal failed: %v", err)
		return
	}
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
	license, err = registerResult.ParseLicense(crypt_key, device_info, time.Now())
	if err != nil {
		result = ERR_UNKNOWN
		err = fmt.Errorf("license parse failed: %v", err)
		return
	}
	license_json, err := json.Marshal(license)
	if err != nil {
		result = ERR_UNKNOWN
		err = fmt.Errorf("license marshal failed: %v", err)
		return
	}
	license_encrypted, err := core.AesGcmEncrypt(string(license_json))
	if err != nil {
		result = ERR_ENCRYPT
		err = fmt.Errorf("license encryption failed: %v", err)
		return
	}
	fmt.Println(string(device_info_decrypted))
	err = os.WriteFile(LICENSE_FILE, []byte(license_encrypted), 0644)
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
