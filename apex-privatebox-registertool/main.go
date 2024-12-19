package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Key", "HsWHbfqtCPcVMRxvVwqP8NeUpTbF4sz6")
	resp, err := http.DefaultClient.Do(request)
	// resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
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

// func pseudoResponse() (string, error) {
// 	expoire_encrypted, _ := core.AesGcmEncrypt("2025-10-10 00:00:00")
// 	left_encrypted, _ := core.AesGcmEncrypt(fmt.Sprintf("%d", 720*24*60*60))
// 	license := map[string]interface{}{"seller": "順發3D", "name": "華碩電惱", "total_pieces": 1000}
// 	license_json, _ := json.Marshal(license)
// 	license_encrypted, _ := core.AesGcmEncrypt(string(license_json))
// 	license_hash := sha256.Sum256(license_json)
// 	response := core.RegisterResponse{Result: 0, Expire: expoire_encrypted, Left: left_encrypted, License: license_encrypted, LicenseHash: base64.URLEncoding.EncodeToString(license_hash[:]), Message: "0"}
// 	response_json, _ := json.Marshal(response)
// 	return string(response_json), nil
// }

func registerSerial(ethMac string, serial string, debug bool) (result *core.RegisterResponse, err error) {
	ethMac_encrypted, err := core.AesGcmEncrypt(ethMac)
	if err != nil {
		return
	}
	serial_encrypted, err := core.AesGcmEncrypt(serial)
	if err != nil {
		return
	}
	post_body_json := map[string]interface{}{"type": "local_apex", "mac": ethMac_encrypted, "serial": serial_encrypted}
	result_string, err := httpPostJson("https://apex.cmoremap.com.tw/pm_apex/bundle_aws.php", post_body_json)
	// result_string, err := pseudoResponse()
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
	var err error = nil
	var msg string
	var license *core.License = nil
	var result = ERR_UNKNOWN
	var registerResult *core.RegisterResponse
	defer func() {
		exit_code := 0
		message := msg
		if err != nil {
			message = err.Error()
			license = nil
			exit_code = 1
		}
		outputContent := map[string]interface{}{"msg": message, "result": result}
		if license != nil {
			outputContent["license"] = license.Meta
			outputContent["expire"] = license.Expire
			outputContent["license_hash"] = license.MetaHash
			nextToken, err := license.NextToken(nil)
			if err != nil {
				panic(err)
			}
			outputContent["token"] = nextToken
		}
		output, err := json.Marshal(outputContent)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", output)
		os.Exit(exit_code)
	}()
	if len(os.Args) < 2 || os.Args[1] == "" {
		result = ERR_INPUT
		err = errors.New("provided serial is empty")
		return
	}
	serial := os.Args[1]
	debug := len(os.Args) > 2 && os.Args[2] == "debug"
	_, licenseReadErr := os.ReadFile(LICENSE_FILE)
	if licenseReadErr == nil {
		result = ERR_REGISTERED
		err = errors.New("already registered")
		if debug {
			fmt.Println("already registered")
		}
		return
	} else if !os.IsNotExist(licenseReadErr) {
		result = ERR_FILE_IO
		if debug {
			fmt.Println("read crypt key failed")
		}
		err = errors.New("read crypt key failed")
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
	device_info_encrypted_raw, deviceInfoMergeErr := shamir.Combine(device_info_splits...)
	if deviceInfoMergeErr != nil {
		result = ERR_DEVICE_INFO
		if debug {
			fmt.Printf("device info recovery failed: %v\n", deviceInfoMergeErr)
		}
		err = errors.New("device info recovery failed")
		return
	}
	device_info_encrypted := string(device_info_encrypted_raw)
	if debug {
		fmt.Printf("device_info_encrypted = %s\n", device_info_encrypted)
	}
	device_info_decrypted, deviceInfoDecryptErr := core.AesGcmDecrypt(device_info_encrypted)
	if deviceInfoDecryptErr != nil {
		result = ERR_ENCRYPT
		if debug {
			fmt.Printf("device info decryption failed: %v\n", deviceInfoDecryptErr)
		}
		err = errors.New("device info decryption failed")
		return
	}
	if debug {
		fmt.Printf("device_info_decrypted = %s\n", device_info_decrypted)
	}
	var device_info core.DeviceInfo = core.DeviceInfo{}
	deviceInfoUnmarshalErr := json.Unmarshal([]byte(device_info_decrypted), &device_info)
	if deviceInfoUnmarshalErr != nil {
		result = ERR_DEVICE_INFO
		if debug {
			fmt.Printf("device info unmarshal failed: %v\n", deviceInfoUnmarshalErr)
		}
		err = errors.New("device info unmarshal failed")
		return
	}
	registerResult, registerErr := registerSerial(device_info.Mac, serial, debug)
	if debug {
		fmt.Printf("registerResult = %+v\n", registerResult)
	}
	if registerErr != nil || registerResult.Result != 0 {
		result = ERR_REGISTER
		if debug {
			fmt.Printf("register failed: %v\n", registerErr)
		}
		err = errors.New("register failed")
		return
	}
	crypt_key := make([]byte, 32)
	rand.Read(crypt_key)
	currentTime := time.Now()
	license, err = registerResult.ParseLicense(crypt_key, device_info, currentTime)
	if err != nil {
		result = ERR_UNKNOWN
		if debug {
			fmt.Printf("license parse failed: %v\n", err)
		}
		err = errors.New("license parse failed")
		return
	}
	if debug {
		fmt.Printf("license = %+v\n", license)
	}
	license_json, licenseMarshalErr := json.Marshal(license)
	if licenseMarshalErr != nil {
		result = ERR_UNKNOWN
		if debug {
			fmt.Printf("license marshal failed: %v\n", licenseMarshalErr)
		}
		err = errors.New("license marshal failed")
		return
	}
	license_encrypted, licenseEncryptErr := core.AesGcmEncrypt(string(license_json))
	if licenseEncryptErr != nil {
		result = ERR_ENCRYPT
		if debug {
			fmt.Printf("license encryption failed: %v\n", licenseEncryptErr)
		}
		err = errors.New("license encryption failed")
		return
	}
	err = os.WriteFile(LICENSE_FILE, []byte(license_encrypted), 0644)
	if err != nil {
		if debug {
			fmt.Printf("write crypt key failed: %v\n", err)
		}
		err = errors.New("write crypt key failed")
		result = ERR_FILE_IO
		return
	}
	if debug {
		fmt.Println("register success, serial = ", serial)
	}
	result = SUCCESS
	msg = fmt.Sprintf("register success, serial = %s", serial)
}
