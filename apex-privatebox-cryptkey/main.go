package main

import (
	"core"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	debug := len(os.Args) > 1 && os.Args[1] == "debug"
	const (
		DATA_DIR     = "./" // "/etc/apex-privatebox/"
		LICENSE_FILE = DATA_DIR + "license"

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
	license_data, err := os.ReadFile(LICENSE_FILE)
	if debug {
		fmt.Println("crypt_key_data = ", license_data)
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
	license_decrypted, err := core.AesGcmDecrypt(string(license_data))
	if debug {
		fmt.Println("license_decrypted = ", key_base64)
	}
	if err != nil {
		result = ERR_DECRYPT
		err = fmt.Errorf("crypt key decryption failed: %v", err)
		return
	}
	var license core.License
	err = json.Unmarshal([]byte(license_decrypted), &license)
	if err != nil {
		result = ERR_DECRYPT
		err = fmt.Errorf("crypt key decryption failed: %v", err)
		return
	}
	key_base64 = license.Key
	result = SUCCESS
	msg = "success"
}
