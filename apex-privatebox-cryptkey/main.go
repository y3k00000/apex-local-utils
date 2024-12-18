package main

import (
	"core"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	const (
		DATA_DIR     = "./" // "/etc/apex-privatebox/"
		LICENSE_FILE = DATA_DIR + "license"

		SUCCESS            = 0
		ERR_FILE_IO        = -1
		ERR_DECRYPT        = -2
		ERR_NOT_REGISTERED = -3
		ERR_EXPIRED        = -4
		ERR_INPUT          = -5
		ERR_UNKNOWN        = -6
	)
	var err error
	var msg string
	var license *core.License = nil
	var nextToken *string = nil
	var result = ERR_UNKNOWN
	defer func() {
		exit_code := 0
		if err != nil {
			msg = err.Error()
			license = nil
			exit_code = 1
		}
		result := map[string]interface{}{"msg": msg, "result": result}
		if license != nil {
			result["license"] = license.Meta
			result["expire"] = license.Expire
			result["license_hash"] = license.MetaHash
			result["key"] = license.Key
			result["token"] = nextToken
		}
		output, err := json.Marshal(result)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", output)
		os.Exit(exit_code)
	}()
	debug := len(os.Args) > 2 && os.Args[2] == "debug"
	if len(os.Args) < 2 || os.Args[1] == "" {
		result = ERR_INPUT
		err = fmt.Errorf("no token provided")
		return
	}
	token := &os.Args[1]
	license_data, err := os.ReadFile(LICENSE_FILE)
	if debug {
		fmt.Println("license_data = ", license_data)
	}
	if debug {
		fmt.Println("token = ", token)
	}
	if err != nil {
		if os.IsNotExist(err) {
			if debug {
				fmt.Println("license key file not found")
			}
			result = ERR_NOT_REGISTERED
			err = fmt.Errorf("license file not found: %v", err)
		} else {
			result = ERR_FILE_IO
			if debug {
				fmt.Println("read license failed: ", err)
			}
			err = fmt.Errorf("read license failed: %v", err)
		}
		return
	}
	license, err = core.DecryptLicense(string(license_data))
	if err != nil {
		result = ERR_DECRYPT
		if debug {
			fmt.Println("decrypt license failed: ", string(license_data))
		}
		err = fmt.Errorf("decrypt license failed: %v", err)
		return
	}
	if debug {
		fmt.Println("debug license = ", license)
	}
	*nextToken = license.NextToken(token)
	result = SUCCESS
	msg = "success"
}
