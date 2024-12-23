package main

import (
	"core"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

func main() {
	const (
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
	var outputToken string
	var result = ERR_UNKNOWN
	defer func() {
		exit_code := 0
		message := msg
		if err != nil {
			message = err.Error()
			license = nil
			exit_code = 1
		}
		result := map[string]interface{}{"msg": message, "result": result}
		if license != nil {
			result["license"] = license.Meta
			result["expire"] = license.Expire
			result["license_hash"] = license.MetaHash
			if outputToken != "" {
				result["key"] = license.Key
				result["token"] = outputToken
			}
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
		err = errors.New("no token provided")
		return
	}
	lastToken := os.Args[1]
	license_data, readErr := os.ReadFile(core.GetLicenseFilePath(836))
	if debug {
		fmt.Println("license_data = ", license_data)
		fmt.Println("lastToken = ", lastToken)
	}
	if readErr != nil {
		if os.IsNotExist(readErr) {
			result = ERR_NOT_REGISTERED
			if debug {
				fmt.Println("license key file not found")
			}
			err = errors.New("license file not found")
		} else {
			result = ERR_FILE_IO
			if debug {
				fmt.Println("read license failed: ", readErr)
			}
			err = errors.New("read license failed")
		}
		return
	}
	license, decryptLicenseErr := core.DecryptLicense(string(license_data))
	if decryptLicenseErr != nil {
		result = ERR_DECRYPT
		if debug {
			fmt.Println("decrypt license failed: ", string(license_data))
		}
		err = errors.New("decrypt license failed: " + decryptLicenseErr.Error())
		return
	}
	if debug {
		fmt.Println("debug license = ", license)
	}
	nextToken, nextTokenErr := license.NextToken(&lastToken)
	if debug {
		fmt.Println("debug lastToken = ", lastToken)
		fmt.Println("debug nextTokenErr = ", nextTokenErr)
		fmt.Println("debug nextToken = ", nextToken)
	}
	if nextTokenErr != nil {
		if debug {
			fmt.Println("nextTokenErr = ", nextTokenErr)
		}
		if core.IsDecryptError(nextTokenErr) {
			result = ERR_DECRYPT
			if debug {
				fmt.Println("decrypt token failed: ", lastToken)
			}
			err = errors.New("decrypt token failed")
		} else if core.IsExpiredError(nextTokenErr) {
			result = ERR_EXPIRED
			if debug {
				fmt.Println("license expired")
			}
			err = errors.New("license expired")
		} else {
			result = ERR_UNKNOWN
			if debug {
				fmt.Println("unknown error: ", nextTokenErr)
			}
			err = errors.New("unknown error")
		}
		return
	} else if nextToken == "" {
		result = ERR_EXPIRED
		err = errors.New("license expired")
		return
	}
	outputToken = nextToken
	if debug {
		fmt.Println("debug outputToken = ", outputToken)
	}
	result = SUCCESS
	msg = "success"
}
