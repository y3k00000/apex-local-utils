package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"core"

	"github.com/lafriks/go-shamir"
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
	return "", errors.New("interface not found")
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
		return "", errors.New("findInterfaceHWAddr failed: " + err.Error())
	}
	return mac, nil
}

func getAsusWifiMac() (string, error) {
	// return "c8:cb:9e:f8:e5:53", nil
	mac, err := findInterfaceHWAddr("wlo1")
	if err != nil {
		return "", errors.New("findInterfaceHWAddr failed: " + err.Error())
	}
	return mac, nil
}

func onboardMAC(ethMac string, wifiMac string) (result core.OnboardResponse, err error) {
	// return core.OnboardResponse{Result: 0, Message: "Success"}, nil
	ethMac_encrypted, err := core.AesGcmEncrypt(ethMac)
	if err != nil {
		return
	}
	wifiMac_encrypted, err := core.AesGcmEncrypt(wifiMac)
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
		ERR_UNKNOWN     = -6
	)
	var err error
	var msg string
	var result int = ERR_UNKNOWN
	var onboard_response core.OnboardResponse
	debug := len(os.Args) > 1 && os.Args[1] == "debug"
	defer func() {
		exit_code := 0
		if err != nil {
			msg = err.Error()
			exit_code = 1
		}
		output, err := json.Marshal(map[string]interface{}{"msg": msg, "result": result, "data": onboard_response})
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", output)
		os.Exit(exit_code)
	}()
	// testAesDecrypt()
	// testListInterfaces()
	mac, getMacErr := getAsusEthMac()
	if getMacErr != nil {
		err = getMacErr
		result = ERR_DEVICE_INFO
		// mac = "00:00:00:00:00:00"
		return
	}
	wifiMac, getMacErr := getAsusWifiMac()
	if getMacErr != nil {
		err = getMacErr
		result = ERR_DEVICE_INFO
		// wifiMac = "00:00:00:00:00:00"
		return
	}
	onboard_response, onBoardErr := onboardMAC(mac, wifiMac)
	if onBoardErr != nil {
		err = onBoardErr
		result = ERR_REGISTER
		return
	} else if onboard_response.Result != 0 {
		result = ERR_REGISTER
		return
	}
	device_info, deviceInfoMarshalErr := json.Marshal(map[string]string{"mac": mac, "wifi-mac": wifiMac})
	if deviceInfoMarshalErr != nil {
		err = deviceInfoMarshalErr
		result = ERR_DEVICE_INFO
		return
	}
	device_info_encrypted, deviceInfoEncryptErr := core.AesGcmEncrypt(string(device_info))
	if deviceInfoEncryptErr != nil {
		err = deviceInfoEncryptErr
		result = ERR_ENCRYPT
		return
	}
	device_info_encrypted_raw := []byte(device_info_encrypted)
	const DEVICE_INFO_SPLITS = 10
	splits, deviceInfoSplitErr := shamir.Split(device_info_encrypted_raw, DEVICE_INFO_SPLITS, 4)
	if deviceInfoSplitErr != nil {
		err = deviceInfoSplitErr
		result = ERR_DEVICE_INFO
		return
	}
	for i, split := range splits {
		deviceInfoFileName := core.DeviceInfoFileName(i)
		_, deviceInfoFileExistsErr := os.ReadFile(deviceInfoFileName)
		if deviceInfoFileExistsErr == nil {
			if debug {
				fmt.Printf("%s exists, removing\n", deviceInfoFileName)
			}
			deviceInfoFileExistsErr = os.Remove(deviceInfoFileName)
			if deviceInfoFileExistsErr != nil {
				err = deviceInfoFileExistsErr
				result = ERR_FILE_IO
				return
			}
		}
		deviceInfoWriteErr := os.WriteFile(deviceInfoFileName, split, 0644)
		if deviceInfoWriteErr != nil {
			err = deviceInfoWriteErr
			result = ERR_FILE_IO
			return
		}
	}
	device_info_splits := make([][]byte, 0)
	for i := 0; i < DEVICE_INFO_SPLITS; i++ {
		split, deviceInfFileReadErr := os.ReadFile(core.DeviceInfoFileName(i))
		if deviceInfFileReadErr != nil {
			deviceInfFileReadErr = nil
			continue
		}
		device_info_splits = append(device_info_splits, split)
	}
	if len(device_info_splits) < 4 {
		result = ERR_DEVICE_INFO
		return
	}
	// fmt.Printf("length of device_info_splits = %d\n", len(device_info_splits))
	device_info_encrypted_raw, deviceInfoSplitsCheckErr := shamir.Combine(device_info_splits...)
	if deviceInfoSplitsCheckErr != nil {
		err = deviceInfoSplitsCheckErr
		result = ERR_DEVICE_INFO
		return
	}
	device_info_encrypted = string(device_info_encrypted_raw)
	_, deviceInfoDecryptErr := core.AesGcmDecrypt(device_info_encrypted)
	if deviceInfoDecryptErr != nil {
		err = deviceInfoDecryptErr
		result = ERR_ENCRYPT
		return
	}
	// fmt.Println(device_info_encrypted)
	result = SUCCESS
	msg = "Success"
}
