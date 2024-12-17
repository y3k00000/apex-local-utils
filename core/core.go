package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

type DeviceInfo struct {
	Mac     string `json:"mac"`
	WifiMac string `json:"wifi-mac"`
}

type OnboardResponse struct {
	Result  int    `json:"result"`
	Message string `json:"message"`
}

type RegisterResponse struct {
	Result      int    `json:"result"`
	Expire      string `json:"expire"`
	Message     string `json:"message"`
	Left        string `json:"left"`
	License     string `json:"license"`
	LicenseHash string `json:"license_hash"`
}

type License struct {
	Key        string                 `json:"key"`
	DeviceInfo DeviceInfo             `json:"device_info"`
	Expire     string                 `json:"expire"`
	Start      int64                  `json:"start"`
	Left       int                    `json:"left"`
	Meta       map[string]interface{} `json:"meta"`
	MetaHash   string                 `json:"meta_hash"`
}

func AesGcmEncrypt(plain string) (string, error) {
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

func AesGcmDecrypt(encrypted_b64 string) (string, error) {
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

func (response *RegisterResponse) ParseLicense(key []byte, deviceInfo DeviceInfo, start time.Time) (*License, error) {
	expireDecrypted, err := AesGcmDecrypt(response.Expire)
	if err != nil {
		return nil, err
	}
	leftDecrypted, err := AesGcmDecrypt(response.Left)
	if err != nil {
		return nil, err
	}
	leftInt, err := strconv.Atoi(leftDecrypted)
	if err != nil {
		return nil, err
	}
	keyBase64 := base64.URLEncoding.EncodeToString(key)
	licenseDecrypted, err := AesGcmDecrypt(response.License)
	if err != nil {
		return nil, err
	}
	meta := make(map[string]interface{})
	err = json.Unmarshal([]byte(licenseDecrypted), &meta)
	if err != nil {
		return nil, err
	}
	metaHash := response.LicenseHash
	return &License{Key: keyBase64, DeviceInfo: deviceInfo, Expire: expireDecrypted, Start: start.Unix(), Left: leftInt, Meta: meta, MetaHash: metaHash}, nil
}

func (license *License) Encrypt() (string, error) {
	licenseJson, err := json.Marshal(license)
	if err != nil {
		return "", err
	}
	licenseEncrypted, err := AesGcmEncrypt(string(licenseJson))
	if err != nil {
		return "", err
	}
	return licenseEncrypted, nil
}

func (license *License) ParseExpire() (time.Time, error) {
	expire, err := time.Parse("2006-01-02 15:04:05", license.Expire)
	if err != nil {
		return time.Time{}, err
	}
	return expire, nil
}