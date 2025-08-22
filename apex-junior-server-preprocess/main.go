package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

func main() {
	var err error
	defer func() {
		if err != nil {
			panic(err)
		}
	}()
	// copy all files from src into build
	files, err := os.ReadDir(filepath.Join(".", "src"))
	err = os.MkdirAll(filepath.Join(".", "build"), 0755)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		src, err := os.Open(filepath.Join(".", "src", file.Name()))
		if err != nil {
			return
		}
		defer src.Close()
		dst, err := os.Create(filepath.Join(".", "build", file.Name()))
		if err != nil {
			return
		}
		defer dst.Close()
		_, err = io.Copy(dst, src)
		if err != nil {
			return
		}
	}
	src, err := os.ReadFile("build/main.go")
	if err != nil {
		return
	}
	pufDevice, err := OpenPufDevice(true)
	if err != nil {
		return
	}
	secret_id, err := pufDevice.ApiCreateNewPrivate()
	if err != nil {
		return
	}
	secret_id_bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(secret_id_bytes, secret_id)
	secret_id_hex := hex.EncodeToString(secret_id_bytes)
	publics_result, err := pufDevice.ApiCreatePublics(secret_id)
	if err != nil {
		return
	}
	publics_bytes := []byte{0x04}
	publics_bytes = append(publics_bytes, publics_result.PublicX[0:32]...)
	publics_bytes = append(publics_bytes, publics_result.PublicY[0:32]...)
	publics_hex := hex.EncodeToString(publics_bytes)
	newData := bytes.ReplaceAll(src, []byte("PLACEHOLDER_SECRET_ID"), []byte(secret_id_hex))
	newData = bytes.ReplaceAll(newData, []byte("PLACEHOLDER_PUBLICS"), []byte(publics_hex))
	err = os.WriteFile("build/main.go", newData, 0644)
	if err != nil {
		return
	}
}
