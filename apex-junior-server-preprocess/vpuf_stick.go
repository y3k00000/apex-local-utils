package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/sstallion/go-hid"
)

type UsbPufDevice struct {
	usbHid *hid.Device
	debug  bool
}

const errorMessageLength = 6

func timeStamp8Bytes() []byte {
	timeStampBuffer := make([]byte, 8)
	timeStamp := time.Now().UnixMilli()
	// timeStampBuffer[0] = byte(timeStamp >> 56)
	// timeStampBuffer[1] = byte(timeStamp >> 48)
	// timeStampBuffer[2] = byte(timeStamp >> 40)
	// timeStampBuffer[3] = byte(timeStamp >> 32)
	// timeStampBuffer[4] = byte(timeStamp >> 24)
	// timeStampBuffer[5] = byte(timeStamp >> 16)
	// timeStampBuffer[6] = byte(timeStamp >> 8)
	// timeStampBuffer[7] = byte(timeStamp)
	binary.BigEndian.PutUint64(timeStampBuffer, uint64(timeStamp)) // equivalent to the above 8 lines
	return timeStampBuffer
}

func OpenPufDevice(debug bool) (*UsbPufDevice, error) {
	device, err := openHidDevice("TPPUF", debug)
	if err != nil {
		device, err = openHidDevice("TPPC", debug)
		if err != nil {
			return nil, err
		}
		return &UsbPufDevice{usbHid: device, debug: debug}, err
	}
	return &UsbPufDevice{usbHid: device, debug: debug}, nil
}

func openHidDevice(name string, debug bool) (*hid.Device, error) {
	matchedDevices := make([]*hid.DeviceInfo, 0)
	hid.Enumerate(0, 0, func(info *hid.DeviceInfo) error {
		if debug {
			fmt.Printf("Device found: %s %s %s\n", info.Path, info.ProductStr, info.SerialNbr)
		}
		if info.ProductStr == name {
			if debug {
				fmt.Printf("Found %s device: %s\n", name, info.Path)
			}
			matchedDevices = append(matchedDevices, info)
		}
		return nil
	})
	if len(matchedDevices) == 0 {
		return nil, fmt.Errorf("no %s devices found", name)
	}
	device, err := hid.OpenPath(matchedDevices[0].Path)
	if err != nil {
		return nil, fmt.Errorf("error opening %s device: %w", name, err)
	}
	return device, nil
}

func isErrorResponse(response []byte, errorWillStartWith []byte) error {
	if bytes.HasPrefix(response, errorWillStartWith) {
		messageStart := len(errorWillStartWith)
		if len(response) < messageStart+errorMessageLength {
			return nil
		}
		errorContent := response[len(errorWillStartWith) : len(errorWillStartWith)+errorMessageLength]
		if !bytes.HasPrefix(errorContent, []byte("E")) {
			return fmt.Errorf("error response: %x", errorContent)
		}
		return errors.New(string(errorContent)) // E00001,E0002,E00003,E00004,E00005,E00006...
	}
	return nil
}

func writeToHidDevice(device *UsbPufDevice, body [][]byte, expectedReads int, errorHeader []byte) ([][]byte, error) {
	for i, b := range body {
		if len(b) > 62 {
			return nil, fmt.Errorf("body[%d] exceeds maximum length of 62 bytes", i)
		}
		writeBuffer := make([]byte, 64)
		copy(writeBuffer, []byte{0x81})
		copy(writeBuffer[1:], body[i])
		writeCount, err := device.usbHid.Write(writeBuffer)
		if err != nil {
			if device.debug {
				fmt.Println("Error writing to HID device:", err)
			}
			return nil, err
		}
		if device.debug {
			fmt.Printf("Wrote %d bytes to HID device\n", writeCount)
		}
		time.Sleep(50 * time.Millisecond)
	}
	readResults := make([][]byte, expectedReads)
	for i := range expectedReads {
		readBuffer := make([]byte, 64)
		readCount := 0
		var err error
		for range 10 {
			readCount, err = device.usbHid.ReadWithTimeout(readBuffer, 2*time.Second)
			if err == nil {
				if device.debug {
					fmt.Println("Successfully read from HID device")
				}
				break
			}
			if device.debug {
				fmt.Println("Error reading from HID device:", err, "retrying...")
			}
		}
		if err != nil {
			if device.debug {
				fmt.Println("Error reading from HID device:", err)
			}
			return nil, err
		}
		if readBuffer[0] != 0x01 {
			if device.debug {
				fmt.Printf("Unexpected response from HID device: %x\n", readBuffer[:readCount])
			}
			return nil, fmt.Errorf("unexpected response from HID device: %x", readBuffer[:readCount])
		}
		if device.debug {
			fmt.Printf("Read %d bytes from HID device\n", readCount)
		}
		err = isErrorResponse(readBuffer[1:readCount], errorHeader)
		if err != nil {
			if device.debug {
				fmt.Println("Error response from HID device:", err)
			}
			return nil, err
		}
		readResults[i] = make([]byte, readCount)
		copy(readResults[i], readBuffer[1:readCount])
	}
	if device.debug {
		fmt.Println("All reads completed successfully")
	}
	return readResults, nil
}

func createErrorHeader(header []byte, emptyLength int) []byte {
	errorHeader := make([]byte, len(header)+emptyLength)
	copy(errorHeader, header)
	for i := len(header); i < len(errorHeader); i++ {
		errorHeader[i] = 0x00
	}
	return errorHeader
}

func (device *UsbPufDevice) ApiCreateUniqueHash(data []byte) ([]byte, error) {
	request := make([]byte, 12)
	copy(request, []byte{0xff, 0xff})
	copy(request[2:], []byte{12})
	copy(request[3:], data)
	if device.debug {
		fmt.Printf("Request: %x\n", request)
	}
	requests := [][]byte{request}
	responses, err := writeToHidDevice(device, requests, 1, createErrorHeader([]byte{0xff, 0xff}, 32))
	if device.debug {
		fmt.Printf("Responses: %x\n", responses)
	}
	response := responses[0][2:34]
	return response, err
}

func (device *UsbPufDevice) ApiCreateNewPrivate() (uint16, error) {
	requestSecretSeed := make([]byte, 32)
	rand.Read(requestSecretSeed)
	requestTimeStamp := timeStamp8Bytes()
	requestSecretSeed = append([]byte{0xfe, 0xfe}, requestSecretSeed...)
	requestTimeStamp = append([]byte{0xfe, 0xff}, requestTimeStamp...)
	requests := [][]byte{
		requestSecretSeed,
		requestTimeStamp,
	}
	if device.debug {
		fmt.Printf("Requests: %x\n", requests)
	}
	responses, err := writeToHidDevice(device, requests, 1, createErrorHeader([]byte{0xfe, 0xff}, 2))
	if err != nil {
		if device.debug {
			fmt.Println("Error in testB:", err)
		}
		return 0, err
	}
	if device.debug {
		fmt.Printf("Response: %x\n", responses)
	}
	return binary.BigEndian.Uint16(responses[0][2:4]), nil
}

type CreatePublicsResponse struct {
	PublicX []byte
	PublicY []byte
}

func (device *UsbPufDevice) ApiCreatePublics(privateId uint16) (*CreatePublicsResponse, error) {
	requestTimeStamp := timeStamp8Bytes()
	requestIdBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(requestIdBytes, privateId)
	requestIdBytes = append([]byte{0xfd, 0xfe}, requestIdBytes...)
	requestTimeStamp = append([]byte{0xfd, 0xff}, requestTimeStamp...)
	requests := [][]byte{
		requestIdBytes,
		requestTimeStamp,
	}
	if device.debug {
		fmt.Printf("Requests: %x\n", requests)
	}
	responses, err := writeToHidDevice(device, requests, 2, createErrorHeader([]byte{0xfd, 0xff}, 32))
	if err != nil {
		if device.debug {
			fmt.Println("Error in testC:", err)
		}
		return nil, err
	}
	if device.debug {
		fmt.Printf("Response: %x\n", responses)
	}
	publicX := responses[0][2:34]
	publicY := responses[1][2:34]
	return &CreatePublicsResponse{
		PublicX: publicX,
		PublicY: publicY,
	}, nil
}

func (device *UsbPufDevice) ApiSharedSecret(privateId uint16, localPublicX [32]byte, localPublicY [32]byte) ([]byte, error) {
	requestTimeStamp := timeStamp8Bytes()
	requestIdBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(requestIdBytes, privateId)
	requestIdBytes = append([]byte{0xfc, 0xfc}, requestIdBytes[0:2]...)
	requestPublicX := append([]byte{0xfc, 0xfd}, localPublicX[0:32]...)
	requestPublicY := append([]byte{0xfc, 0xfe}, localPublicY[0:32]...)
	requestTimeStamp = append([]byte{0xfc, 0xff}, requestTimeStamp[0:8]...)
	requests := [][]byte{
		requestIdBytes,
		requestPublicX,
		requestPublicY,
		requestTimeStamp,
	}
	if device.debug {
		fmt.Printf("Requests: %x\n", requests)
	}
	responses, err := writeToHidDevice(device, requests, 1, createErrorHeader([]byte{0xfc, 0xff}, 32))
	if err != nil {
		if device.debug {
			fmt.Println("Error in testD:", err)
		}
		return nil, err
	}
	if device.debug {
		fmt.Printf("Response: %x\n", responses)
	}
	sharedSecret := responses[0][2:34]
	return sharedSecret, nil
}

type SignMessageResponse struct {
	SignatureR []byte
	SignatureS []byte
}

func (device *UsbPufDevice) ApiSignMessage(privateId uint16, messageHash [32]byte) (*SignMessageResponse, error) {
	requestTimeStamp := timeStamp8Bytes()
	requestIdBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(requestIdBytes, privateId)
	requestIdBytes = append([]byte{0xfb, 0xfd}, requestIdBytes[0:2]...)
	requestMessageHash := append([]byte{0xfb, 0xfe}, messageHash[0:32]...)
	requestTimeStamp = append([]byte{0xfb, 0xff}, requestTimeStamp[0:8]...)
	requests := [][]byte{
		requestIdBytes,
		requestMessageHash,
		requestTimeStamp,
	}
	if device.debug {
		fmt.Printf("Requests: %x\n", requests)
	}
	responses, err := writeToHidDevice(device, requests, 2, createErrorHeader([]byte{0xfb, 0xff}, 32))
	if err != nil {
		if device.debug {
			fmt.Println("Error in testE:", err)
		}
		return nil, err
	}
	if device.debug {
		fmt.Printf("Response: %x\n", responses)
	}
	signatureR := responses[0][2:34]
	signatureS := responses[1][2:34]
	return &SignMessageResponse{
		SignatureR: signatureR,
		SignatureS: signatureS,
	}, nil
}

func (device *UsbPufDevice) Close() error {
	err := device.usbHid.Close()
	device.usbHid = nil
	return err
}
