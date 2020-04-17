package protocol

import (
	"encoding/binary"
	"math/rand"
	"time"

	"github.com/wwqgtxx/gossr/ssr"
	"github.com/wwqgtxx/gossr/tools"
)

func init() {
	register("auth_sha1_v4", NewAuthSHA1v4)
}

type authSHA1v4 struct {
	ssr.ServerInfoForObfs
	data          *authData
	hasSentHeader bool
	//recvBuffer       []byte
	//recvBufferLength int
}

func NewAuthSHA1v4() IProtocol {
	a := &authSHA1v4{}
	return a
}

func (a *authSHA1v4) SetServerInfo(s *ssr.ServerInfoForObfs) {
	a.ServerInfoForObfs = *s
}

func (a *authSHA1v4) GetServerInfo() (s *ssr.ServerInfoForObfs) {
	return &a.ServerInfoForObfs
}

func (a *authSHA1v4) SetData(data interface{}) {
	if auth, ok := data.(*authData); ok {
		a.data = auth
	}
}

func (a *authSHA1v4) GetData() interface{} {
	if a.data == nil {
		a.data = &authData{}
	}
	return a.data
}

func (a *authSHA1v4) packData(data []byte) (outData []byte) {
	dataLength := len(data)
	randLength := 1
	if dataLength <= 1300 {
		if dataLength > 400 {
			randLength += rand.Intn(128)
		} else {
			randLength += rand.Intn(1024)
		}
	}

	outLength := randLength + dataLength + 8
	outData = make([]byte, outLength)
	// 0~1, out length
	binary.BigEndian.PutUint16(outData[0:2], uint16(outLength&0xFFFF))
	// 2~3, crc of out length
	crc32 := ssr.CalcCRC32(outData, 2, 0xFFFFFFFF)
	binary.LittleEndian.PutUint16(outData[2:4], uint16(crc32&0xFFFF))
	// 4, rand length
	if randLength < 128 {
		outData[4] = uint8(randLength & 0xFF)
	} else {
		outData[4] = uint8(0xFF)
		binary.BigEndian.PutUint16(outData[5:7], uint16(randLength&0xFFFF))
	}
	// rand length+4~out length-4, data
	if dataLength > 0 {
		copy(outData[randLength+4:], data)
	}
	// out length-4~end, adler32 of full data
	adler := ssr.CalcAdler32(outData[:outLength-4])
	binary.LittleEndian.PutUint32(outData[outLength-4:], adler)

	return outData
}

func (a *authSHA1v4) packAuthData(data []byte) (outData []byte) {
	dataLength := len(data)
	randLength := 1
	if dataLength <= 1300 {
		if dataLength > 400 {
			randLength += rand.Intn(128)
		} else {
			randLength += rand.Intn(1024)
		}
	}
	dataOffset := randLength + 4 + 2
	outLength := dataOffset + dataLength + 12 + ssr.ObfsHMACSHA1Len
	outData = make([]byte, outLength)

	a.data.connectionID++
	if a.data.connectionID > 0xFF000000 {
		a.data.clientID = nil
	}
	if len(a.data.clientID) == 0 {
		a.data.clientID = make([]byte, 8)
		rand.Read(a.data.clientID)
		b := make([]byte, 4)
		rand.Read(b)
		a.data.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	// 0-1, out length
	binary.BigEndian.PutUint16(outData[0:2], uint16(outLength&0xFFFF))

	// 2~6, crc of out length+salt+key
	salt := []byte("auth_sha1_v4")
	crcData := make([]byte, len(salt)+a.KeyLen+2)
	copy(crcData[0:2], outData[0:2])
	copy(crcData[2:], salt)
	copy(crcData[2+len(salt):], a.Key)
	crc32 := ssr.CalcCRC32(crcData, len(crcData), 0xFFFFFFFF)
	// 2~6, crc of out length+salt+key
	binary.LittleEndian.PutUint32(outData[2:], crc32)
	// 6~rand length+6, rand numbers
	rand.Read(outData[dataOffset-randLength : dataOffset])
	// 6, rand length
	if randLength < 128 {
		outData[6] = byte(randLength & 0xFF)
	} else {
		// 6, magic number 0xFF
		outData[6] = 0xFF
		// 7-8, rand length
		binary.BigEndian.PutUint16(outData[7:9], uint16(randLength&0xFFFF))
	}
	// rand length+6~rand length+10, time stamp
	now := time.Now().Unix()
	binary.LittleEndian.PutUint32(outData[dataOffset:dataOffset+4], uint32(now))
	// rand length+10~rand length+14, client ID
	copy(outData[dataOffset+4:dataOffset+4+4], a.data.clientID[0:4])
	// rand length+14~rand length+18, connection ID
	binary.LittleEndian.PutUint32(outData[dataOffset+8:dataOffset+8+4], a.data.connectionID)
	// rand length+18~rand length+18+data length, data
	copy(outData[dataOffset+12:], data)

	key := make([]byte, a.IVLen+a.KeyLen)
	copy(key, a.IV)
	copy(key[a.IVLen:], a.Key)

	h := tools.HmacSHA1(key, outData[:outLength-ssr.ObfsHMACSHA1Len])
	// out length-10~out length/rand length+18+data length~end, hmac
	copy(outData[outLength-ssr.ObfsHMACSHA1Len:], h[0:ssr.ObfsHMACSHA1Len])

	return outData
}

func (a *authSHA1v4) PreEncrypt(plainData []byte) (outData []byte, err error) {
	dataLength := len(plainData)
	offset := 0
	if !a.hasSentHeader && dataLength > 0 {
		headSize := ssr.GetHeadSize(plainData, 30)
		if headSize > dataLength {
			headSize = dataLength
		}
		packData := a.packAuthData(plainData[:headSize])
		outData = append(outData, packData...)
		offset += headSize
		dataLength -= headSize
		a.hasSentHeader = true
	}
	const blockSize = 4096
	for dataLength > blockSize {
		packData := a.packData(plainData[offset : offset+blockSize])
		outData = append(outData, packData...)
		offset += blockSize
		dataLength -= blockSize
	}
	if dataLength > 0 {
		packData := a.packData(plainData[offset:])
		outData = append(outData, packData...)
	}
	return
}

func (a *authSHA1v4) PostDecrypt(plainData []byte) (outData []byte, n int, err error) {
	dataLength := len(plainData)
	b := make([]byte, dataLength)
	copy(b, plainData)
	for dataLength > 4 {
		crc32 := ssr.CalcCRC32(b, 2, 0xFFFFFFFF)
		if binary.LittleEndian.Uint16(b[2:4]) != uint16(crc32&0xFFFF) {
			//common.Error("auth_sha1_v4 post decrypt data crc32 error")
			return nil, 0, ssr.ErrAuthSHA1v4CRC32Error
		}
		length := int(binary.BigEndian.Uint16(b[0:2]))
		if length >= 8192 || length < 8 {
			//common.Error("auth_sha1_v4 post decrypt data length error")
			dataLength = 0
			b = nil
			return nil, 0, ssr.ErrAuthSHA1v4DataLengthError
		}
		if length > dataLength {
			break
		}

		if ssr.CheckAdler32(b, length) {
			pos := int(b[4])
			if pos != 0xFF {
				pos += 4
			} else {
				pos = int(binary.BigEndian.Uint16(b[5:5+2])) + 4
			}
			outLength := length - pos - 4
			tmp := make([]byte, len(outData)+outLength)
			copy(tmp, outData)
			copy(tmp[len(outData):], b[pos:pos+outLength])
			outData = tmp
			dataLength -= length
			b = b[length:]
		} else {
			//common.Error("auth_sha1_v4 post decrypt incorrect checksum")
			dataLength = 0
			b = nil
			return nil, 0, ssr.ErrAuthSHA1v4IncorrectChecksum
		}
	}
	return outData, len(plainData) - dataLength, nil
}

func (o *authSHA1v4) UdpPreEncrypt(data []byte) (encryptedData []byte, err error) {
	return data, nil
}

func (o *authSHA1v4) UdpPostDecrypt(data []byte) ([]byte, int, error) {
	return data, len(data), nil
}
