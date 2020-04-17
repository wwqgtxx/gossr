package protocol

import (
	"bytes"

	"github.com/wwqgtxx/gossr/tools"
)

func init() {
	register("auth_aes128_md5", NewAuthAES128MD5)
}

func NewAuthAES128MD5() IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_md5",
		hmac:       tools.HmacMD5,
		hashDigest: tools.MD5Sum,
		packID:     1,
		recvInfo: recvInfo{
			recvID: 1,
			buffer: bytes.NewBuffer(nil),
		},
		//data: &authData{
		//	connectionID: 0xFF000001,
		//},
	}
	return a
}
