package protocol

import (
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/wwqgtxx/gossr/ssr"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type creator func() IProtocol

var (
	creatorMap              = make(map[string]creator)
	NotSupportProtocolError = errors.New("protocol do not support")
)

type IProtocol interface {
	SetServerInfo(s *ssr.ServerInfoForObfs)
	GetServerInfo() *ssr.ServerInfoForObfs
	PreEncrypt(data []byte) ([]byte, error)
	PostDecrypt(data []byte) ([]byte, int, error)
	UdpPreEncrypt(data []byte) ([]byte, error)
	UdpPostDecrypt(data []byte) ([]byte, int, error)
	SetData(data interface{})
	GetData() interface{}
}

type authData struct {
	clientID     []byte
	connectionID uint32
}

func register(name string, c creator) {
	creatorMap[name] = c
}

func NewProtocol(name string) (iprotocol IProtocol, err error) {
	c, ok := creatorMap[strings.ToLower(name)]
	if ok {
		return c(), nil
	}
	return nil, NotSupportProtocolError
}

func ProtocolCopy(in *IProtocol) *IProtocol {
	out := *in
	return &out
}
