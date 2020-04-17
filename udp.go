package gossr

import (
	"errors"
	"io"
	"net"

	"github.com/wwqgtxx/gossr/protocol"
)

// ErrShortPacket means the packet is too short to be a valid encrypted packet.
var ErrShortPacket = errors.New("short packet")

// Pack encrypts plaintext using stream cipher s and a random IV.
// Returns a slice of dst containing random IV and ciphertext.
func (c *PacketConn) Pack(plaintext []byte) ([]byte, error) {
	s := c.StreamCipher
	iv, err := s.initEncrypt()
	if err != nil {
		return nil, err
	}

	protocolServerInfo := c.IProtocol.GetServerInfo()
	protocolServerInfo.SetHeadLen(plaintext, 30)
	protocolServerInfo.IV, protocolServerInfo.IVLen = c.IV()
	protocolServerInfo.Key, protocolServerInfo.KeyLen = c.Key()
	c.IProtocol.SetServerInfo(protocolServerInfo)

	preEncryptedData, err := c.IProtocol.UdpPreEncrypt(plaintext)
	if err != nil {
		return nil, err
	}
	preEncryptedDataLen := len(preEncryptedData)
	encryptedData := make([]byte, preEncryptedDataLen+s.info.ivLen)
	copy(encryptedData[:s.info.ivLen], iv)
	s.encrypt(encryptedData[s.info.ivLen:s.info.ivLen+preEncryptedDataLen], preEncryptedData)
	return encryptedData, nil
}

// Unpack decrypts pkt using stream cipher s.
// Returns a slice of dst containing decrypted plaintext.
func (c *PacketConn) Unpack(dst, pkt []byte) ([]byte, error) {
	s := c.StreamCipher
	if len(pkt) < s.info.ivLen {
		return nil, ErrShortPacket
	}

	if len(dst) < len(pkt)-s.info.ivLen {
		return nil, io.ErrShortBuffer
	}

	iv := pkt[:s.info.ivLen]
	err := s.initDecrypt(iv)
	if err != nil {
		return nil, err
	}
	s.decrypt(dst, pkt[s.info.ivLen:])
	dst = dst[:len(pkt)-s.info.ivLen]
	postDecryptedData, length, err := c.IProtocol.UdpPostDecrypt(dst)
	if err != nil || length == 0 {
		return nil, err
	}

	return postDecryptedData, nil
}

type PacketConn struct {
	net.PacketConn
	*StreamCipher
	IProtocol protocol.IProtocol
}

// NewPacketConn wraps a net.PacketConn with stream cipher encryption/decryption.
func NewSSUDPConn(c net.PacketConn, cipher *StreamCipher) net.PacketConn {
	return &PacketConn{PacketConn: c, StreamCipher: cipher}
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf, err := c.Pack(b)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	b, err = c.Unpack(b, b[:n])
	return len(b), addr, err
}
