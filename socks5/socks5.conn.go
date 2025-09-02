package socks5

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/yangxm/gecko/logger"
)

type Socks5Conn struct {
	net.Conn
	mutex          sync.RWMutex
	connID         string
	shortID        string
	targetAddr     string
	targetPort     int
	targetAddrType byte
	isConnected    bool
	isDirect       bool
	attrs          map[string]interface{}
}

func NewSocks5Conn(conn net.Conn) *Socks5Conn {
	connID := uuid.New().String()
	s := &Socks5Conn{
		Conn:           conn,
		connID:         connID,
		shortID:        connID[:6],
		targetAddr:     "",
		targetPort:     -1,
		targetAddrType: 0,
		isConnected:    false,
		isDirect:       false,
		attrs:          make(map[string]interface{}),
	}
	logger.Debug("SOCKS5[%s] CREATED", s.shortID)
	return s
}

func (s *Socks5Conn) SetTarget(targetAddr string, targetPort int, targetAddrType byte, isDirect bool) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	targetAddr = strings.TrimSpace(targetAddr)
	if targetAddr == "" {
		return fmt.Errorf("CONN[%s] ADDR IS EMPTY", s.shortID)
	}
	if targetPort <= 0 || targetPort > 65535 {
		return fmt.Errorf("SOCKS5[%s] PORT %d IS INVALID", s.shortID, targetPort)
	}

	s.targetAddr = targetAddr
	s.targetPort = targetPort
	s.targetAddrType = targetAddrType
	s.isDirect = isDirect
	logger.Debug("SOCKS5[%s] SET TARGET --- %s:%d %d %v", s.shortID, targetAddr, targetPort, targetAddrType, isDirect)
	return nil
}

func (s *Socks5Conn) SetConnected(isConnected bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	s.isConnected = isConnected
	logger.Debug("SOCKS5[%s] SET CONNECTED %v", s.shortID, isConnected)
}

func (s *Socks5Conn) IsConnected() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isConnected && s.targetAddr != "" && s.targetPort != -1
}

func (s *Socks5Conn) GetTarget() (string, int, byte, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.targetAddr, int(s.targetPort), s.targetAddrType, s.isDirect
}

func (s *Socks5Conn) SetAttr(key string, value interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.attrs[key] = value
	logger.Debug("SOCKS5[%s] SET ATTR %s:%v", s.shortID, key, value)
}

func (s *Socks5Conn) GetAttr(key string) (interface{}, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	value, ok := s.attrs[key]
	return value, ok
}

func (s *Socks5Conn) RemoveAttr(key string) (interface{}, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	value, ok := s.attrs[key]
	if ok {
		delete(s.attrs, key)
	}
	return value, ok
}

func (s *Socks5Conn) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.targetAddr = ""
	s.targetPort = -1
	s.targetAddrType = 0
	s.isConnected = false
	s.isDirect = false
	s.attrs = nil
	logger.Debug("SOCKS5[%s] CLOSE", s.shortID)
	return s.Conn.Close()
}

func (s *Socks5Conn) ConnID() string {
	return s.connID
}

func (s *Socks5Conn) ShortID() string {
	return s.shortID
}

func (s *Socks5Conn) IsDirect() bool {
	return s.isDirect
}
