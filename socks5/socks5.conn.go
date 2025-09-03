package socks5

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/yangxm/gecko/logger"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	isProxy        bool
	attrs          map[string]interface{}
	isClosed       atomic.Bool
	CloseChan      chan struct{}
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
		isProxy:        false,
		attrs:          make(map[string]interface{}),
		CloseChan:      make(chan struct{}),
	}
	s.isClosed.Store(false)
	logger.Debug("SOCKS5[%s] created --- %s", s.shortID, s.connID)
	return s
}

func (s *Socks5Conn) SetTarget(targetAddr string, targetPort int, targetAddrType byte, isProxy bool) error {
	if s.isClosed.Load() {
		logger.Error("SOCKS5[%s] set target failed, conn is closed", s.shortID)
		return fmt.Errorf("SOCKS5[%s] conn is closed", s.shortID)
	}

	targetAddr = strings.TrimSpace(targetAddr)
	if targetAddr == "" {
		logger.Error("SOCKS5[%s] set target failed, addr is empty", s.shortID)
		return fmt.Errorf("SOCKS5[%s] addr is empty", s.shortID)
	}
	if targetPort <= 0 || targetPort > 65535 {
		logger.Error("SOCKS5[%s] set target failed, invalid port: %d", s.shortID, targetPort)
		return fmt.Errorf("SOCKS5[%s] invalid port: %d", s.shortID, targetPort)
	}

	s.targetAddr = targetAddr
	s.targetPort = targetPort
	s.targetAddrType = targetAddrType
	s.isProxy = isProxy
	logger.Debug("SOCKS5[%s] set target --- %s:%d %d, proxy: %v", s.shortID, targetAddr, targetPort, targetAddrType, isProxy)
	return nil
}

func (s *Socks5Conn) SetConnected(isConnected bool) {
	if s.isClosed.Load() {
		logger.Warn("SOCKS5[%s] set connected failed, conn is closed", s.shortID)
		return
	}

	s.isConnected = isConnected
	logger.Debug("SOCKS5[%s] set connected: %v", s.shortID, isConnected)
}

func (s *Socks5Conn) IsConnected() bool {
	return !s.isClosed.Load() && s.isConnected && s.targetAddr != "" && s.targetPort > 0 && s.targetPort <= 65535
}

func (s *Socks5Conn) GetTarget() (string, int, byte, bool) {
	return s.targetAddr, s.targetPort, s.targetAddrType, s.isProxy
}

func (s *Socks5Conn) SetAttr(key string, value interface{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.isClosed.Load() {
		logger.Warn("SOCKS5[%s] set attr failed, conn is closed --- %s:%v", s.shortID, key, value)
		return
	}
	old := s.attrs[key]
	s.attrs[key] = value
	logger.Debug("SOCKS5[%s] set attr --- %s:%v, old: %v", s.shortID, key, value, old)
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

	if s.isClosed.Load() {
		logger.Warn("SOCKS5[%s] remove attr failed, conn is closed --- %s", s.shortID, key)
		return nil, false
	}

	value, ok := s.attrs[key]
	if ok {
		delete(s.attrs, key)
		logger.Debug("SOCKS5[%s] remove attr --- %s:%v", s.shortID, key, value)
	} else {
		logger.Warn("SOCKS5[%s] remove attr failed, key --- %s", s.shortID, key)
	}
	return value, ok
}

func (s *Socks5Conn) Close() error {
	if s.isClosed.CompareAndSwap(false, true) {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		<-s.CloseChan
		close(s.CloseChan)
		s.targetAddr = ""
		s.targetPort = -1
		s.targetAddrType = 0
		s.isConnected = false
		s.isProxy = false
		s.attrs = nil
		logger.Debug("SOCKS5[%s] closed", s.shortID)
		return s.Conn.Close()
	}
	return nil
}

func (s *Socks5Conn) ConnID() string {
	return s.connID
}

func (s *Socks5Conn) ShortID() string {
	return s.shortID
}

func (s *Socks5Conn) IsProxy() bool {
	return s.isProxy
}

func (s *Socks5Conn) WriteIfConnected(data []byte) (int, error) {
	if s.isClosed.Load() {
		logger.Warn("SOCKS5[%s] write failed, conn is closed", s.shortID)
		return 0, fmt.Errorf("SOCKS5[%s] conn is closed", s.shortID)
	}

	if s.IsConnected() {
		return s.Conn.Write(data)
	}
	return 0, fmt.Errorf("SOCKS5[%s] not connected", s.shortID)
}

func (s *Socks5Conn) Write(data []byte) (int, error) {
	if s.isClosed.Load() {
		logger.Warn("SOCKS5[%s] write failed, conn is closed", s.shortID)
		return 0, fmt.Errorf("SOCKS5[%s] conn is closed", s.shortID)
	}

	return s.Conn.Write(data)
}

func (s *Socks5Conn) Read(data []byte) (int, error) {
	if s.isClosed.Load() {
		logger.Error("SOCKS5[%s] read failed, conn is closed", s.shortID)
		return 0, fmt.Errorf("SOCKS5[%s] conn is closed", s.shortID)
	}
	return s.Conn.Read(data)
}
