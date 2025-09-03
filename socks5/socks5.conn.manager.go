package socks5

import (
	"fmt"
	"github.com/yangxm/gecko/util"
	"sync"

	"github.com/yangxm/gecko/logger"
)

type ConnManager struct {
	mutex sync.RWMutex
	conns map[string]*Socks5Conn
}

var (
	ConnManagerInstance *ConnManager
	connManagerOnce     sync.Once
)

func init() {
	connManagerOnce.Do(func() {
		ConnManagerInstance = NewSocks5ConnManager()
		logger.Debug("[SOCKS4MGR] ConnManager Instance Created")
	})
}

func NewSocks5ConnManager() *ConnManager {
	return &ConnManager{
		conns: make(map[string]*Socks5Conn),
	}
}

func (m *ConnManager) Add(conn *Socks5Conn) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.conns[conn.connID] = conn
	logger.Debug("[SOCKS5MGR] [%s] + %s", conn.shortID, conn.connID)
}

func (m *ConnManager) RemoveAndClose(connID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if conn, ok := m.conns[connID]; ok {
		_ = conn.Close()
		delete(m.conns, connID)
		logger.Debug("[SOCKS5MGR] [%s] - %s", conn.shortID, conn.connID)
	}
}

func (m *ConnManager) Get(connID string) (*Socks5Conn, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	conn, ok := m.conns[connID]
	return conn, ok
}

func (m *ConnManager) Exist(connID string) bool {
	v, ok := m.conns[connID]
	return ok && v != nil
}

func (m *ConnManager) Write(connID string, data []byte) (int, error) {
	if data == nil {
		logger.Warn("[SOCKS4MGR] [%s] write failed, data bytes is nil", util.ShortConnID(connID))
		return 0, nil
	}

	dataLen := len(data)
	if dataLen == 0 {
		logger.Warn("[SOCKS4MGR] [%s] write failed, data bytes is empty", util.ShortConnID(connID))
		return 0, nil
	}

	conn, ok := m.Get(connID)
	if !ok {
		logger.Error("[SOCKS4MGR] [%s] write failed, socks5 conn not found: %s", util.ShortConnID(connID), connID)
		return 0, fmt.Errorf("[SOCKS4MGR] [%s] socks5 conn not found", connID)
	}

	logger.Debug("[SOCKS4MGR] [%s] trying to write --- %d", conn.shortID, dataLen)
	if n, err := conn.Write(data); err != nil {
		logger.Error("[SOCKS5MGR] [%s] write failed: %v", conn.shortID, err)
		return n, err
	} else {
		if n == dataLen {
			logger.Debug("[SOCKS5MGR] [%s] write success: %d", conn.shortID, dataLen)
		} else {
			logger.Warn("[SOCKS5MGR] [%s] write success warning, expected: %d, actual: %d", conn.shortID, dataLen, n)
		}
		return n, nil
	}
}

func (m *ConnManager) Len() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.conns)
}
