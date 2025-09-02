package socks5

import (
	"errors"
	"sync"

	"github.com/yangxm/gecko/logger"
)

type Socks5ConnManager struct {
	mutex sync.RWMutex
	conns map[string]*Socks5Conn
}

var (
	Socks5ConnManagerInstance *Socks5ConnManager
	socks5ConnManagerOnce     sync.Once
)

func init() {
	socks5ConnManagerOnce.Do(func() {
		Socks5ConnManagerInstance = NewSocks5ConnManager()
		logger.Debug("Socks5ConnManager Instance Created")
	})
}

func NewSocks5ConnManager() *Socks5ConnManager {
	return &Socks5ConnManager{
		conns: make(map[string]*Socks5Conn),
	}
}

func (m *Socks5ConnManager) Add(conn *Socks5Conn) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.conns[conn.connID] = conn
	logger.Debug("[SOCKS5MGR] + %s", conn.shortID)
}

func (m *Socks5ConnManager) RemoveAndClose(connID string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if conn, ok := m.conns[connID]; ok {
		conn.Close()
		delete(m.conns, connID)
		logger.Debug("[SOCKS5MGR] - %s", conn.shortID)
	}
}

func (m *Socks5ConnManager) Get(connID string) (*Socks5Conn, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	conn, ok := m.conns[connID]
	return conn, ok
}

func (m *Socks5ConnManager) Write(connID string, data []byte) (int, error) {
	if data == nil {
		logger.Warn("[SOCKS4MGR] WRITE FAILED, DATA IS NIL", connID[:6])
		return 0, nil
	}

	conn, ok := m.Get(connID)
	if !ok {
		return 0, errors.New("SOCKS5 CONN NOT FOUND")
	}

	logger.Debug("[SOCKS4MGR] TRY TO WRITE [%s] %d", conn.shortID, len(data))
	if n, err := conn.Write(data); err != nil {
		logger.Error("[SOCKS5MGR] WRITE [%s] ERROR: %v", conn.shortID, err)
		return n, err
	} else {
		logger.Debug("[SOCKS5MGR] WRITE [%s] %d", conn.shortID, n)
		return n, nil
	}
}

func (m *Socks5ConnManager) Len() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.conns)
}
