package socks5

import (
	"fmt"
	"github.com/yangxm/gecko/base"
	"github.com/yangxm/gecko/logger"
	"github.com/yangxm/gecko/util"
	"sync"
)

type _Sock5ConnManager struct {
	mutex sync.Mutex
	conns map[string]*Socks5Conn
}

var (
	sock5ConnManagerCreateMutex sync.Mutex
	sock5ConnManagerInstance    *_Sock5ConnManager
)

func Sock5ConnManager() base.ConnManager[*Socks5Conn] {
	if sock5ConnManagerInstance == nil {
		sock5ConnManagerCreateMutex.Lock()
		defer sock5ConnManagerCreateMutex.Unlock()
		if sock5ConnManagerInstance == nil {
			sock5ConnManagerInstance = &_Sock5ConnManager{
				conns: make(map[string]*Socks5Conn),
			}
		}
	}
	return sock5ConnManagerInstance
}

func (s *_Sock5ConnManager) Add(connID string, conn *Socks5Conn) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.conns[connID] = conn
	logger.Debug("[CONNMGR] [%s] + %s", util.ShortConnID(connID), connID)
}

func (s *_Sock5ConnManager) RemoveAndClose(connID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if conn, ok := s.conns[connID]; ok {
		if err := conn.Close(); err != nil {
			logger.Warn("[CONNMGR] [%s] close sk5Conn failed: %v", util.ShortConnID(connID), err)
		}
		delete(s.conns, connID)
		logger.Debug("[CONNMGR] [%s] - %s", util.ShortConnID(connID), connID)
	}
}

func (s *_Sock5ConnManager) Get(connID string) (*Socks5Conn, bool) {
	conn, ok := s.conns[connID]
	return conn, ok && conn != nil
}

func (s *_Sock5ConnManager) IsExist(connID string) bool {
	sk5Conns, ok := s.conns[connID]
	return ok && sk5Conns != nil
}

func (s *_Sock5ConnManager) Write(connID string, data []byte) (int, error) {
	return s.write(connID, data, func(sk5Conn *Socks5Conn, d []byte) (int, error) {
		return sk5Conn.Write(d)
	})
}

func (s *_Sock5ConnManager) WriteIfConnected(connID string, data []byte) (int, error) {
	return s.write(connID, data, func(sk5Conn *Socks5Conn, d []byte) (int, error) {
		return sk5Conn.WriteIfConnected(d)
	})
}

func (s *_Sock5ConnManager) Len() int {
	return len(s.conns)
}

func (s *_Sock5ConnManager) write(connID string, data []byte, delegate func(sk5Conn *Socks5Conn, d []byte) (int, error)) (int, error) {
	shortConn := util.ShortConnID(connID)
	if data == nil {
		logger.Warn("[CONNMGR] [%s] write failed, data bytes is nil", shortConn)
		return 0, nil
	}

	dataLen := len(data)
	if dataLen == 0 {
		logger.Warn("[CONNMGR] [%s] write failed, data bytes is empty", shortConn)
		return 0, nil
	}

	sk5Conn, ok := s.Get(connID)
	if !ok {
		logger.Error("[CONNMGR] [%s] write failed, sk5Conn not found: %s", shortConn, connID)
		return 0, fmt.Errorf("[CONNMGR] [%s]socks5 sk5Conn not found", connID)
	}

	if !sk5Conn.IsProxy() {
		logger.Error("[CONNMGR] [%s] write failed, sk5Conn is not proxy: %s", shortConn, connID)
		return 0, fmt.Errorf("[CONNMGR] [%s] sk5Conn is not proxy", connID)
	}

	logger.Debug("[CONNMGR] [%s] trying to write --- %d", shortConn, dataLen)
	if n, err := delegate(sk5Conn, data); err != nil {
		logger.Error("[CONNMGR] [%s] write failed: %v", shortConn, err)
		return n, err
	} else {
		if n == dataLen {
			logger.Debug("[CONNMGR] [%s] write success: %d", shortConn, dataLen)
		} else {
			logger.Warn("[CONNMGR] [%s] write success warning, expected: %d, actual: %d", shortConn, dataLen, n)
		}
		return n, nil
	}
}
