package socks5

import (
	"fmt"
	"github.com/yangxm/gecko/util"
	"sync"

	"github.com/yangxm/gecko/logger"
)

var (
	sk5mutex sync.RWMutex
	sk5Conns map[string]*Socks5Conn
)

func init() {
	sk5Conns = make(map[string]*Socks5Conn)
}

func AddSock5Conn(sk5Conn *Socks5Conn) {
	sk5mutex.Lock()
	defer sk5mutex.Unlock()
	sk5Conns[sk5Conn.ConnID()] = sk5Conn
	logger.Debug("[CONNMGR] [%s] + %s", util.ShortConnID(sk5Conn.ConnID()), sk5Conn.ConnID())
}

func RemoveAndCloseSk5Conn(connID string) {
	sk5mutex.Lock()
	defer sk5mutex.Unlock()
	if sk5Conn, ok := sk5Conns[connID]; ok {
		if err := sk5Conn.Close(); err != nil {
			logger.Warn("[CONNMGR] [%s] close sk5Conn failed: %v", util.ShortConnID(sk5Conn.ConnID()), err)
		}
		delete(sk5Conns, connID)
		logger.Debug("[CONNMGR] [%s] - %s", util.ShortConnID(sk5Conn.ConnID()), sk5Conn.ConnID())
	}
}

func GetSk5Conn(connID string) (*Socks5Conn, bool) {
	sk5Conns, ok := sk5Conns[connID]
	return sk5Conns, ok
}

func IsSk5ConnExist(connID string) bool {
	sk5Conns, ok := sk5Conns[connID]
	return ok && sk5Conns != nil
}

func WriteToSk5Conn(connID string, data []byte) (int, error) {
	return writeToSk5Conn(connID, data, func(sk5Conn *Socks5Conn, d []byte) (int, error) {
		return sk5Conn.Write(d)
	})
}

func WriteToSk5ConnIfConnected(connID string, data []byte) (int, error) {
	return writeToSk5Conn(connID, data, func(sk5Conn *Socks5Conn, d []byte) (int, error) {
		return sk5Conn.WriteIfConnected(d)
	})
}

func writeToSk5Conn(connID string, data []byte, delegate func(sk5Conn *Socks5Conn, d []byte) (int, error)) (int, error) {
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

	sk5Conn, ok := GetSk5Conn(connID)
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

func Sk5ConnLen() int {
	return len(sk5Conns)
}
