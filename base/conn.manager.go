package base

import (
	"net"
)

type ConnManager[T net.Conn] interface {
	Add(connID string, conn T)
	RemoveAndClose(connID string)
	Get(connID string) (T, bool)
	IsExist(connID string) bool
	Write(connID string, data []byte) (int, error)
	WriteIfConnected(connID string, data []byte) (int, error)
	Close()
	Len() int
}
