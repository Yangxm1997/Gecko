package socks5

import (
	"fmt"
	"github.com/yangxm/gecko/logger"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

type ProxyForwarder struct {
	Done       chan string
	sk5Conn    *Socks5Conn
	bridgeConn net.Conn
	once       sync.Once
	retries    atomic.Uint32
}

const (
	proxyMaxRetry = 3
)

func NewProxyForwarder(sk5Conn *Socks5Conn, bridgeConn net.Conn) (*ProxyForwarder, error) {
	if sk5Conn == nil {
		return nil, fmt.Errorf("sk5Conn is nil")
	}

	if bridgeConn == nil {
		return nil, fmt.Errorf("bridgeConn is nil")
	}

	p := &ProxyForwarder{
		Done:       make(chan string),
		sk5Conn:    sk5Conn,
		bridgeConn: bridgeConn,
	}

	logger.Info("PROXY[%s] forward created", p.sk5Conn.ShortID())
	return p, nil
}

func (p *ProxyForwarder) Start() {
	logger.Info("PROXY[%s] pipe start", p.sk5Conn.ShortID())
	go p.pipe()
}

func (p *ProxyForwarder) pipe() {
	buf := make([]byte, 32*1024)
	sk5Conn := p.sk5Conn
	bridgeConn := p.bridgeConn
	shortConn := sk5Conn.ShortID()

	addr, port, _, isProxy := sk5Conn.GetTarget()
	if !isProxy {
		logger.Error("PROXY[%s] not a proxy", shortConn)
		return
	}
	src := sk5Conn.RemoteAddr().String()
	dst := fmt.Sprintf("%s:%d", addr, port)

	for {
		n, rerr := sk5Conn.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				wn, werr := bridgeConn.Write(buf[written:n])
				if werr != nil {
					logger.Error("PROXY[%s] F:%v --> T:%v  write error: %v", shortConn, src, dst, werr)
					p.retries.Add(1)
					if p.retries.Load() >= proxyMaxRetry {
						p.Done <- "Write error: " + werr.Error()
						return
					}
				} else {
					logger.Debug("PROXY[%s] F:%v --> T:%v  write  %d", shortConn, src, dst, wn)
					p.retries.Store(0)
				}
				written += wn
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				logger.Error("PROXY[%s] F:%v --> T:%v  read error: %v", shortConn, src, dst, rerr)
				p.Done <- "Read error: " + rerr.Error()
			} else {
				logger.Debug("PROXY[%s] F:%v --> T:%v  read EOF", shortConn, src, dst)
				p.Done <- "Read EOF"
			}
			break
		}

		select {
		case <-p.sk5Conn.CloseChan:
			logger.Debug("PROXY[%s] F:%v --> T:%v  skConn closed", shortConn, src, dst)
			p.Done <- "SkConn closed"
			break
		default:
		}
	}

	p.once.Do(func() {
		close(p.Done)
	})
}
