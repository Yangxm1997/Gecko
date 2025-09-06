package socks5

import (
	"errors"
	"fmt"
	"github.com/yangxm/gecko/base"
	"github.com/yangxm/gecko/logger"
	"github.com/yangxm/gecko/util"
	"github.com/yangxm/gecko/whitlist"
	"io"
	"net"
	"strings"
	"sync"
)

const (
	serverStatusClosed  = 0
	serverStatusRunning = 1
	serverStatusClosing = 2
)

type ClientLocalSocks5Server struct {
	clientID        string
	bindAddr        string
	bindPort        int
	bridgeTransport base.BridgeTransport
	wg              sync.WaitGroup
	mu              sync.Mutex
	isClosing       bool
}

func NewClientLocalSocks5Server(clientID string, bindAddr string, bindPort int, bridgeTransport base.BridgeTransport) *ClientLocalSocks5Server {
	return &ClientLocalSocks5Server{clientID: clientID, bindAddr: bindAddr, bindPort: bindPort, bridgeTransport: bridgeTransport}
}

func (s *ClientLocalSocks5Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosing {
		return errors.New("server is closing")
	}

	infoStr := fmt.Sprintf("[%s] %s:%d", s.clientID, s.bindAddr, s.bindPort)
	logger.Info("Socks5 server start, %s", infoStr)
	if listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.bindAddr, s.bindPort)); err != nil {
		logger.Error("Socks5 server listen failed, %s, err: %v", infoStr, err)
		return err
	} else {
		defer func(listener net.Listener) {
			if err := listener.Close(); err != nil {
				logger.Warn("Socks5 server close listener %s failed: %v", infoStr, err)
			}
			logger.Info("Socks5 server listener %s closed", infoStr)
		}(listener)

		s.mu.Unlock()
		logger.Info("Socks5 server listen success, %s", infoStr)

		for {
			if s.isClosing {
				break
			}

			if conn, err := listener.Accept(); err != nil {
				logger.Warn("Socks5 server accept failed, err: %v", err)
				continue
			} else {
				sk5Conn := NewSocks5Conn(conn)
				go s.handleConn(sk5Conn)
			}
		}
		return nil
	}
}

func (s *ClientLocalSocks5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosing {
		logger.Warn("Socks5 server is closing")
		return nil
	}

	s.isClosing = true
	Sock5ConnManager().Close()
	if s.bridgeTransport != nil {
		_ = s.bridgeTransport.Close()
	}
	s.wg.Wait()
	s.isClosing = false

	logger.Info("Socks5 server closed")
	return nil
}

func (s *ClientLocalSocks5Server) handleConn(sk5Conn *Socks5Conn) {
	s.wg.Add(1)
	shortConn := util.ShortConnID(sk5Conn.connID)
	defer func(sk5Conn *Socks5Conn) {
		if err := sk5Conn.Close(); err != nil {
			logger.Warn("SOCKS5[%s] close sk5Conn failed: %v", shortConn, err)
		}
		logger.Debug("SOCKS5[%s] sk5Conn[%v] closed", shortConn, sk5Conn.RemoteAddr())
		s.wg.Done()
	}(sk5Conn)

	logger.Debug("SOCKS5[%s] handle conn start", shortConn)
	if err := s.handleAuth(sk5Conn); err != nil {
		logger.Error("SOCKS5[%s] handle auth failed: %v", shortConn, err)
		return
	}

	if err := s.handleRequest(sk5Conn); err != nil {
		logger.Error("SOCKS5[%s] handle request failed: %v", shortConn, err)
		return
	}
}

func (s *ClientLocalSocks5Server) handleAuth(sk5Conn *Socks5Conn) error {
	shortConn := util.ShortConnID(sk5Conn.connID)
	logger.Debug("SOCKS5[%s] handle auth start", shortConn)
	buf := make([]byte, 256)

	n, err := io.ReadFull(sk5Conn, buf[:2])
	if err != nil {
		logger.Error("SOCKS5[%s] handle auth, read message failed: %v", shortConn, err)
		return fmt.Errorf("[handle auth] read message failed: %v", err)
	}

	if n != 2 {
		logger.Error("SOCKS5[%s] handle auth, message length: %d", shortConn, n)
		return fmt.Errorf("[handle auth] message length: %d", n)
	}

	ver, nMethods := buf[0], buf[1]
	logger.Debug("SOCKS5[%s] handle auth, ver: %v, nMethods: %v", shortConn, ver, nMethods)
	if ver != base.Socks5Version {
		logger.Error("SOCKS5[%s] handle auth, invalid ver: %v", shortConn, ver)
		return fmt.Errorf("[handle auth] invalid ver: %v", ver)
	}

	if _, err := io.ReadFull(sk5Conn, buf[:nMethods]); err != nil {
		logger.Error("SOCKS5[%s] handle auth, read methods failed: %v", shortConn, err)
		return fmt.Errorf("[handle auth] read methods failed: %v", err)
	}
	logger.Debug("SOCKS5[%s] handle auth, methods: %v", shortConn, ver, buf[:nMethods])

	if _, err := sk5Conn.Write(base.Socks5AuthLegacy()); err != nil {
		logger.Error("SOCKS5[%s] handle auth, write response failed: %v", shortConn, err)
		return fmt.Errorf("[handle auth] write response failed: %v", err)
	}

	logger.Debug("SOCKS5[%s] handle auth, write response success", shortConn)
	return nil
}

func (s *ClientLocalSocks5Server) handleRequest(sk5Conn *Socks5Conn) error {
	shortConn := util.ShortConnID(sk5Conn.connID)
	logger.Debug("SOCKS5[%s] handle request start", shortConn)
	buf := make([]byte, 256)

	n, err := io.ReadFull(sk5Conn, buf[:4])
	if err != nil {
		logger.Error("SOCKS5[%s] handle request, read message failed: %v", shortConn, err)
		return fmt.Errorf("[handle request] read message failed: %v", err)
	}

	if n != 4 {
		logger.Error("SOCKS5[%s] handle request, message length: %d", shortConn, n)
		return fmt.Errorf("[handle request] message length: %d", n)
	}
	ver, cmd, atyp := buf[0], buf[1], buf[3]
	logger.Debug("SOCKS5[%s] handle request, ver: %v, cmd: %v, atyp: %v", shortConn, ver, cmd, atyp)

	if ver != base.Socks5Version {
		logger.Error("SOCKS5[%s] handle request, invalid ver: %v", shortConn, ver)
		return fmt.Errorf("[handle request] invalid ver: %v", ver)
	}

	if cmd != base.Socks5CmdConnect {
		logger.Error("SOCKS5[%s] handle request, invalid cmd: %v", shortConn, cmd)
		return fmt.Errorf("[handle request] invalid cmd: %v", cmd)
	}

	// 读取地址
	var addr string
	switch atyp {
	case base.AddrTypeIPv4:
		if _, err := io.ReadFull(sk5Conn, buf[:4]); err != nil {
			logger.Error("SOCKS5[%s] handle request, read ipv4 failed: %v", shortConn, err)
			return fmt.Errorf("[handle request] read ipv4 failed: %v", err)
		}
		addr = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
	case base.AddrTypeDomain:
		if _, err := io.ReadFull(sk5Conn, buf[:1]); err != nil {
			logger.Error("SOCKS5[%s] handle request, read domain length failed: %v", shortConn, err)
			return fmt.Errorf("[handle request] read domain length failed: %v", err)
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(sk5Conn, buf[:domainLen]); err != nil {
			logger.Error("SOCKS5[%s] handle request, read domain failed: %v, len: %d", shortConn, err, domainLen)
			return fmt.Errorf("[handle request] read domain failed: %v, len: %d", err, domainLen)
		}
		addr = string(buf[:domainLen])
	case base.AddrTypeIPv6:
		if _, err := io.ReadFull(sk5Conn, buf[:16]); err != nil {
			logger.Error("SOCKS5[%s] handle request, read ipv6 failed: %v", shortConn, err)
			return fmt.Errorf("[handle request] read ipv6 failed: %v", err)
		}
		addr = net.IP(buf[:16]).String()
	default:
		logger.Error("SOCKS5[%s] handle request, invalid atyp: %v", shortConn, atyp)
		return fmt.Errorf("[handle request] invalid atyp: %v", atyp)
	}

	// 读取端口
	if _, err := io.ReadFull(sk5Conn, buf[:2]); err != nil {
		logger.Error("SOCKS5[%s] handle request, read port failed: %v", shortConn, err)
		return fmt.Errorf("[handle request] read port failed: %v", err)
	}
	port := int(buf[0])<<8 | int(buf[1])
	logger.Debug("SOCKS5[%s] handle request, target: %s:%d", shortConn, addr, port)

	// 连接目标
	if whitlist.Contains(addr, atyp == base.AddrTypeDomain) {
		return s.handleDirect(sk5Conn, addr, port, atyp)
	} else {
		return s.handleProxy(sk5Conn, addr, port, atyp)
	}
}

func (s *ClientLocalSocks5Server) handleDirect(sk5Conn *Socks5Conn, addr string, port int, atyp byte) error {
	shortConn := util.ShortConnID(sk5Conn.connID)
	targetAddr := fmt.Sprintf("%s:%d", addr, port)
	logger.Debug("SOCKS5[%s] handle direct start --> %s", shortConn, targetAddr)

	if err := sk5Conn.SetTarget(addr, port, atyp, false); err != nil {
		logger.Error("SOCKS5[%s] handle direct, set conn target info failed, error: %v", shortConn, err)
		return fmt.Errorf("[handle direct] set conn target info failed: %v", err)
	}

	logger.Debug("SOCKS5[%s] handle direct, connect to %s", shortConn, targetAddr)
	if targetConn, err := net.Dial("tcp", targetAddr); err != nil {
		logger.Error("SOCKS5[%s] handle direct, connect to target failed: %v", shortConn, err)
		sk5Conn.SetConnected(false)
		if _, err := sk5Conn.Write(base.Socks5CmdConnectFailed()); err != nil {
			logger.Warn("SOCKS5[%s] handle direct, write Socks5CmdConnectFailed failed: %v", shortConn, err)
		}
		return fmt.Errorf("[handle direct] connect to target failed: %v", err)
	} else {
		var targetAddrLog string
		if atyp == base.AddrTypeDomain {
			targetAddrLog = fmt.Sprintf("%s(%s)", targetAddr, targetConn.RemoteAddr())
		} else {
			targetAddrLog = fmt.Sprintf("%s", targetConn.RemoteAddr())
		}

		logger.Info("SOCKS5[%s] handle direct, L:%v --> R:%s", shortConn, sk5Conn.RemoteAddr(), targetAddrLog)
		sk5Conn.SetConnected(true)
		if _, err := sk5Conn.Write(base.Socks5CmdConnectSuccess()); err != nil {
			logger.Error("SOCKS5[%s] handle direct, write Socks5CmdConnectSuccess failed: %v", shortConn, err)
			if err := targetConn.Close(); err != nil {
				logger.Warn("SOCKS5[%s] handle direct, close targetConn failed: %v", shortConn, err)
			}
			logger.Debug("SOCKS5[%s] targetConn[%s] closed", shortConn, targetAddr)
			return fmt.Errorf("[handle direct] write Socks5CmdConnectSuccess failed: %v", err)
		}

		forwarder := NewDirectForwarder(sk5Conn, targetConn)
		defer forwarder.CloseConn()
		forwarder.Start()

		doneMessage := <-forwarder.Done

		if doneMessage == "" || strings.Contains(doneMessage, "EOF") {
			logger.Info("SOCKS5[%s] handle direct, L:%v ××> R:%s", shortConn, sk5Conn.RemoteAddr(), targetAddrLog)
			logger.Debug("SOCKS5[%s] handle direct, done with %s", shortConn, doneMessage)
			return nil
		} else {
			logger.Error("SOCKS5[%s] handle direct, done with error: %s", shortConn, doneMessage)
			return fmt.Errorf("[handle direct] done with error: %s", doneMessage)
		}
	}
}

func (s *ClientLocalSocks5Server) handleProxy(sk5Conn *Socks5Conn, addr string, port int, atyp byte) error {
	shortConn := util.ShortConnID(sk5Conn.connID)
	targetAddr := fmt.Sprintf("%s:%d", addr, port)
	logger.Debug("SOCKS5[%s] handle proxy start --> %s", shortConn, targetAddr)

	if err := sk5Conn.SetTarget(addr, port, atyp, true); err != nil {
		logger.Error("SOCKS5[%s] handle proxy, set conn target info failed, error: %v", shortConn, err)
		return fmt.Errorf("[handle proxy] set conn target info failed: %v", err)
	}

	logger.Debug("SOCKS5[%s] handle proxy, connect to %s", shortConn, targetAddr)
	Sock5ConnManager().Add(sk5Conn.connID, sk5Conn)
	forwarder, err := NewProxyForwarder(sk5Conn, s.bridgeTransport, s.clientID)
	if err != nil {
		logger.Error("SOCKS5[%s] handle proxy, create proxy forward failed: %v", shortConn, err)
		return fmt.Errorf("[handle proxy] create proxy forward failed: %v", err)
	}

	logger.Info("SOCKS5[%s] handle proxy, L:%v --> R:%s", shortConn, sk5Conn.RemoteAddr(), targetAddr)
	forwarder.Start()
	doneMessage := <-forwarder.Done
	Sock5ConnManager().RemoveAndClose(sk5Conn.connID)
	if doneMessage == "" || strings.Contains(doneMessage, "EOF") || strings.Contains(doneMessage, "SkConn closed") {
		logger.Info("SOCKS5[%s] handle proxy, L:%v ××> R:%s", shortConn, sk5Conn.RemoteAddr(), targetAddr)
		logger.Debug("SOCKS5[%s] handle proxy, done with %s", shortConn, doneMessage)
		return nil
	} else {
		logger.Error("SOCKS5[%s] handle proxy, done with error: %s", shortConn, doneMessage)
		return fmt.Errorf("[handle proxy] done with error: %s", doneMessage)
	}
}
