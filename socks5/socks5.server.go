package socks5

import (
	"errors"
	"fmt"
	"github.com/yangxm/gecko/util"
	"io"
	"net"
	"strings"

	"github.com/yangxm/gecko/logger"
)

type Socks5Server struct {
	ID         string
	BindAddr   string
	BindPort   int
	BridgeConn net.Conn
}

func (s *Socks5Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.BindAddr, s.BindPort)
	logger.Info("Socks5 server start, id: %s, addr: %s", s.ID, addr)
	if listener, err := net.Listen("tcp", addr); err != nil {
		logger.Error("Socks5 server listen failed, id: %s, addr: %s, err: %v", s.ID, addr, err)
		return err
	} else {
		defer listener.Close()
		logger.Info("Socks5 server listen success, id: %s, addr: %s", s.ID, addr)

		for {
			if conn, err := listener.Accept(); err != nil {
				logger.Warn("Socks5 server accept failed, err: %v", err)
				continue
			} else {
				sk5Conn := NewSocks5Conn(conn)
				go s.handleConn(sk5Conn)
			}
		}
	}
}

func (s *Socks5Server) handleConn(sk5Conn *Socks5Conn) {
	shortConn := util.ShortConnID(sk5Conn.connID)
	defer func(sk5Conn *Socks5Conn) {
		if err := sk5Conn.Close(); err != nil {
			logger.Warn("SOCKS5[%s] close sk5Conn failed: %v", shortConn, err)
		}
	}(sk5Conn)

	if err := s.handleAuth(sk5Conn); err != nil {
		logger.Error("SOCKS5[%s] handle auth failed: %v", shortConn, err)
		return
	}

	if err := s.handleRequest(sk5Conn); err != nil {
		logger.Error("SOCKS5[%s] handle request failed: %v", shortConn, err)
	}
}

func (s *Socks5Server) handleAuth(sk5Conn *Socks5Conn) error {
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
	if ver != socks5Version {
		logger.Error("SOCKS5[%s] handle auth, invalid ver: %v", shortConn, ver)
		return fmt.Errorf("[handle auth] invalid ver: %v", ver)
	}

	if _, err := io.ReadFull(sk5Conn, buf[:nMethods]); err != nil {
		logger.Error("SOCKS5[%s] handle auth, read methods failed: %v", shortConn, err)
		return fmt.Errorf("[handle auth] read methods failed: %v", err)
	}
	logger.Debug("SOCKS5[%s] handle auth, methods: %v", shortConn, ver, buf[:nMethods])

	if _, err := sk5Conn.Write(Socks5NoAuth()); err != nil {
		logger.Error("SOCKS5[%s] handle auth, write response failed: %v", shortConn, err)
		return fmt.Errorf("SOCKS5 AUTH, WRITE RESP FAILED: %v", err)
	}
	logger.Debug("SOCKS5[%s] AUTH, WRITE RESP SUCCESS", shortConn)
	return nil
}

func (s *Socks5Server) handleRequest(sk5Conn *Socks5Conn) error {
	logger.Debug("SOCKS5[%s] CONN", sk5Conn.ShortID())
	buf := make([]byte, 256)

	if n, err := io.ReadFull(sk5Conn, buf[:4]); err != nil || n != 4 {
		logger.Error("SOCKS5[%s] CONN, READ FAILED, N: %d, ERR: %v", sk5Conn.ShortID(), n, err)
		var errMsg string
		if err != nil {
			errMsg = fmt.Sprintf("%v", err)
		} else {
			errMsg = fmt.Sprintf("N: %d", n)
		}
		return fmt.Errorf("SOCKS5 CONN, READ FAILED: %s", errMsg)
	} else {
		ver, cmd, atyp := buf[0], buf[1], buf[3]
		logger.Debug("SOCKS5[%s] CONN, VER: %v, CMD: %v, ATYP: %v", sk5Conn.ShortID(), ver, cmd, atyp)

		if ver != socks5Version {
			logger.Error("SOCKS5[%s] CONN FAILED, INVALID VER %v", sk5Conn.ShortID(), ver)
			return fmt.Errorf("SOCKS5 CONN, INVALID VER %v", ver)
		}

		if cmd != socks5CmdConnect {
			logger.Error("SOCKS5[%s] CONN FAILED, INVALID CMD %v", sk5Conn.ShortID(), cmd)
			return fmt.Errorf("SOCKS5 CONN, INVALID CMD %v", ver)
		}

		// 读取地址
		var addr string
		switch atyp {
		case addrTypeIPv4:
			if _, err := io.ReadFull(sk5Conn, buf[:4]); err != nil {
				logger.Error("SOCKS5[%s] CONN, READ IPV4 FAILED, ERR: %v", sk5Conn.ShortID(), err)
				return fmt.Errorf("SOCKS5 CONN, READ IPV4 FAILED: %v", err)
			}
			addr = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
		case addrTypeDomain:
			if _, err := io.ReadFull(sk5Conn, buf[:1]); err != nil {
				logger.Error("SOCKS5[%s] CONN, READ DOMAIN LEN FAILED, ERR: %v", sk5Conn.ShortID(), err)
				return fmt.Errorf("SOCKS5 CONN, READ DOMAIN LEN FAILED: %v", err)
			}
			domainLen := int(buf[0])
			if _, err := io.ReadFull(sk5Conn, buf[:domainLen]); err != nil {
				logger.Error("SOCKS5[%s] CONN, READ DOMAIN FAILED, ERR: %v", sk5Conn.ShortID(), err)
				return fmt.Errorf("SOCKS5 CONN, READ DOMAIN FAILED: %v", err)
			}
			addr = string(buf[:domainLen])
		case addrTypeIPv6:
			if _, err := io.ReadFull(sk5Conn, buf[:16]); err != nil {
				logger.Error("SOCKS5[%s] CONN, READ IPV6 FAILED, ERR: %v", sk5Conn.ShortID(), err)
				return fmt.Errorf("SOCKS5 CONN, READ IPV6 FAILED: %v", err)
			}
			addr = net.IP(buf[:16]).String()
		default:
			logger.Error("SOCKS5[%s] CONN, INVALID ATYP %v", sk5Conn.ShortID(), atyp)
			return fmt.Errorf("SOCKS5 CONN, INVALID ATYP %v", atyp)
		}

		// 读取端口
		if _, err := io.ReadFull(sk5Conn, buf[:2]); err != nil {
			logger.Error("SOCKS5[%s] CONN, READ PORT FAILED, ERR: %v", sk5Conn.ShortID(), err)
			return fmt.Errorf("SOCKS5 CONN, READ PORT FAILED: %v", err)
		}
		port := int(buf[0])<<8 | int(buf[1])
		logger.Debug("SOCKS5[%s] CONN, ADDR: %s, PORT: %v", sk5Conn.ShortID(), addr, port)

		// 连接目标
		if HostWhiteListInstance.Contains(addr, atyp == addrTypeDomain) {
			return handleDirect(sk5Conn, addr, port, atyp)
		} else {
			if err := sk5Conn.SetTarget(addr, port, atyp, true); err != nil {
				logger.Error("SOCKS5[%s] CONN, set conn target info failed, error: %v", sk5Conn.ShortID(), err)
				return err
			}

			targetAddr := fmt.Sprintf("%s:%d", addr, port)
			logger.Info("SOCKS5[%s] CONN, proxy connect to %s", sk5Conn.ShortID(), targetAddr)
			ConnManagerInstance.Add(sk5Conn)
			if forwarder, err := NewProxyForwarder(sk5Conn, s.BridgeConn); err != nil {
				logger.Error("SOCKS5[%s] CONN, create proxy forward failed: %v", sk5Conn.ShortID(), err)
				return err
			} else {
				forwarder.Start()
				select {
				case v := <-forwarder.Done:
					ConnManagerInstance.RemoveAndClose(sk5Conn.connID)
					if v == "" || v == "Read EOF" {
						return nil
					} else {
						return errors.New(v)
					}
				case <-sk5Conn.CloseChan:
					return nil
				}

			}
		}
		return nil
	}
}

func handleDirect(sk5Conn *Socks5Conn, addr string, port int, atyp byte) error {
	shortConn := util.ShortConnID(sk5Conn.connID)
	targetAddr := fmt.Sprintf("%s:%d", addr, port)
	logger.Debug("SOCKS5[%s] handle direct start", shortConn)

	if err := sk5Conn.SetTarget(addr, port, atyp, false); err != nil {
		logger.Error("SOCKS5[%s] handle direct, set conn target info failed, error: %v", shortConn, err)
		return fmt.Errorf("[handle direct] set conn target info failed: %v", err)
	}

	logger.Info("SOCKS5[%s] handle direct, connect to %s", shortConn, targetAddr)

	if targetConn, err := net.Dial("tcp", targetAddr); err != nil {
		logger.Error("SOCKS5[%s] handle direct, connect to target failed: %v", shortConn, err)
		sk5Conn.SetConnected(false)
		if _, err := sk5Conn.Write(Socks5CmdConnectFailed()); err != nil {
			logger.Warn("SOCKS5[%s] handle direct, write Socks5CmdConnectFailed failed: %v", shortConn, err)
		}
		return fmt.Errorf("[handle direct] connect to target failed: %v", err)
	} else {
		defer func(targetConn net.Conn) {
			if err := targetConn.Close(); err != nil {
				logger.Warn("SOCKS5[%s] handle direct, close targetConn failed: %v", shortConn, err)
			}
		}(targetConn)

		logger.Info("SOCKS5[%s] handle direct, connect to target success, L:%v --> R:%v", shortConn, sk5Conn.RemoteAddr(), targetConn.RemoteAddr())
		sk5Conn.SetConnected(true)
		if _, err := sk5Conn.Write(Socks5CmdConnectSuccess()); err != nil {
			logger.Error("SOCKS5[%s] handle direct, write Socks5CmdConnectSuccess failed: %v", shortConn, err)

			return fmt.Errorf("[handle direct] write Socks5CmdConnectSuccess failed: %v", err)
		}

		forwarder := NewDirectForwarder(sk5Conn, targetConn)
		forwarder.Start()

		doneMessage := <-forwarder.Done
		close(forwarder.Done)

		if doneMessage == "" || strings.Contains(doneMessage, "EOF") {
			logger.Info("SOCKS5[%s] handle direct, done with EOF: %s", shortConn, doneMessage)
			return nil
		} else {
			logger.Error("SOCKS5[%s] handle direct, done with error: %s", shortConn, doneMessage)
			return fmt.Errorf("[handle direct] done with error: %s", doneMessage)
		}
	}
}
