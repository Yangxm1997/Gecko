package socks5

import (
	"fmt"
	"io"
	"net"

	"github.com/yangxm/gecko/logger"
)

type Socks5Server struct {
	ID       string
	BindAddr string
	BindPort int
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
	if err := s.handleAuth(sk5Conn); err != nil {
		logger.Error("SOCKS5[%s] AUTH FAILED, ERR: %v", sk5Conn.ShortID(), err)
		return
	}

	if err := s.handleRequest(sk5Conn); err != nil {
		logger.Error("SOCKS5[%s] CONN FAILED, ERR: %v", sk5Conn.ShortID(), err)
		return
	}
}

func (s *Socks5Server) handleAuth(sk5Conn *Socks5Conn) error {
	logger.Debug("SOCKS5[%s] AUTH", sk5Conn.ShortID())
	buf := make([]byte, 256)

	if n, err := io.ReadFull(sk5Conn, buf[:2]); err != nil || n != 2 {
		logger.Error("SOCKS5[%s] AUTH, READ FAILED, N: %d, ERR: %v", sk5Conn.ShortID(), n, err)
		var errMsg string
		if err != nil {
			errMsg = fmt.Sprintf("%v", err)
		} else {
			errMsg = fmt.Sprintf("N: %d", n)
		}
		return fmt.Errorf("SOCKS5 AUTH, READ FAILED: %s", errMsg)
	} else {
		ver, nMethods := buf[0], buf[1]
		logger.Debug("SOCKS5[%s] AUTH, VER: %v, NMETHODS: %v", sk5Conn.ShortID(), ver, nMethods)
		if ver != socks5Version {
			logger.Error("SOCKS5[%s] AUTH FAILED, INVALID VER %v", sk5Conn.ShortID(), ver)
			return fmt.Errorf("SOCKS5 AUTH, INVALID VER %v", ver)
		}

		if _, err := io.ReadFull(sk5Conn, buf[:nMethods]); err != nil {
			logger.Error("SOCKS5[%s] AUTH, READ METHODS FAILED, ERR: %v", sk5Conn.ShortID(), err)
			return fmt.Errorf("SOCKS5 AUTH, READ METHODS FAILED: %v", err)
		}
		logger.Debug("SOCKS5[%s] AUTH, METHODS: %v", sk5Conn.ShortID(), buf[:nMethods])

		if _, err := sk5Conn.Write(Socks5NoAuth()); err != nil {
			logger.Error("SOCKS5[%s] AUTH FAILED, WRITE RESP FAILED, ERR: %v", sk5Conn.ShortID(), err)
			return fmt.Errorf("SOCKS5 AUTH, WRITE RESP FAILED: %v", err)
		}
		logger.Debug("SOCKS5[%s] AUTH, WRITE RESP SUCCESS", sk5Conn.ShortID())
	}
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
		if HostWhiteList().Contains(addr, atyp == addrTypeDomain) {
			sk5Conn.SetTarget(addr, port, atyp, true)
			targetAddr := fmt.Sprintf("%s:%d", addr, port)
			logger.Info("SOCKS5[%s] CONN, DIRECT CONNECT TO %s", sk5Conn.ShortID(), targetAddr)

			if targetConn, err := net.Dial("tcp", targetAddr); err != nil {
				logger.Error("SOCKS5[%s] CONN, CONNECT TO TARGET FAILED, ERR: %v", sk5Conn.ShortID(), err)
				sk5Conn.SetConnected(false)
				sk5Conn.Write(Socks5CmdConnectFailed())
				return fmt.Errorf("SOCKS5 CONN, CONNECT TO TARGET FAILED: %v", err)
			} else {
				logger.Info("SOCKS5[%s] CONN, CONNECT TO TARGET SUCCESS, L:%v --> R:%v", sk5Conn.ShortID(),
					sk5Conn.RemoteAddr(), targetConn.RemoteAddr())
				sk5Conn.SetConnected(true)
				sk5Conn.Write(Socks5CmdConnectSuccess())
				go func() {
					defer targetConn.Close()
					for {
						s.directForward(targetConn, sk5Conn)
					}
				}()
				go func() {
					defer sk5Conn.Close()
					for {
						s.directForward(sk5Conn, targetConn)
					}
				}()

			}
		}
		return nil
	}
}

func (s *Socks5Server) directForward(dst net.Conn, src net.Conn) {
	if n, err := io.Copy(dst, src); err != nil && err != io.EOF {
		logger.Error("DIRECT F:%v --> T:%v, ERR: %v", src.RemoteAddr(), dst.RemoteAddr(), err)
	} else {
		logger.Debug("DIRECT F:%v --> T:%v, N: %d", src.RemoteAddr(), dst.RemoteAddr(), n)
	}
}
