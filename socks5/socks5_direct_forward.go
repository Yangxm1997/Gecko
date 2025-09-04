package socks5

import (
	"fmt"
	"github.com/yangxm/gecko/util"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/yangxm/gecko/logger"
)

type DirectForwarder struct {
	sk5Conn       *Socks5Conn
	dstConn       net.Conn
	Done          chan string
	sk5Done       chan string
	dstDone       chan string
	closeConnOnce sync.Once
	closeChanOnce sync.Once
	retries1      atomic.Uint32
	retries2      atomic.Uint32
	wg            sync.WaitGroup
}

const (
	directMaxRetry = 3
)

func NewDirectForwarder(src *Socks5Conn, dst net.Conn) *DirectForwarder {
	f := &DirectForwarder{
		sk5Conn: src,
		dstConn: dst,
		Done:    make(chan string),
		sk5Done: make(chan string),
		dstDone: make(chan string),
	}

	logger.Debug("Direct[%s] forward created", util.ShortConnID(f.sk5Conn.connID))
	return f
}

func (f *DirectForwarder) Start() {
	logger.Debug("Direct[%s] forward start", util.ShortConnID(f.sk5Conn.connID))
	go f.pipe1()
	go f.pipe2()
	go func() {
		select {
		case msg := <-f.sk5Done:
			f.Done <- msg
		case msg := <-f.dstDone:
			f.Done <- msg
		}
	}()
}

func (f *DirectForwarder) pipe1() {
	buf := make([]byte, 32*1024)
	shortConn := f.sk5Conn.ShortID()

	if !f.isDirect() {
		f.sk5Done <- "SkConn not a direct"
		return
	}

	src, dst := f.getAddr()

	for {
		f.wg.Add(1)
		n, rerr := f.sk5Conn.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				wn, werr := f.dstConn.Write(buf[written:n])
				if werr != nil {
					logger.Error("Direct[%s] LF:%s --> RT:%s  write error: %v", shortConn, src, dst, werr)
					f.retries1.Add(1)
					if f.retries1.Load()+f.retries2.Load() >= directMaxRetry {
						f.wg.Done()
						f.sk5Done <- "Write to remote error: " + werr.Error()
						return
					}
				} else {
					logger.Debug("Direct[%s] LF:%s --> RT:%s  write  %d", shortConn, src, dst, wn)
					f.retries1.Store(0)
				}
				written += wn
			}
		}
		if rerr != nil {
			f.wg.Done()
			if rerr != io.EOF {
				logger.Error("Direct[%s] LF:%s --> RT:%s  read error: %v", shortConn, src, dst, rerr)
				f.sk5Done <- "Read from local error: " + rerr.Error()
			} else {
				logger.Debug("Direct[%s] LF:%s --> RT:%s  read EOF", shortConn, src, dst)
				f.sk5Done <- "Read local EOF"
			}
			return
		}

		select {
		case v := <-f.dstDone:
			f.wg.Done()
			f.sk5Done <- v
			return
		case <-f.sk5Conn.CloseChan:
			logger.Debug("Direct[%s] LF:%v --> RT:%v  skConn closed", shortConn, src, dst)
			f.wg.Done()
			f.sk5Done <- "SkConn closed"
			return
		default:
		}
		f.wg.Done()
	}
}

func (f *DirectForwarder) pipe2() {
	buf := make([]byte, 32*1024)
	shortConn := f.sk5Conn.ShortID()

	if !f.isDirect() {
		f.dstDone <- "SkConn not a direct"
		return
	}

	dst, src := f.getAddr()

	for {
		f.wg.Add(1)
		n, rerr := f.dstConn.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				wn, werr := f.sk5Conn.Write(buf[written:n])
				if werr != nil {
					logger.Error("Direct[%s] RF:%s --> LT:%s  write error: %v", shortConn, src, dst, werr)
					f.retries2.Add(1)
					if f.retries2.Load()+f.retries1.Load() >= directMaxRetry {
						f.wg.Done()
						f.dstDone <- "Write to local error: " + werr.Error()
						return
					}
				} else {
					logger.Debug("Direct[%s] RF:%s --> LT:%s  write  %d", shortConn, src, dst, wn)
					f.retries2.Store(0)
				}
				written += wn
			}
		}

		if rerr != nil {
			f.wg.Done()
			if rerr != io.EOF {
				logger.Error("Direct[%s] RF:%s --> LT:%s  read error: %v", shortConn, src, dst, rerr)
				f.dstDone <- "Read from remote error: " + rerr.Error()
			} else {
				logger.Debug("Direct[%s] RF:%s --> LT:%s  read EOF", shortConn, src, dst)
				f.dstDone <- "Read remote EOF"
			}
			return
		}

		select {
		case v := <-f.sk5Done:
			f.wg.Done()
			f.dstDone <- v
			return
		default:
		}
		f.wg.Done()
	}
}

func (f *DirectForwarder) CloseConn() {
	f.closeConnOnce.Do(func() {
		shortConn := f.sk5Conn.ShortID()
		src, dst := f.getAddr()

		if dstTcp, ok := f.dstConn.(*net.TCPConn); ok {
			if err := dstTcp.CloseWrite(); err != nil {
				logger.Error("Direct[%s] closed write for dstConn %s error: %v", shortConn, dst, err)
			} else {
				logger.Debug("Direct[%s] closed write for dstConn %s", shortConn, dst)
			}
		}

		if sk5Tcp, ok := f.sk5Conn.Conn.(*net.TCPConn); ok {
			if err := sk5Tcp.CloseWrite(); err != nil {
				logger.Error("Direct[%s] closed write for sk5Conn %s error: %v", shortConn, src, err)
			} else {
				logger.Debug("Direct[%s] closed write for sk5Conn %s", shortConn, src)
			}
		}

		f.wg.Wait()

		if err := f.dstConn.Close(); err != nil {
			logger.Error("Direct[%s] closed dstConn %s error: %v", shortConn, dst, err)
		} else {
			logger.Debug("Direct[%s] closed dstConn %s", shortConn, dst)
		}

		if err := f.sk5Conn.Close(); err != nil {
			logger.Error("Direct[%s] closed sk5Conn %s error: %v", shortConn, dst, err)
		} else {
			logger.Debug("Direct[%s] closed sk5Conn %s", shortConn, dst)
		}

		close(f.sk5Done)
		close(f.dstDone)
		close(f.Done)
	})
}

func (f *DirectForwarder) isDirect() bool {
	_, _, _, isProxy := f.sk5Conn.GetTarget()
	if isProxy {
		logger.Error("Direct[%s] skConn is not a direct", util.ShortConnID(f.sk5Conn.shortID))
		return false
	}
	return true
}

func (f *DirectForwarder) getAddr() (string, string) {
	addr, port, atyp, _ := f.sk5Conn.GetTarget()
	var src = f.sk5Conn.RemoteAddr().String()
	var dst string
	if atyp == addrTypeDomain {
		dst = fmt.Sprintf("%s:%d(%s)", addr, port, f.dstConn.RemoteAddr().String())
	} else {
		dst = f.dstConn.RemoteAddr().String()
	}
	return src, dst
}
