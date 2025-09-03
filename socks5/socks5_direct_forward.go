package socks5

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/yangxm/gecko/logger"
)

type DirectForwarder struct {
	sk5Conn  *Socks5Conn
	dstConn  net.Conn
	Done     chan string
	sk5Done  chan string
	dstDone  chan string
	once     sync.Once
	retries1 atomic.Uint32
	retries2 atomic.Uint32
}

const (
	directMaxRetry = 3
)

func NewDirectForwarder(src *Socks5Conn, dst net.Conn) *DirectForwarder {
	return &DirectForwarder{
		sk5Conn: src,
		dstConn: dst,
		Done:    make(chan string),
		sk5Done: make(chan string),
		dstDone: make(chan string),
	}
}

func (f *DirectForwarder) Start() {
	logger.Info("Direct[%s] DIRECT FORWARD START", f.sk5Conn.ShortID())
	go f.pipe1()
	go f.pipe2()

	go func() {
		for {
			select {
			case v := <-f.sk5Done:
				f.once.Do(func() {
					close(f.sk5Done)
					close(f.dstDone)
					f.Done <- v
				})
			case v := <-f.dstDone:
				f.once.Do(func() {
					close(f.sk5Done)
					close(f.dstDone)
					f.Done <- v
				})
			default:
			}
		}
	}()
}

func (f *DirectForwarder) pipe1() {
	buf := make([]byte, 32*1024)

	shortConn := f.sk5Conn.ShortID()
	addr, port, atyp, isProxy := f.sk5Conn.GetTarget()
	if isProxy {
		logger.Error("Direct[%s] not a direct", shortConn)
		f.sk5Done <- "SkConn not a direct"
		return
	}
	var src = f.sk5Conn.RemoteAddr().String()
	var dst = fmt.Sprintf("%s:%d", addr, port)
	if atyp == addrTypeDomain {
		dst = fmt.Sprintf("%s:%d(%s)", addr, port, f.dstConn.RemoteAddr().String())
	} else {
		dst = f.dstConn.RemoteAddr().String()
	}

	for {
		n, rerr := f.sk5Conn.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				wn, werr := f.dstConn.Write(buf[written:n])
				if werr != nil {
					logger.Error("Direct[%s] LF:%s --> RT:%s  write error: %v", shortConn, src, dst, werr)
					f.retries1.Add(1)
					if f.retries1.Load()+f.retries2.Load() >= directMaxRetry {
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
			f.sk5Done <- v
			return
		case <-f.sk5Conn.CloseChan:
			logger.Debug("Direct[%s] LF:%v --> RT:%v  skConn closed", shortConn, src, dst)
			f.sk5Done <- "SkConn closed"
			return
		default:
		}
	}
}

func (f *DirectForwarder) pipe2() {
	buf := make([]byte, 32*1024)

	shortConn := f.sk5Conn.ShortID()
	addr, port, atyp, isProxy := f.sk5Conn.GetTarget()
	if isProxy {
		logger.Error("Direct[%s] not a direct", shortConn)
		f.dstDone <- "SkConn not a direct"
		return
	}

	var src string
	if atyp == addrTypeDomain {
		src = fmt.Sprintf("%s:%d(%s)", addr, port, f.dstConn.RemoteAddr().String())
	} else {
		src = f.dstConn.RemoteAddr().String()
	}
	var dst = f.sk5Conn.RemoteAddr().String()

	for {
		n, rerr := f.dstConn.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				wn, werr := f.sk5Conn.Write(buf[written:n])
				if werr != nil {
					logger.Error("Direct[%s] RF:%s --> LT:%s  write error: %v", shortConn, src, dst, werr)
					f.retries2.Add(1)
					if f.retries2.Load()+f.retries1.Load() >= directMaxRetry {
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
			f.dstDone <- v
			return
		default:
		}
	}
}
