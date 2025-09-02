package socks5

import (
	"io"
	"net"
	"sync"

	"github.com/yangxm/gecko/logger"
)

type DirectForwarder struct {
	Src  *Socks5Conn
	Dst  net.Conn
	Done chan struct{}
	once sync.Once
}

func NewDirectForwarder(src *Socks5Conn, dst net.Conn) *DirectForwarder {
	return &DirectForwarder{
		Src:  src,
		Dst:  dst,
		Done: make(chan struct{}),
	}
}

func (f *DirectForwarder) Start() {
	logger.Info("SOCKS5[%s] DIRECT FORWARD START", f.Src.ShortID())
	go f.pipe(f.Src.Conn, f.Dst)
	go f.pipe(f.Dst, f.Src.Conn)
}

func (f *DirectForwarder) pipe(src, dst net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				wn, werr := dst.Write(buf[written:n])
				if werr != nil {
					logger.Error("SOCKS5[%s] F:%v --> T:%v  WRITE ERR: %v", f.Src.ShortID(), src.RemoteAddr(), dst.RemoteAddr(), werr)
					break
				}
				logger.Debug("SOCKS5[%s] F:%v --> T:%v  %d", f.Src.ShortID(), src.RemoteAddr(), dst.RemoteAddr(), wn)
				written += wn
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				logger.Error("SOCKS5[%s] F:%v --> T:%v  READ ERR: %v", f.Src.ShortID(), src.RemoteAddr(), dst.RemoteAddr(), rerr)
			} else {
				logger.Debug("SOCKS5[%s] F:%v --> T:%v  READ EOF", f.Src.ShortID(), src.RemoteAddr(), dst.RemoteAddr())
			}
			break
		}

		// 检查 Done channel 是否被关闭（另一方退出）
		select {
		case <-f.Done:
			return
		default:
		}
	}

	if tc, ok := dst.(*net.TCPConn); ok {
		tc.CloseWrite()
		logger.Debug("SOCKS5[%s] CLOSE WRITE %v", f.Src.ShortID(), dst.RemoteAddr())
	} else {
		dst.Close()
		logger.Debug("SOCKS5[%s] CLOSE %v", f.Src.ShortID(), dst.RemoteAddr())
	}
	// 确保 Done 只关闭一次
	f.once.Do(func() {
		close(f.Done)
	})
}
