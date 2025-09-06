package bridge

import (
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/yangxm/gecko/coder"
	"github.com/yangxm/gecko/logger"
	"github.com/yangxm/gecko/util"
	"net/http"
	"sync"
	"time"
)

const (
	wsPingPeriod   = 10 * time.Second
	wsPongWait     = 15 * time.Second
	wsWriteWait    = 5 * time.Second
	wsSendChanSize = 32 * 1024
)

type WsTransport struct {
	url             string
	connParamGetter func() map[string]string
	receiver        Receiver
	conn            *websocket.Conn
	sendChan        chan []byte
	mutex           sync.Mutex
	closed          bool
	done            chan struct{}
}

func NewWsTransport(url string, connParamGetter func() map[string]string, receiver Receiver) (*WsTransport, error) {
	t := &WsTransport{
		url:             url,
		connParamGetter: connParamGetter,
		receiver:        receiver,
		sendChan:        make(chan []byte, wsSendChanSize),
		done:            make(chan struct{}),
	}
	logger.Debug("[WSTP] WsTransport created: %s", t.url)
	if err := t.connect(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *WsTransport) connect() error {
	logger.Info("[WSTP] dialing to %s", t.url)

	var httpHeader http.Header
	if t.connParamGetter != nil {
		httpHeader = make(http.Header)
		params := t.connParamGetter()
		for k, v := range params {
			httpHeader.Add(k, v)
		}
	}
	logger.Debug("[WSTP] dialing to %s with header: %v", t.url, httpHeader)
	if conn, _, err := websocket.DefaultDialer.Dial(t.url, httpHeader); err != nil {
		logger.Error("[WSTP] dialing to %s error: %v", t.url, err)
		return fmt.Errorf("dialing error: %v", err)
	} else {
		t.conn = conn
	}

	if err := t.conn.SetReadDeadline(time.Now().Add(wsPongWait)); err != nil {
		logger.Error("[WSTP] connect, set read deadline error: %v", err)
		return fmt.Errorf("set read deadline error: %v", err)
	}

	t.conn.SetPongHandler(func(appData string) error {
		if err := t.conn.SetReadDeadline(time.Now().Add(wsPongWait)); err != nil {
			logger.Error("[WSTP] pong handler, set read deadline error: %v", err)
			return fmt.Errorf("set read deadline error: %v", err)
		}
		logger.Debug("[WSTP] pong received")
		return nil
	})

	go t.readLoop()
	go t.writeLoop()
	go t.heartbeatLoop()

	logger.Debug("[WSTP] connected to %s", t.url)
	return nil
}

func (t *WsTransport) readLoop() {
	defer t.reconnect()

	for {
		_, bytes, err := t.conn.ReadMessage()
		if err != nil {
			logger.Error("[WSTP] read error: %v", err)
			return
		}
		logger.Debug("[WSTP] read: %d", len(bytes))
		if t.receiver != nil {
			t.receiver.OnReceived(bytes)
		}
	}
}

func (t *WsTransport) writeLoop() {
	for {
		select {
		case msg, ok := <-t.sendChan:
			if !ok {
				return
			}
			if err := t.conn.SetWriteDeadline(time.Now().Add(wsWriteWait)); err != nil {
				logger.Error("[WSTP] write, set write deadline error: %v", err)
				return
			}

			if err := t.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
				logger.Error("[WSTP] write error: %s", err.Error())
				return
			}
		case <-t.done:
			return
		}
	}
}

func (t *WsTransport) heartbeatLoop() {
	ticker := time.NewTicker(wsPingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.mutex.Lock()
			if t.closed {
				t.mutex.Unlock()
				return
			}
			if err := t.conn.SetWriteDeadline(time.Now().Add(wsWriteWait)); err != nil {
				t.mutex.Unlock()
				logger.Error("[WSTP] send ping, set write deadline error: %v", err)
				return
			}

			if err := t.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				t.mutex.Unlock()
				logger.Error("[WSTP] send ping error: %v", err)
				return
			}
			logger.Debug("[WSTP] send ping")
			t.mutex.Unlock()
		case <-t.done:
			return
		}
	}
}

func (t *WsTransport) Send(_type, flag byte, clientID, connID string, serverType byte, data []byte) error {
	shortConn := util.ShortConnID(connID)
	dataLen := len(data)
	logger.Debug("[WSTP] [%s] send %d start", shortConn, dataLen)

	if t.isClosed() {
		logger.Error("[WSTP] [%s] send %d error: connection is closed", shortConn, dataLen)
		return fmt.Errorf("connection is closed")
	}

	if encodedData, err := coder.Encode(_type, flag, clientID, connID, serverType, data); err != nil {
		logger.Error("[WSTP] [%s] send %d error: encode error: %v", shortConn, dataLen, err)
		return fmt.Errorf("[WSTP] send, encode error: %v", err)
	} else {
		select {
		case t.sendChan <- encodedData:
			logger.Debug("[WSTP] [%s] send %d -> %d", shortConn, dataLen, len(encodedData))
			return nil
		default:
			logger.Error("[WSTP] [%s] send %d -> %d error: send channel full, drop message", shortConn, dataLen, len(encodedData))
			return fmt.Errorf("send channel full")
		}
	}
}

func (t *WsTransport) reconnect() {
	if t.isClosed() {
		return
	}

	logger.Info("[WSTP] reconnecting...")
	if err := t.conn.Close(); err != nil {
		logger.Warn("[WSTP] close old connection error: %v", err)
	}

	i := 0
	for {
		time.Sleep(time.Duration(1<<i) * time.Second)
		if err := t.connect(); err == nil {
			logger.Info("[WSTP] reconnected successfully")
			return
		} else {
			i++
			logger.Error("[WSTP] reconnect error: %v, retries: %d", err, i)
		}
	}
}

func (t *WsTransport) Close() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	close(t.done)
	close(t.sendChan)
	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			logger.Error("[WSTP] close connection error: %v", err)
			return
		}
	}
	logger.Info("[WSTP] closed")
}

func (t *WsTransport) isClosed() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.closed
}
