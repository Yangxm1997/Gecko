package bridge

import (
	"fmt"
	"github.com/yangxm/gecko/coder"
	"github.com/yangxm/gecko/entity"
	"github.com/yangxm/gecko/logger"
	"github.com/yangxm/gecko/socks5"
	"github.com/yangxm/gecko/util"
	"google.golang.org/protobuf/proto"
	"sync/atomic"
)

type ClientHandler struct {
	traceIdCounter atomic.Uint32
	clientID       string
}

func NewClientHandler(clientID string) *ClientHandler {
	return &ClientHandler{clientID: clientID}
}

func (c *ClientHandler) nextTraceID() string {
	for {
		old := c.traceIdCounter.Load()
		newVal := old + 1
		if newVal > 999999 {
			newVal = 0
		}
		if c.traceIdCounter.CompareAndSwap(old, newVal) {
			return fmt.Sprintf("%06d", newVal)
		}
	}
}

func (c *ClientHandler) OnClientReceived(data []byte) {
	traceID := c.nextTraceID()
	logger.Debug("[%s] RECV %d", traceID, len(data))

	if data == nil || len(data) == 0 {
		logger.Warn("[%s] RECV DONE, data bytes is null or empty", traceID)
		return
	}
	var message entity.Message
	if err := proto.Unmarshal(data, &message); err != nil {
		logger.Warn("[%s] RECV ERROR, unmarshal data to Message failed: %v", traceID, err)
		return
	}
	header := message.GetHeader()
	if header == nil {
		logger.Error("[%s] RECV ERROR, header is nil", traceID)
		return
	}
	logger.Debug("[%s] RECV, unmarshal data success, type: %v, flag: %v, ConnID: %v, clientID: %v, serverType: %v",
		traceID, header.Type, header.Flag, header.ConnID, header.ClientID, header.ServerType)

	if c.clientID != header.ClientID {
		logger.Error("[%s] RECV ERROR, clientID not match, expected: %s, actual: %v", traceID, c.clientID, header.ClientID)
		return
	}

	if !socks5.IsSk5ConnExist(header.ConnID) {
		logger.Error("[%s] RECV ERROR, ConnID not exist, ConnID: %v", traceID, header.ConnID)
		return
	}

	if header.Flag == nil || len(header.Flag) != 1 || socks5.MsgFlagToClient != header.Flag[0] {
		logger.Error("[%s] RECV ERROR, illegal flag %v", traceID, header.Flag)
		return
	}

	var _type byte
	if header.Type == nil || len(header.Type) != 1 {
		logger.Error("[%s] RECV ERROR, illegal type %v", traceID, header.Type)
		return
	}
	_type = header.Type[0]

	if decodedData, err := coder.Decode(&message); err != nil {
		logger.Error("[%s] RECV ERROR, decoded failed: %v", traceID, err)
		return
	} else {
		switch _type {
		case socks5.MsgTypeData:
			c.handleData(traceID, header.ConnID, decodedData)
		case socks5.MsgTypeConnectAck:
			c.handleConnectAck(traceID, header.ConnID, decodedData)
		case socks5.MsgTypeClose:
			c.handleClose(traceID, header.ConnID, decodedData)
		case socks5.MsgTypeError:
		default:
			logger.Warn("[%s] RECV ERROR, unknown type %v", traceID, _type)
		}
	}
}

func (c *ClientHandler) handleData(traceID, connID string, data []byte) {
	shortConn := util.ShortConnID(connID)
	logger.Debug("[%s] RECV [%s], handling Data", traceID, shortConn)
	if wn, err := socks5.WriteToSk5ConnIfConnected(connID, data); err != nil {
		logger.Error("[%s] RECV [%s] ERROR, write data to client failed: %v", traceID, shortConn, err)
		socks5.RemoveAndCloseSk5Conn(connID)
	} else {
		logger.Debug("[%s] RECV [%s], write data to client success, %d", traceID, shortConn, wn)
	}
}

func (c *ClientHandler) handleConnectAck(traceID, connID string, data []byte) {
	shortConn := util.ShortConnID(connID)
	logger.Debug("[%s] RECV [%s], handling ConnectAck", traceID, shortConn)
	var notif entity.Notification
	if err := proto.Unmarshal(data, &notif); err != nil {
		logger.Error("[%s] RECV [%s] ERROR, handling ConnectAck, unmarshal data failed: %v", traceID, shortConn, err)
		return
	}

	logger.Debug("[%s] RECV [%s], handling ConnectAck, Addr --> %s:%d %v", traceID, shortConn, notif.Addr, notif.Port, notif.Atyp)
	sk5Conn, res := socks5.GetSk5Conn(connID)
	if !res || sk5Conn == nil {
		logger.Error("[%s] RECV [%s] ERROR, handling ConnectAck, get conn failed", traceID, shortConn)
		return
	}
	var respBytes []byte
	if notif.Code == 0 {
		logger.Debug("[%s] RECV [%s], handling ConnectAck, success, code: %d, message: %s", traceID, shortConn, notif.Code, notif.Message)
		respBytes = socks5.Socks5CmdConnectSuccess()
		sk5Conn.SetConnected(true)

	} else {
		logger.Error("[%s] RECV [%s], handling ConnectAck, failed, code: %d, message: %s", traceID, shortConn, notif.Code, notif.Message)
		respBytes = socks5.Socks5CmdConnectFailed()
		sk5Conn.SetConnected(false)
	}

	if wn, err := socks5.WriteToSk5Conn(connID, respBytes); err != nil {
		logger.Error("[%s] RECV [%s] ERROR, write ConnectAck to client failed: %v", traceID, shortConn, err)
		socks5.RemoveAndCloseSk5Conn(connID)
	} else {
		logger.Debug("[%s] RECV [%s], write ConnectAck to client success, %d", traceID, shortConn, wn)
	}
}

func (c *ClientHandler) handleClose(traceID, connID string, data []byte) {
	shortConn := util.ShortConnID(connID)
	logger.Debug("[%s] RECV [%s], handling Close", traceID, shortConn)
	var notif entity.Notification
	if err := proto.Unmarshal(data, &notif); err != nil {
		logger.Error("[%s] RECV [%s] ERROR, handling Close, unmarshal data failed: %v", traceID, shortConn, err)
	} else {
		logger.Debug("[%s] RECV [%s], handling Close, Addr --> %s:%d %v, code: %d, message: %s",
			traceID, shortConn, notif.Addr, notif.Port, notif.Atyp, notif.Code, notif.Message)
	}
	socks5.RemoveAndCloseSk5Conn(connID)
	logger.Debug("[%s] RECV [%s], handling Close, closed conn", traceID, shortConn)
}

func (c *ClientHandler) handleError(traceID, connID string, data []byte) {
	shortConn := util.ShortConnID(connID)
	logger.Debug("[%s] RECV [%s], handling Error", traceID, shortConn)
	var notif entity.Notification
	if err := proto.Unmarshal(data, &notif); err != nil {
		logger.Error("[%s] RECV [%s] ERROR, handling Error, unmarshal data failed: %v", traceID, shortConn, err)
	} else {
		logger.Error("[%s] RECV [%s], handling Error, Addr --> %s:%d %v, code: %d, message: %s",
			traceID, shortConn, notif.Addr, notif.Port, notif.Atyp, notif.Code, notif.Message)
	}

	socks5.RemoveAndCloseSk5Conn(connID)
	logger.Debug("[%s] RECV [%s], handling Error, closed conn", traceID, shortConn)
}
