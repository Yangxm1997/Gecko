package bridge

import (
	"fmt"
	"github.com/yangxm/gecko/coder"
	"github.com/yangxm/gecko/logger"
	"github.com/yangxm/gecko/util"
	"net"
)

type Transport struct {
	conn net.Conn
}

func (t *Transport) send(_type, flag byte, clientID, connID string, serverType byte, data []byte) (int, error) {
	logger.Debug("[TSP] send [%s] %d start", util.ShortConnID(connID), len(data))
	if encodedData, err := coder.Encode(_type, flag, clientID, connID, serverType, data); err != nil {
		return 0, fmt.Errorf("[TSP] send, encode error: %v", err)
	} else {
		wn, werr := t.conn.Write(encodedData)
		if werr != nil {
			return 0, fmt.Errorf("[TSP] send, write error: %v", werr)
		}

		dataLen := len(encodedData)
		if wn != dataLen {
			logger.Warn("[TSP] send, expected: %d, actual: %d", dataLen, wn)
		}
		logger.Debug("[TSP] send [%s] %d done", util.ShortConnID(connID), wn)
		return wn, nil
	}
}
