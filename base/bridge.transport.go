package base

type BridgeTransport interface {
	Send(_type, flag byte, clientID, connID string, serverType byte, data []byte) (int, error)
	Close()
}
