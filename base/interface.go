package base

type BridgeReceiver interface {
	OnReceived(data []byte)
}

type BridgeTransport interface {
	Send(_type, flag byte, clientID, connID string, serverType byte, data []byte) (int, error)
	Close()
}
