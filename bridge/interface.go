package bridge

type Receiver interface {
	OnReceived(data []byte)
}

type Transport interface {
	Send(_type, flag byte, clientID, connID string, serverType byte, data []byte) error
	Close()
}
