package bridge

type Receiver interface {
	OnReceived(data []byte)
}
