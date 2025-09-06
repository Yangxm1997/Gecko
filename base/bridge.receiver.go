package base

type BridgeReceiver interface {
	OnReceived(data []byte)
}
