package socks5

const (
	socks5Version     byte = 0x05
	socks5NoAuth      byte = 0x00
	socks5CmdConnect  byte = 0x01
	MsgTypeConnect    byte = 0x00
	MsgTypeConnectAck byte = 0x02
	MsgTypeData       byte = 0x04
	MsgTypeClose      byte = 0x08
	MsgTypeError      byte = 0x0F
	MsgFlagToServer   byte = 0x0A
	MsgFlagToClient   byte = 0x0F
	addrTypeIPv4      byte = 0x01
	addrTypeDomain    byte = 0x03
	addrTypeIPv6      byte = 0x04
)

func Socks5NoAuth() []byte {
	return []byte{socks5Version, socks5NoAuth}
}

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  |  0x00 |  1   | Variable |    2     |
func Socks5CmdConnectSuccess() []byte {
	return []byte{socks5Version, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
}

func Socks5CmdConnectFailed() []byte {
	return []byte{socks5Version, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
}
