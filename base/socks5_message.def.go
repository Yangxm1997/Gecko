package base

const (
	Socks5Version     byte = 0x05
	Socks5NoAuth      byte = 0x00
	Socks5CmdConnect  byte = 0x01
	MsgTypeConnect    byte = 0x00
	MsgTypeConnectAck byte = 0x02
	MsgTypeData       byte = 0x04
	MsgTypeClose      byte = 0x08
	MsgTypeError      byte = 0x0F
	MsgFlagToServer   byte = 0x0A
	MsgFlagToClient   byte = 0x0F
	AddrTypeIPv4      byte = 0x01
	AddrTypeDomain    byte = 0x03
	AddrTypeIPv6      byte = 0x04
)

func Socks5AuthLegacy() []byte {
	return []byte{Socks5Version, Socks5NoAuth}
}

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  |  0x00 |  1   | Variable |    2     |
func Socks5CmdConnectSuccess() []byte {
	return []byte{Socks5Version, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
}

func Socks5CmdConnectFailed() []byte {
	return []byte{Socks5Version, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
}
