package main

import (
	"github.com/yangxm/gecko/logger"
	"github.com/yangxm/gecko/socks5"
)

func main() {
	logger.InitLogger("")
	logger.Info("SOCKS5 SERVER START")

	server := &socks5.Socks5Server{
		ID:       "socks5",
		BindAddr: "127.0.0.1",
		BindPort: 1080,
	}
	server.Start()
	logger.Info("SOCKS5 SERVER STOP")
}
