package main

import (
	"github.com/yangxm/gecko/logger"
	"github.com/yangxm/gecko/socks5"
)

func main() {
	logger.InitLogger("")
	logger.Info("SOCKS5 SERVER START")
	server := socks5.NewClientLocalSocks5Server("", "127.0.0.1", 1080, nil)
	server.Start()
	logger.Info("SOCKS5 SERVER STOP")
}
