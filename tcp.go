package main

import "net"

func handleTCP(lConn, rConn net.Conn) {
	defer lConn.Close()
	defer rConn.Close()
	go Copy(rConn, lConn)
	Copy(lConn, rConn)
}
