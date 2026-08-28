// UDP is a package that provides functionality for handling UDP traffic over TCP connections.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

var (
	udpMu             sync.Mutex
	activeTunnels     = make(map[string]chan []byte)
	udpToTCPChannels  = make(map[string]chan []byte)
)

// readFromConn reads data from a net.Conn and sends it to a channel.
func readFromConn(l *slog.Logger, conn net.Conn, c chan<- []byte) {
	defer conn.Close()
	defer close(c) // Close the channel when done.
	buf := make([]byte, 2048)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}

		n, err := conn.Read(buf)
		if err != nil && errors.Is(err, io.EOF) {
			return
		}

		if err != nil {
			l.Debug("connection closed", "protocol", "udp", "address", conn.RemoteAddr(), "error", err.Error())
			return
		}

		if n > 0 {
			c <- append([]byte(nil), buf[:n]...) // Send a copy of the slice.
		}
	}
}

// handleUDPOverTCP handles UDP-over-TCP traffic.
func handleUDPOverTCP(l *slog.Logger, ob outbound, conn net.Conn, destination string) {
	// On return, delete the destination from the map of active tunnels
	defer func() {
		udpMu.Lock()
		delete(activeTunnels, destination)
		udpMu.Unlock()
	}()

	// Store a byte channel in the map of active tunnels. The data read
	// from the UDP socket is sent on this channel.
	udpMu.Lock()
	activeTunnels[destination] = make(chan []byte)
	tunnelCh := activeTunnels[destination]
	udpMu.Unlock()

	wsReadDataChan := make(chan []byte)
	go readFromConn(l, conn, wsReadDataChan)

	for {
		select {
		case dataFromWS := <-wsReadDataChan:
			if dataFromWS == nil || len(dataFromWS) < 8 {
				return
			}

			udpWriteChan, err := getOrCreateUDPChan(l, ob, destination, string(dataFromWS[:8]))
			if err != nil {
				l.Debug("unable to connect to destination", "protocol", "udp", "address", destination, "error", err.Error())
				continue
			}

			udpWriteChan <- dataFromWS

		case dataFromUDP := <-tunnelCh:
			if dataFromUDP == nil {
				continue
			}

			if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
					return
				}

			if _, err := conn.Write(dataFromUDP); err != nil {
				l.Debug("can't write to socket", "protocol", "udp", "address", destination, "error", err.Error())
				return
			}
		}
	}
}

// getOrCreateUDPChan returns an existing UDP channel or creates a new one.
func getOrCreateUDPChan(l *slog.Logger, ob outbound, destination, header string) (chan []byte, error) {
	channelID := destination + header

	udpMu.Lock()
	if udpWriteChan, ok := udpToTCPChannels[channelID]; ok {
		udpMu.Unlock()
		return udpWriteChan, nil
	}

	udpToTCPChannels[channelID] = make(chan []byte)
	ch := udpToTCPChannels[channelID]
	udpMu.Unlock()

	udpConn, err := ob.DialContext(context.Background(), "udp", destination)
	if err != nil {
		udpMu.Lock()
		delete(udpToTCPChannels, channelID)
		udpMu.Unlock()
		return nil, err
	}

	udpReadChanFromConn := make(chan []byte)
	go readFromConn(l, udpConn, udpReadChanFromConn)

	go func() {
		defer func() {
			udpMu.Lock()
			delete(udpToTCPChannels, channelID)
			udpMu.Unlock()
			udpConn.Close()
		}()

		for {
			select {
			case dataFromWS := <-ch:
				if len(dataFromWS) < 8 {
					return
				}

				if err := udpConn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
					return
				}

				_, err := udpConn.Write(dataFromWS[8:])
				if err != nil {
					return
				}

			case dataFromUDP := <-udpReadChanFromConn:
				if dataFromUDP == nil {
					return
				}

				udpMu.Lock()
				tunnelCh, ok := activeTunnels[destination]
				udpMu.Unlock()

				if ok && tunnelCh != nil {
					tunnelCh <- append([]byte(header[6:]), dataFromUDP...)
				}
			}
		}
	}()

	return ch, nil
}
