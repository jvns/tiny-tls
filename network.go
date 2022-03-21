package main

import (
	"encoding/binary"
	"io"
	"net"
)

func send(conn io.Writer, buf []byte) {
	n, err := conn.Write(buf)
	if err != nil {
		panic(err)
	}
	if n != len(buf) {
		panic("didn't send all bytes")
	}
}

func readRecord(reader io.Reader) Record {
	buf := make([]byte, 5)
	n, err := reader.Read(buf)
	if err != nil {
		panic(err)
	}
	if n != 5 {
		panic("didn't read 5 bytes")
	}
	length := binary.BigEndian.Uint16(buf[3:])
	contents := read(int(length), reader)
	return concatenate(buf, contents)
}

func read(length int, reader io.Reader) []byte {
	var buf []byte
	for len(buf) != length {
		buf = append(buf, readUpto(length-len(buf), reader)...)
	}
	return buf
}

func readUpto(length int, reader io.Reader) []byte {
	buf := make([]byte, length)
	n, err := reader.Read(buf)
	if err != nil {
		panic(err)
	}
	return buf[:n]
}

func connect() Session {
	conn, err := net.Dial("tcp", "jvns.ca:443")
	if err != nil {
		panic(err)
	}
	return Session{Conn: conn}
}
