package main

import (
	"fmt"
	"io"
)

func main() {
	get("jvns.ca")
}

func get(domain string) {
	session := connect()
	session.connect(domain)
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", domain)
	session.SendData([]byte(req))
	session.ReceiveData() // ignore the session ticket
	resp := session.ReceiveHTTPResponse()
	fmt.Println(string(resp))
}

func (session *Session) ReceiveHTTPResponse() []byte {
	var response []byte
	for {
		pt := session.ReceiveData()
		if string(pt) == string([]byte{48, 13, 10, 13, 10, 23}) {
			break
		}
		response = append(response, pt...)
	}
	return response
}

func (session *Session) connect(domainName string) {
	session.SendClientHello(domainName)
	session.GetServerHello()
	session.MakeHandshakeKeys()
	session.ParseServerHandshake()
	session.ClientChangeCipherSpec()
	session.ClientHandshakeFinished()
}

type Session struct {
	Conn            io.ReadWriteCloser
	ServerHello     ServerHello
	Messages        Messages
	Keys            Keys
	RecordsSent     uint8
	RecordsReceived uint8
}

func (session *Session) SendClientHello(domain string) {
	// send client hello
	conn := session.Conn
	session.Keys = KeyPair()
	clientHello := ClientHello(domain, session.Keys)
	session.Messages.ClientHello = clientHello
	send(conn, clientHello)
}

func (session *Session) GetServerHello() {
	conn := session.Conn
	record := readRecord(conn)
	if record.Type() != 0x16 {
		panic("expected server hello")
	}
	session.Messages.ServerHello = record
	session.ServerHello = parseServerHello(record.Contents())

	// ignore change cipher spec
	record = readRecord(conn)
	if record.Type() != 0x14 {
		panic("expected change cipher spec")
	}
}

func (session *Session) ParseServerHandshake() {
	record := readRecord(session.Conn)
	if record.Type() != 0x17 {
		panic("expected wrapper")
	}
	session.Messages.ServerHandshake = decrypt(session.Keys.ServerHandshakeKey, session.Keys.ServerHandshakeIV, record)
	session.MakeApplicationKeys()
}

func (session *Session) ClientChangeCipherSpec() {
	conn := session.Conn
	send(conn, []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01})
}

func (session *Session) ClientHandshakeFinished() {
	conn := session.Conn
	send(conn, session.ClientHandshakeFinishedMsg())
}
