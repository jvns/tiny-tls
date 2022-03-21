package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockConn struct {
	Reader io.Reader
}

func (c MockConn) Read(data []byte) (n int, err error)  { return c.Reader.Read(data) }
func (c MockConn) Write(data []byte) (n int, err error) { return len(data), nil }
func (c MockConn) Close() error                         { return nil }

func readHex(filename string) []byte {
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	// strip newline
	data = data[:len(data)-1]
	decoded, err := hex.DecodeString(string(data))
	if err != nil {
		panic(err)
	}
	return decoded
}

func decodehex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHandshake(t *testing.T) {
	responses := concatenate(
		readHex("test/server-hello.hex"),
		decodehex("140303000101"), // change cipher spec
		readHex("test/wrapper.hex"),
	)
	conn := MockConn{bytes.NewReader(responses)}
	var session = Session{Conn: conn}

	session.Messages.ClientHello = readHex("test/client-hello.hex")
	session.Keys.Private = readHex("test/client-ephemeral-private.hex")

	session.GetServerHello()
	session.MakeHandshakeKeys()

	assert.Equal(t, hex.EncodeToString(session.Keys.ClientHandshakeKey), "7154f314e6be7dc008df2c832baa1d39")
	assert.Equal(t, hex.EncodeToString(session.Keys.ServerHandshakeKey), "844780a7acad9f980fa25c114e43402a")
	assert.Equal(t, hex.EncodeToString(session.Keys.ClientHandshakeIV), "71abc2cae4c699d47c600268")
	assert.Equal(t, hex.EncodeToString(session.Keys.ServerHandshakeIV), "4c042ddc120a38d1417fc815")

	session.ParseServerHandshake()

	assert.Equal(t, hex.EncodeToString(session.Keys.ClientApplicationKey), "49134b95328f279f0183860589ac6707")
	assert.Equal(t, hex.EncodeToString(session.Keys.ClientApplicationIV), "bc4dd5f7b98acff85466261d")
	assert.Equal(t, hex.EncodeToString(session.Keys.ServerApplicationKey), "0b6d22c8ff68097ea871c672073773bf")
	assert.Equal(t, hex.EncodeToString(session.Keys.ServerApplicationIV), "1b13dd9f8d8f17091d34b349")

	verifyData := "976017a77ae47f1658e28f7085fe37d149d1e9c91f56e1aebbe0c6bb054bd92b"
	assert.Equal(t, verifyData, hex.EncodeToString(session.VerifyData()))

	handshakeFinished := readHex("test/client-handshake-finished.hex")
	assert.Equal(t, hex.EncodeToString(handshakeFinished), hex.EncodeToString(session.ClientHandshakeFinishedMsg()))
	encryptedPing := "1703030015c74061535eb12f5f25a781957874742ab7fb305dd5"
	assert.Equal(t, hex.EncodeToString(session.EncryptApplicationData([]byte("ping"))), encryptedPing)
}
