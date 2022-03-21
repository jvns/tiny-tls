package main

import (
	"encoding/binary"

	"golang.org/x/crypto/cryptobyte"
)

type Messages struct {
	ClientHello     Record
	ServerHello     Record
	ServerHandshake DecryptedRecord
}
type DecryptedRecord []byte

func (r *DecryptedRecord) Type() byte {
	return (*r)[len(*r)-1]
}

func (r *DecryptedRecord) Contents() []byte {
	return (*r)[:len(*r)-1]
}

type Record []byte

func (r *Record) Contents() []byte {
	return (*r)[5:]
}

func (r *Record) Type() byte {
	return (*r)[0]
}

type ServerHello struct {
	Random    []byte
	PublicKey []byte
}

/** client hello **/

func ClientHello(name string, keys Keys) []byte {
	extensions := concatenate(
		Extension(0x0, ServerName(name)),                // SNI extension
		Extension(0x0a, []byte{0x00, 0x02, 0x00, 0x1d}), //groups
		// signature algorithms: lots I guess, it doesn't matter because we're not going to verify it
		Extension(0x0d, []byte{0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01}),
		Extension(0x33, KeyShare(keys.Public)),    // key share
		Extension(0x2d, []byte{0x01, 0x01}),       // PSK (no effect)
		Extension(0x2b, []byte{0x02, 0x03, 0x04}), // TLS version
	)
	handshake := concatenate(
		[]byte{0x03, 0x03},             // client version: TLS 1.2
		random(32),                     // client random
		[]byte{0x00},                   // no session id
		[]byte{0x00, 0x02, 0x13, 0x01}, // cipher suites: TLS_AES_128_GCM_SHA256
		[]byte{0x01, 0x00},
		u16(uint16(len(extensions))),
		extensions,
	)
	return concatenate(
		[]byte{0x16, 0x03, 0x01}, // handshake
		u16(uint16(len(handshake)+4)),
		[]byte{0x01, 0x00}, // handshake
		u16(uint16(len(handshake))),
		handshake,
	)
}

func ServerName(name string) []byte {
	bytes := []byte(name)
	return concatenate(
		u16(uint16(len(name))+3),
		[]byte{0x00},
		u16(uint16(len(name))),
		bytes,
	)
}

func KeyShare(publicKey []byte) []byte {
	return concatenate(
		u16(uint16(len(publicKey)+4)),
		u16(0x1d), // x25519
		u16(uint16(len(publicKey))),
		publicKey,
	)
}

func Extension(id uint16, contents []byte) []byte {
	return concatenate(
		u16(id),
		u16(uint16(len(contents))),
		contents,
	)
}

/** server hello **/

func parseServerHello(buf cryptobyte.String) ServerHello {
	var hello ServerHello
	buf.Skip(4) // handshake type & length
	buf.Skip(2) // tls version
	buf.ReadBytes(&hello.Random, 32)
	var sessionID cryptobyte.String
	buf.ReadUint8LengthPrefixed(&sessionID)
	buf.Skip(2) // cipher suite
	buf.Skip(1) // compression
	var extensions cryptobyte.String
	buf.ReadUint16LengthPrefixed(&extensions)
	for !extensions.Empty() {
		var typ uint16
		extensions.ReadUint16(&typ)
		var contents cryptobyte.String
		extensions.ReadUint16LengthPrefixed(&contents)
		switch typ {
		case 0x0033:
			// key share
			contents.Skip(2) // x25519
			var publicKey cryptobyte.String
			contents.ReadUint16LengthPrefixed(&publicKey)
			hello.PublicKey = publicKey
			if !contents.Empty() {
				panic("didn't read all of key share")
			}
		case 0x002b:
			// ignore the TLS version
		default:
			panic("unknown extension")
		}
	}
	return hello
}

/** helper functions **/

func concatenate(bufs ...[]byte) []byte {
	var buf []byte
	for _, b := range bufs {
		buf = append(buf, b...)
	}
	return buf
}

func u16(x uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, x)
	return buf
}
