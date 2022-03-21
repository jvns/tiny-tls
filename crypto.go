package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

/** key generation **/

func random(bytes int) []byte {
	// generate 32 bytes of random data
	buf := make([]byte, bytes)
	rand.Read(buf)
	return buf
}

func KeyPair() Keys {
	privateKey := random(32)
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return Keys{
		Public:  publicKey,
		Private: privateKey,
	}
}

/***** handshake *****/

type Keys struct {
	Public                []byte
	Private               []byte
	ServerPublic          []byte
	HandshakeSecret       []byte
	ClientHandshakeSecret []byte
	ClientHandshakeKey    []byte
	ServerHandshakeKey    []byte
	ClientHandshakeIV     []byte
	ServerHandshakeIV     []byte

	ClientApplicationKey []byte
	ClientApplicationIV  []byte
	ServerApplicationKey []byte
	ServerApplicationIV  []byte
}

/*
From https://datatracker.ietf.org/doc/html/rfc8446#section-7.1:
   HKDF-Expand-Label(Secret, Label, Context, Length) =
        HKDF-Expand(Secret, HkdfLabel, Length)

   Where HkdfLabel is specified as:

   struct {
       uint16 length = Length;
       opaque label<7..255> = "tls13 " + Label;
       opaque context<0..255> = Context;
   } HkdfLabel;

   Derive-Secret(Secret, Label, Messages) =
        HKDF-Expand-Label(Secret, Label,
                          Transcript-Hash(Messages), Hash.length)
*/

func hkdfExpandLabel(secret []byte, label string, context []byte, length uint16) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})

	reader := hkdf.Expand(sha256.New, secret, hkdfLabel.BytesOrPanic())
	buf := make([]byte, length)
	reader.Read(buf)
	return buf
}

func deriveSecret(secret []byte, label string, transcriptMessages []byte) []byte {
	hash := sha256.Sum256(transcriptMessages)
	return hkdfExpandLabel(secret, label, hash[:], 32)
}

func (session *Session) MakeHandshakeKeys() {
	zeros := make([]byte, 32)
	psk := make([]byte, 32)
	sharedSecret, err := curve25519.X25519(session.Keys.Private, session.ServerHello.PublicKey)
	// ok so far
	if err != nil {
		panic(err)
	}
	// hkdf extract (hash, secret, salt)
	earlySecret := hkdf.Extract(sha256.New, psk, zeros) // TODO: psk might be wrong
	derivedSecret := deriveSecret(earlySecret, "derived", []byte{})
	session.Keys.HandshakeSecret = hkdf.Extract(sha256.New, sharedSecret, derivedSecret)
	handshakeMessages := concatenate(session.Messages.ClientHello.Contents(), session.Messages.ServerHello.Contents())

	cHsSecret := deriveSecret(session.Keys.HandshakeSecret, "c hs traffic", handshakeMessages)
	session.Keys.ClientHandshakeSecret = cHsSecret
	session.Keys.ClientHandshakeKey = hkdfExpandLabel(cHsSecret, "key", []byte{}, 16)
	session.Keys.ClientHandshakeIV = hkdfExpandLabel(cHsSecret, "iv", []byte{}, 12)

	sHsSecret := deriveSecret(session.Keys.HandshakeSecret, "s hs traffic", handshakeMessages)
	session.Keys.ServerHandshakeKey = hkdfExpandLabel(sHsSecret, "key", []byte{}, 16)
	session.Keys.ServerHandshakeIV = hkdfExpandLabel(sHsSecret, "iv", []byte{}, 12)
}

func (session *Session) MakeApplicationKeys() {
	handshakeMessages := concatenate(
		session.Messages.ClientHello.Contents(),
		session.Messages.ServerHello.Contents(),
		session.Messages.ServerHandshake.Contents())

	zeros := make([]byte, 32)
	derivedSecret := deriveSecret(session.Keys.HandshakeSecret, "derived", []byte{})
	masterSecret := hkdf.Extract(sha256.New, zeros, derivedSecret)

	cApSecret := deriveSecret(masterSecret, "c ap traffic", handshakeMessages)
	session.Keys.ClientApplicationKey = hkdfExpandLabel(cApSecret, "key", []byte{}, 16)
	session.Keys.ClientApplicationIV = hkdfExpandLabel(cApSecret, "iv", []byte{}, 12)

	sApSecret := deriveSecret(masterSecret, "s ap traffic", handshakeMessages)
	session.Keys.ServerApplicationKey = hkdfExpandLabel(sApSecret, "key", []byte{}, 16)
	session.Keys.ServerApplicationIV = hkdfExpandLabel(sApSecret, "iv", []byte{}, 12)
}

func (session *Session) VerifyData() []byte {
	finishedKey := hkdfExpandLabel(session.Keys.ClientHandshakeSecret, "finished", []byte{}, 32)
	finishedHash := sha256.Sum256(concatenate(session.Messages.ClientHello.Contents(), session.Messages.ServerHello.Contents(), session.Messages.ServerHandshake.Contents()))
	hm := hmac.New(sha256.New, finishedKey)
	hm.Write(finishedHash[:])
	return hm.Sum(nil)
}

func (session *Session) SendClientHandshakeFinished() {
	conn := session.Conn
	msg := session.ClientHandshakeFinishedMsg()
	conn.Write(msg)
}

func (session *Session) SendData(data []byte) {
	conn := session.Conn
	msg := session.EncryptApplicationData(data)
	session.RecordsSent += 1
	conn.Write(msg)
}

func (session *Session) ReceiveData() []byte {
	record := readRecord(session.Conn)
	iv := make([]byte, 12)
	copy(iv, session.Keys.ServerApplicationIV)
	iv[11] ^= session.RecordsReceived
	plaintext := decrypt(session.Keys.ServerApplicationKey, iv, record)
	session.RecordsReceived += 1
	fmt.Println(session.RecordsReceived)
	return plaintext
}

func (session *Session) EncryptApplicationData(data []byte) []byte {
	data = append(data, 0x17)
	additional := concatenate([]byte{0x17, 0x03, 0x03}, u16(uint16(len(data)+16))) // add 16 for the auth tag
	return encrypt(session.Keys.ClientApplicationKey, session.Keys.ClientApplicationIV, data, additional)
}

func (session *Session) ClientHandshakeFinishedMsg() []byte {
	verifyData := session.VerifyData()
	msg := concatenate([]byte{0x14, 0x00, 0x00, 0x20}, verifyData, []byte{0x16})
	additional := []byte{0x17, 0x03, 0x03, 0x00, 0x35}
	encrypted := encrypt(session.Keys.ClientHandshakeKey, session.Keys.ClientHandshakeIV, msg, additional)
	return encrypted
}

/** AEAD helper functions **/

func decrypt(key, iv, wrapper []byte) []byte {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	additional := wrapper[:5]
	ciphertext := wrapper[5:]

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, additional)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encrypt(key, iv, plaintext, additional []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, additional)
	return append(additional, ciphertext...)
}
