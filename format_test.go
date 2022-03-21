package main

/*
import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/cryptobyte"
)

func TestParseServerHello(t *testing.T) {
	data, _ := os.ReadFile("test/server_hello.hex")
	data, _ = hex.DecodeString(string(data))
	hello := parseServerHello(cryptobyte.String(data))
	assert.Equal(t, hello.Random[:2], []byte{0xa4, 0x09})
	assert.Equal(t, len(hello.Random), 32)
	assert.Equal(t, hello.PublicKey[:3], []byte{0x3e, 0x66, 0xee})
	assert.Equal(t, len(hello.PublicKey), 32)

}
*/
