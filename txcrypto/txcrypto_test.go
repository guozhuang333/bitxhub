package txcrypto

import (
	"encoding/json"
	"fmt"
	"github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa"
	"math/rand"
	"testing"

	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/asym"
	"github.com/stretchr/testify/require"
)

func TestSimpleCryptor(t *testing.T) {

	privKey1, err := asym.GenerateKeyPair(crypto.Secp256k1)
	require.Nil(t, err)

	address1, err := privKey1.PublicKey().Address()
	require.Nil(t, err)
	pubBytes1, err := privKey1.PublicKey().Bytes()
	require.Nil(t, err)
	addr1 := address1.String()

	privKey2, err := asym.GenerateKeyPair(crypto.Secp256k1)
	require.Nil(t, err)

	address2, err := privKey2.PublicKey().Address()
	require.Nil(t, err)
	pubBytes2, err := privKey2.PublicKey().Bytes()

	addr2 := address2.String()
	require.Nil(t, err)
	keyMap := make(map[string][]byte)
	keyMap[addr1] = pubBytes1
	keyMap[addr2] = pubBytes2
	cryptor1, err := NewSimpleCryptor(privKey1, keyMap)
	if err != nil {
		return
	}
	cryptor2, err := NewSimpleCryptor(privKey2, keyMap)
	if err != nil {
		return
	}
	content := []byte("bitxhub cryptor test")
	encryptBytes, err := cryptor1.Encrypt(content, addr2)
	require.Nil(t, err)

	decryptBytes, err := cryptor2.Decrypt(encryptBytes, addr1)
	require.Nil(t, err)
	require.Equal(t, decryptBytes, content)

	fmt.Println(string(decryptBytes))
}

func TestRand(t *testing.T) {
	randomNumber := rand.Intn(4)
	fmt.Println(randomNumber)
}

func TestJson(t *testing.T) {
	privKey1, _ := asym.GenerateKeyPair(crypto.Secp256k1)
	marshal, err := json.Marshal(privKey1)
	if err != nil {
		return
	}
	var a crypto.PrivateKey
	//var a ecdsa.PrivateKey
	err = json.Unmarshal(marshal, &a)
	require.Nil(t, err)
}

func TestX509(t *testing.T) {
	privKey1, _ := asym.GenerateKeyPair(crypto.Secp256k1)
	bytes, err := privKey1.Bytes()
	if err != nil {
		return
	}
	key, err := ecdsa.UnmarshalPrivateKey(bytes, 3)
	if err != nil {
		return
	}
	fmt.Println(key)
}

func TestMap(t *testing.T) {
	m := make(map[string][]byte)
	fmt.Println(len(m))
	m["1"] = []byte("1")
	fmt.Println(m)

}

func TestSelfSimpleCryptor(t *testing.T) {

	privKey1, err := asym.GenerateKeyPair(crypto.Secp256k1)
	require.Nil(t, err)

	address1, err := privKey1.PublicKey().Address()
	require.Nil(t, err)
	pubBytes1, err := privKey1.PublicKey().Bytes()
	require.Nil(t, err)
	addr1 := address1.Address
	keyMap := make(map[string][]byte)
	keyMap[addr1] = pubBytes1
	cryptor1, err := NewSimpleCryptor(privKey1, keyMap)

	cryptor2, err := NewSimpleCryptor(privKey1, keyMap)
	if err != nil {
		return
	}
	content := []byte("bitxhub cryptor test")
	encryptBytes, err := cryptor1.Encrypt(content, addr1)
	require.Nil(t, err)

	decryptBytes, err := cryptor2.Decrypt(encryptBytes, addr1)
	require.Nil(t, err)
	require.Equal(t, decryptBytes, content)

	fmt.Println(string(decryptBytes))
}
