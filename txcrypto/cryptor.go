package txcrypto

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/ecdh"
	"github.com/meshplus/bitxhub-kit/crypto/sym"
)

type SimpleCryptor struct {
	privKey crypto.PrivateKey
	keyMap  map[string][]byte
}

func NewSimpleCryptor(privKey crypto.PrivateKey, keyMap map[string][]byte) (Cryptor, error) {
	d := &SimpleCryptor{
		privKey: privKey,
		keyMap:  keyMap,
	}

	return d, nil
}

func (d *SimpleCryptor) Encrypt(content []byte, address string) ([]byte, error) {
	des, err := d.getDesKey(address)
	if err != nil {
		return nil, err
	}
	return des.Encrypt(content)
}

func (d *SimpleCryptor) Decrypt(content []byte, address string) ([]byte, error) {
	des, err := d.getDesKey(address)
	if err != nil {
		return nil, err
	}
	return des.Decrypt(content)
}

func (d *SimpleCryptor) getDesKey(chainID string) (crypto.SymmetricKey, error) {
	pubKey, ok := d.keyMap[chainID]
	var err error
	if !ok {
		pubKey, err = d.getPubKeyByChainID(chainID)
		if err != nil {
			return nil, fmt.Errorf("cannot find the public key of chain ID %s: %w", chainID, err)
		}
		d.keyMap[chainID] = pubKey
	}
	ke, err := ecdh.NewEllipticECDH(btcec.S256())
	if err != nil {
		return nil, err
	}
	secret, err := ke.ComputeSecret(d.privKey, pubKey)
	if err != nil {
		return nil, err
	}
	return sym.GenerateSymKey(crypto.ThirdDES, secret)
}

func (d *SimpleCryptor) getPubKeyByChainID(chainID string) ([]byte, error) {

	return nil, nil
}
