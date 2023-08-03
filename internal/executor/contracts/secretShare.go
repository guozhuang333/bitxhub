package contracts

import (
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/asym"
	"strconv"
)

type SecretShare struct {
	boltvm.Stub
	secret crypto.PrivateKey
}

//p(x,y)=x+y^2+3*y+2xy+13

func util(x int, y int) int {
	_, err := asym.GenerateKeyPair(crypto.Secp256k1)
	if err != nil {
		return 0
	}
	return x + y*y + 3*y + 2*x*y + 13
}

func (t *SecretShare) GetfullSecret(x int, y int) *boltvm.Response {
	ret := util(x, y)
	temp := strconv.Itoa(ret)
	return boltvm.Success([]byte(temp))
}
