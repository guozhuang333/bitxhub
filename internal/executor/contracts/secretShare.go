package contracts

import (
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/ncw/gmp"
)

type SecretShare struct {
	boltvm.Stub
	secret crypto.PrivateKey
}

//p(x,y)=x+y^2+3*y+2xy+serc

func GmpUtil(x int, y int, secr crypto.PrivateKey) *gmp.Int {

	i, _ := secr.Bytes()
	gmpx := gmp.NewInt(int64(x))
	gmpy := gmp.NewInt(int64(y))
	//return x + y*y + 3*y + 2*x*y + secret
	//x
	ans := gmp.NewInt(gmpx.Int64())

	temp := gmp.NewInt(0)
	temp.Mul(gmpy, gmpy)
	//x + y*y
	ans.Add(ans, temp)
	//fmt.Println(ans.Int64())

	//x + y*y + 3*y
	temp.MulInt32(gmpy, 3)
	ans.Add(ans, temp)
	//fmt.Println(ans.Int64())

	//x + y*y + 3*y + 2*x*y
	temp.Mul(gmpy, gmpx)
	temp.MulInt32(temp, 2)
	ans.Add(ans, temp)
	//fmt.Println(ans.Int64())

	IntSecret := gmp.NewInt(0).SetBytes(i)
	ans.Add(ans, IntSecret)

	return ans
}

func (t *SecretShare) GetfullSecretShare(x int, y int) *boltvm.Response {
	ret := GmpUtil(x, y, t.secret)
	return boltvm.Success(ret.Bytes())
}
