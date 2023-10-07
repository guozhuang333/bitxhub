package contracts

import (
	"encoding/json"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub/internal/repo"
	"github.com/ncw/gmp"
)

type SecretShare struct {
	boltvm.Stub
	secret crypto.PrivateKey
}

//p(x,y)=x+y^2+3*y+2xy+serc

func GmpUtil(x int64, y int64, secr crypto.PrivateKey) *gmp.Int {

	i, _ := secr.Bytes()
	gmpx := gmp.NewInt(x)
	gmpy := gmp.NewInt(y)
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

func (t *SecretShare) GetFullSecretShare(x int64) *boltvm.Response {
	if t.secret == nil {
		path1 := "/Users/guozhuang/GolandProjects/hub/bitxhub/bitxhub/scripts/build/node1"
		repo1, _ := repo.Load(path1, "", "", "")
		t.secret = repo1.Key.PrivKey
	}
	ret1 := GmpUtil(x, 1, t.secret)
	ret2 := GmpUtil(x, 2, t.secret)
	ret3 := GmpUtil(x, 3, t.secret)
	i := make([][]byte, 3)
	i[0] = ret1.Bytes()
	i[1] = ret2.Bytes()
	i[2] = ret3.Bytes()
	marshal, _ := json.Marshal(i)
	return boltvm.Success(marshal)
}
