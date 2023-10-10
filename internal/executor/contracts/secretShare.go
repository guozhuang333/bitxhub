package contracts

import (
	"encoding/json"
	"fmt"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub/internal/repo"
	"github.com/ncw/gmp"
)

type SecretShare struct {
	boltvm.Stub
	secret   crypto.PrivateKey
	Share456 map[int64][][]byte
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

func (t *SecretShare) Collect456Share(i int64, b []byte) *boltvm.Response {
	if t.Share456 == nil {
		t.Share456 = make(map[int64][][]byte)
	}
	bytes := make([][]byte, 3)
	err := json.Unmarshal(b, &bytes)
	if err != nil {
		return nil
	}

	//14,15,16都存在t.Share456[1]里面
	//t.Share456[1][0]是14 t.Share456[1][1]是15 t.Share456[1][2]是16
	//t.Share456[2][0]是24 t.Share456[2][1]是25 t.Share456[2][2]是26
	//t.Share456[3][0]是34 t.Share456[3][1]是35 t.Share456[3][2]是36
	t.Share456[i] = bytes
	fmt.Println(t.Share456)
	return boltvm.Success([]byte("456碎片上传成功"))
}

func (t *SecretShare) Get456Share(i int64) *boltvm.Response {
	//4是4 3是5 2是6
	bytes := make([][]byte, 5)

	fmt.Println("收到请求index", i)

	for j := 1; j <= 4; j++ {
		fmt.Println("进入到的j", j, t.Share456[int64(j)])
		if len(t.Share456[int64(j)]) > 0 {
			fmt.Println("获取到的密钥碎片", t.Share456[int64(j)][4-i])
			bytes[j] = t.Share456[int64(j)][4-i]
		} else {
			bytes[j] = nil
		}
	}
	marshal, err := json.Marshal(bytes)
	if err != nil {
		return nil
	}

	return boltvm.Success(marshal)
}
