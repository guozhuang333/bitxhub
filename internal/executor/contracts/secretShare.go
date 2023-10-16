package contracts

import (
	"encoding/json"
	"fmt"
	"github.com/meshplus/bitxhub-core/boltvm"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub/Lagrange/interpolation"
	"github.com/meshplus/bitxhub/internal/repo"
	"github.com/ncw/gmp"
	"strconv"
)

const totalNums = 5
const hostNums = 2

type SecretShare struct {
	boltvm.Stub
	secret   crypto.PrivateKey
	Share34  map[int64][][]byte
	Recovery map[int64][]byte
	flag     bool
}

//p(x,y)=x+y^2+3*y+2xy+serc

func GmpShamirUtil(x int64, secr crypto.PrivateKey) *gmp.Int {

	//x+sec
	i, _ := secr.Bytes()
	gmpx := gmp.NewInt(int64(x))
	IntSecret := gmp.NewInt(0).SetBytes(i)
	gmpx.Add(gmpx, IntSecret)

	return gmpx
}

func (t *SecretShare) GetFullSecretShare(x int64) *boltvm.Response {
	if t.secret == nil {
		path1 := "/Users/guozhuang/GolandProjects/hub/bitxhub/bitxhub/scripts/build/node1"
		repo1, _ := repo.Load(path1, "", "", "")
		t.secret = repo1.Key.PrivKey
	}
	ret1 := GmpShamirUtil(x, t.secret)

	return boltvm.Success(ret1.Bytes())
}

func (t *SecretShare) Collect34Share(i int64, b []byte) *boltvm.Response {
	if t.Share34 == nil {
		t.Share34 = make(map[int64][][]byte)
	}
	bytes := make([][]byte, hostNums)
	err := json.Unmarshal(b, &bytes)
	if err != nil {
		return nil
	}

	//[1][0] 是 14 [1][1] 是 15
	//[2][0]   24  [2][1] 	25
	t.Share34[i] = bytes
	return boltvm.Success([]byte("34碎片上传成功"))
}

func (t *SecretShare) Get34ShareSize() *boltvm.Response {
	i := len(t.Share34)
	itoa := strconv.Itoa(i)
	return boltvm.Success([]byte(itoa))
}

func (t *SecretShare) Get34Share(i int64) *boltvm.Response {
	bytes := make([][]byte, hostNums)

	//fmt.Println("收到请求index", i)

	for j := 0; j < hostNums; j++ {

		//byte[0]=t.Share34[1][0] for4
		//byte[1]=t.Share34[2][0] for4
		bytes[j] = t.Share34[int64(j+1)][i-(totalNums+1-hostNums)]
	}
	marshal, err := json.Marshal(bytes)
	if err != nil {
		return nil
	}

	return boltvm.Success(marshal)
}

func (t *SecretShare) CollectSecretRecoveryShare(i int64, bytes []byte) *boltvm.Response {
	if t.Recovery == nil {
		t.Recovery = make(map[int64][]byte)
	}
	t.Recovery[i] = bytes

	//40 50 60
	//return boltvm.Success(t.Recovery[i])
	fmt.Println(t.Recovery)
	if len(t.Recovery) == totalNums {
		var p, _ = gmp.NewInt(0).SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521123123", 10)
		a := make([]*gmp.Int, 0)
		for j := 0; j < hostNums; j++ {
			//a = append(a, gmp.NewInt(4))
			//a = append(a, gmp.NewInt(5))
			a = append(a, gmp.NewInt(int64(totalNums+1-hostNums+j)))
		}
		b := make([]*gmp.Int, 0)
		for j := 0; j < hostNums; j++ {
			//b4 := gmp.NewInt(0).SetBytes(t.Recovery[3])
			//b5 := gmp.NewInt(0).SetBytes(t.Recovery[4])
			b = append(b, gmp.NewInt(0).SetBytes(t.Recovery[int64(totalNums+1-hostNums+j)]))
		}

		//完整份额的插值多项式
		interpolate, _ := interpolation.LagrangeInterpolate(hostNums-1, a, b, p)
		secrCal := interpolate.GetGmpNum(gmp.NewInt(0))
		byteCal := secrCal.Bytes()
		by, _ := t.secret.Bytes()
		fmt.Println("--------------------最后恢复的密钥与原始密钥对比计算结果是否正确---------------------------", string(byteCal) == string(by))
		t.flag = true
	}
	return boltvm.Success([]byte("恢复完整0点碎片上传成功"))
}

func (t *SecretShare) GetRecoveryStatus() *boltvm.Response {
	if t.flag {
		t.Recovery = make(map[int64][]byte)
		t.Share34 = make(map[int64][][]byte)
		return boltvm.Success([]byte{1})
	} else {
		return boltvm.Success([]byte{})
	}
}
