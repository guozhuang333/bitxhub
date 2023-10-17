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
const hostNums = 3
const hostBegin = totalNums - hostNums + 1

type SecretShare struct {
	boltvm.Stub
	secret       crypto.PrivateKey
	HalfShare456 map[int64][][]byte
	Share456     map[int64][][]byte
	Recovery     map[int64][]byte
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

func (t *SecretShare) Collect456HalfShare(i int64, b []byte) *boltvm.Response {
	if t.HalfShare456 == nil {
		t.HalfShare456 = make(map[int64][][]byte)
	}
	bytes := make([][]byte, hostNums)
	err := json.Unmarshal(b, &bytes)
	if err != nil {
		return nil
	}

	//14,15,16都存在t.HalfShare456[1]里面
	//t.HalfShare456[1][0]是13 t.HalfShare456[1][1]是14 t.HalfShare456[1][2]是15
	//t.HalfShare456[2][0]是23 t.HalfShare456[2][1]是24 t.HalfShare456[2][2]是25
	//t.HalfShare456[3][0]是33 t.HalfShare456[3][1]是34 t.HalfShare456[3][2]是35
	t.HalfShare456[i] = bytes
	fmt.Println("t.HalfShare456", t.HalfShare456)
	return boltvm.Success([]byte("一半456碎片上传成功"))
}

func (t *SecretShare) GetHalf456ShareSize() *boltvm.Response {
	i := len(t.HalfShare456)
	itoa := strconv.Itoa(i)
	return boltvm.Success([]byte(itoa))
}

func (t *SecretShare) GetHalf456Share(i int64) *boltvm.Response {

	bytes := make([][]byte, hostNums)

	fmt.Println("收到请求index", i)

	for j := 0; j < hostNums; j++ {
		//3-0 4-1 5-2
		bytes[j] = t.HalfShare456[int64(j+1)][i-hostBegin]
	}
	marshal, err := json.Marshal(bytes)
	if err != nil {
		return nil
	}

	return boltvm.Success(marshal)
}

func (t *SecretShare) Collect456Share(i int64, b []byte) *boltvm.Response {
	if t.Share456 == nil {
		t.Share456 = make(map[int64][][]byte)
	}
	bytes := make([][]byte, hostNums)
	err := json.Unmarshal(b, &bytes)
	if err != nil {
		return nil
	}

	//44,45,46都存在t.Share456[4]里面
	//t.Share456[3][0]是33 t.Share456[3][1]是43 t.Share456[3][2]是53
	//t.Share456[4][0]是34 t.Share456[4][1]是44 t.Share456[4][2]是54
	//t.Share456[5][0]是35 t.Share456[5][1]是45 t.Share456[5][2]是55
	t.Share456[i] = bytes
	//fmt.Println("完整的456share", t.Share456)
	return boltvm.Success([]byte("恢复完整456碎片上传成功"))
}

func (t *SecretShare) Get456ShareSize() *boltvm.Response {
	i := len(t.Share456)
	itoa := strconv.Itoa(i)
	return boltvm.Success([]byte(itoa))
}

func (t *SecretShare) Get456Share(i int64) *boltvm.Response {
	bytes := make([][]byte, hostNums)
	for j := 0; j < hostNums; j++ {
		bytes[j] = t.Share456[int64(hostNums+j)][i-hostBegin]
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
	if len(t.Recovery) == totalNums {
		var p, _ = gmp.NewInt(0).SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521123123", 10)
		a := make([]*gmp.Int, 0)
		a = append(a, gmp.NewInt(4))
		a = append(a, gmp.NewInt(5))
		b := make([]*gmp.Int, 0)
		b4 := gmp.NewInt(0).SetBytes(t.Recovery[4])
		b5 := gmp.NewInt(0).SetBytes(t.Recovery[5])
		b = append(b, b4)
		b = append(b, b5)

		//节点456的完整份额的插值多项式
		interpolate, _ := interpolation.LagrangeInterpolate(1, a, b, p)
		secrCal := interpolate.GetGmpNum(gmp.NewInt(0))
		byteCal := secrCal.Bytes()
		by, _ := t.secret.Bytes()
		fmt.Println("--------------------最后恢复的密钥与原始密钥对比计算结果是否正确---------------------------", string(byteCal) == string(by))
	}
	return boltvm.Success([]byte("恢复完整0点碎片上传成功"))
}

func (t *SecretShare) GetRecoverySize() *boltvm.Response {
	i := len(t.Recovery)
	itoa := strconv.Itoa(i)
	return boltvm.Success([]byte(itoa))
}

func (t *SecretShare) GetRecoveryShare(i int64) *boltvm.Response {
	return boltvm.Success(t.Recovery[i])
}
