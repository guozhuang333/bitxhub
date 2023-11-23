package interpolation

import (
	"bytes"
	"fmt"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub/internal/repo"
	"math/rand"
	"testing"

	. "github.com/meshplus/bitxhub/Lagrange/polyring"
	"github.com/ncw/gmp"
	"github.com/stretchr/testify/assert"
)

const POLY_ORDER = 2
const RAND_SEED = 2

var large_str string

func gen_prime(p *gmp.Int, bitnum int) {
	var buffer bytes.Buffer
	for i := 0; i < bitnum; i++ {
		buffer.WriteString("0")
	}

	large_str = "1"
	large_str += buffer.String()

	p.SetString(large_str, 10)
	// No next_prime method in go yet. Placeholder for now
	p.Set(gmp.NewInt(15486511))
	// p.Set(gmp.NewInt(7))
}

func eve(x int) int {
	return 18 + 99999980*x + 6*x*x
}

func TestLagrangeInterpolate(t *testing.T) {
	p := gmp.NewInt(0)
	gen_prime(p, 256)
	r := rand.New(rand.NewSource(RAND_SEED))

	fmt.Printf("Prime p = %s\n", p.String())

	originalPoly, err := NewRand(POLY_ORDER, r, p)
	assert.Nil(t, err, "New")

	// Test EvalArray
	x := make([]*gmp.Int, POLY_ORDER+1)
	y := make([]*gmp.Int, POLY_ORDER+1)
	VecInit(x)
	VecInit(y)
	VecRand(x, p, r)

	originalPoly.EvalModArray(x, p, y)

	fmt.Println("Finished eval")
	fmt.Println("Starting interpolation")

	reconstructedPoly, err := LagrangeInterpolate(POLY_ORDER, x, y, p)
	assert.Nil(t, err, "New")

	//fmt.Printf("Original Poly ")
	//originalPoly.Print()

	//fmt.Printf("Reconstructed Poly ")
	//reconstructedPoly.Print()
	assert.True(t, reconstructedPoly.IsSame(originalPoly))
}

func TestLagrange(t *testing.T) {
	a := make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(1))
	a = append(a, gmp.NewInt(2))
	a = append(a, gmp.NewInt(3))
	a = append(a, gmp.NewInt(4))

	b := make([]*gmp.Int, 0)
	b = append(b, gmp.NewInt(2))
	b = append(b, gmp.NewInt(5))
	b = append(b, gmp.NewInt(10))
	b = append(b, gmp.NewInt(17))

	p := gmp.NewInt(0)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521", 10)

	interpolate, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println(interpolate)
}

func TestMarshal(t *testing.T) {
	newInt := gmp.NewInt(1)
	json, err := newInt.MarshalJSON()
	if err != nil {
		return
	}
	fmt.Println(json)
	newInt2 := gmp.NewInt(12)
	fmt.Println(newInt2.String())
	err = newInt2.UnmarshalJSON(json)
	if err != nil {
		return
	}
	fmt.Println(newInt2.String())
}

func TestNum(t *testing.T) {
	a := make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(1))
	a = append(a, gmp.NewInt(2))
	a = append(a, gmp.NewInt(3))
	a = append(a, gmp.NewInt(4))

	b := make([]*gmp.Int, 0)
	b = append(b, gmp.NewInt(2))
	b = append(b, gmp.NewInt(5))
	b = append(b, gmp.NewInt(10))
	b = append(b, gmp.NewInt(17))

	p := gmp.NewInt(0)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521", 10)

	interpolate, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println(interpolate)
	fmt.Println(interpolate.GetNum(10))
}

func util(x int, y int) int {
	return x + y*y + 3*y + 2*x*y + 13
}

func TestTwoDimensionalLagrange(t *testing.T) {
	//secr, err := asym.GenerateKeyPair(crypto.Secp256k1)

	path1 := "/Users/guozhuang/GolandProjects/hub/bitxhub/bitxhub/scripts/build/node1"
	repo1, _ := repo.Load(path1, "", "", "")
	secr := repo1.Key.PrivKey
	i, err := repo1.Key.PrivKey.Bytes()
	fmt.Println("生成的秘密为", i)
	fmt.Println("秘密实际值", GmpUtil(0, 0, secr))

	p := gmp.NewInt(0)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521123123", 10)
	//p(x,y)=x+y^2+3*y+2xy+serc
	//三个节点 1，2，3
	//节点1拿着 p(1,1) p(1,2) p(1,3)
	//节点2拿着 p(2,1) p(2,2) p(2,3)
	//节点3拿着 p(3,1) p(3,2) p(3,3)
	//fmt.Println("节点1的值", util(1, 1), util(1, 2), util(1, 3))
	//fmt.Println("节点2的值", util(2, 1), util(2, 2), util(2, 3))
	//fmt.Println("节点3的值", util(3, 1), util(3, 2), util(3, 3))

	//fmt.Println("节点1的值", GmpUtil(1, 1), GmpUtil(1, 2), GmpUtil(1, 3))
	//fmt.Println("节点2的值", GmpUtil(2, 1), GmpUtil(2, 2), GmpUtil(2, 3))
	//fmt.Println("节点3的值", GmpUtil(3, 1), GmpUtil(3, 2), GmpUtil(3, 3))

	//进入新时期 变成节点 4 5 6 此时的份额是减半的
	//节点4拿着 p(1,4) p(2,4) p(3,4)
	//节点5拿着 p(1,5) p(2,5) p(3,5)
	//节点6拿着 p(1,6) p(2,6) p(3,6)

	//节点4计算出 p(4,4) p(5,4) p(6,4)
	//节点5计算出 p(4,5) p(5,5) p(6,5)
	//节点6计算出 p(4,6) p(5,6) p(6,6)

	//进入份额恢复
	//节点4拿着  p(4,4) p(4,5) p(4,6)
	//节点5拿着  p(5,4) p(5,5) p(5,6)
	//节点6拿着  p(6,4) p(6,5) p(6,6)

	a := make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(1))
	a = append(a, gmp.NewInt(2))
	a = append(a, gmp.NewInt(3))

	b := make([]*gmp.Int, 0)
	b = append(b, GmpUtil(1, 1, secr))
	b = append(b, GmpUtil(1, 2, secr))
	b = append(b, GmpUtil(1, 3, secr))

	fmt.Println("节点1的值", GmpUtil(1, 1, secr).Bytes(), GmpUtil(1, 2, secr).Bytes(), GmpUtil(1, 3, secr).Bytes())

	//节点1的插值多项式
	interpolate1, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点1拉格朗日插值多项式", interpolate1)

	num14 := interpolate1.GetGmpNum(gmp.NewInt(4))
	num15 := interpolate1.GetGmpNum(gmp.NewInt(5))
	num16 := interpolate1.GetGmpNum(gmp.NewInt(6))

	//fmt.Println("插值出来的14", num14)
	//fmt.Println("插值出来的15", num15)
	//fmt.Println("插值出来的16", num16)
	//fmt.Println("计算出来的14", GmpUtil(1, 4, secr))
	//fmt.Println("计算出来的15", GmpUtil(1, 5, secr))
	//fmt.Println("计算出来的16", GmpUtil(1, 6, secr))

	b = make([]*gmp.Int, 0)
	b = append(b, GmpUtil(2, 1, secr))
	b = append(b, GmpUtil(2, 2, secr))
	b = append(b, GmpUtil(2, 3, secr))

	//节点2的插值多项式
	interpolate2, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点2拉格朗日插值多项式", interpolate2)

	num24 := interpolate2.GetGmpNum(gmp.NewInt(4))
	num25 := interpolate2.GetGmpNum(gmp.NewInt(5))
	num26 := interpolate2.GetGmpNum(gmp.NewInt(6))
	//fmt.Println("插值出来的24", num24)
	//fmt.Println("插值出来的25", num25)
	//fmt.Println("插值出来的26", num26)
	//fmt.Println("计算出来的24", GmpUtil(2, 4, secr))
	//fmt.Println("计算出来的25", GmpUtil(2, 5, secr))
	//fmt.Println("计算出来的26", GmpUtil(2, 6, secr))

	b = make([]*gmp.Int, 0)
	b = append(b, GmpUtil(3, 1, secr))
	b = append(b, GmpUtil(3, 2, secr))
	b = append(b, GmpUtil(3, 3, secr))

	//节点3的插值多项式
	interpolate3, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点3拉格朗日插值多项式", interpolate3)

	num34 := interpolate3.GetGmpNum(gmp.NewInt(4))
	num35 := interpolate3.GetGmpNum(gmp.NewInt(5))
	num36 := interpolate3.GetGmpNum(gmp.NewInt(6))

	//节点4 拿到了 14 24 34
	b = make([]*gmp.Int, 0)
	b = append(b, num14)
	b = append(b, num24)
	b = append(b, num34)
	//节点4的一半插值多项式
	interpolate4Half, err := LagrangeInterpolate(1, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点4一半拉格朗日插值多项式", interpolate4Half)
	vec := FromVec(0, 7)
	interpolate4Half.AddSelf(vec)
	fmt.Println("偏移后节点4一半拉格朗日插值多项式", interpolate4Half)

	num44 := interpolate4Half.GetGmpNum(gmp.NewInt(4))
	num54 := interpolate4Half.GetGmpNum(gmp.NewInt(5))
	num64 := interpolate4Half.GetGmpNum(gmp.NewInt(6))
	//fmt.Println("插值出来的44", num44)
	//fmt.Println("插值出来的54", num54)
	//fmt.Println("插值出来的64", num64)
	//fmt.Println("计算出来的44", GmpUtil(4, 4, secr))
	//fmt.Println("计算出来的54", GmpUtil(5, 4, secr))
	//fmt.Println("计算出来的64", GmpUtil(6, 4, secr))

	//节点5 拿到了 15 25 35
	b = make([]*gmp.Int, 0)
	b = append(b, num15)
	b = append(b, num25)
	b = append(b, num35)
	//节点5的一半插值多项式
	interpolate5Half, err := LagrangeInterpolate(1, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点5一半拉格朗日插值多项式", interpolate5Half)
	vec = FromVec(0, 9)
	interpolate5Half.AddSelf(vec)
	fmt.Println("偏移后节点5一半拉格朗日插值多项式", interpolate5Half)

	num45 := interpolate5Half.GetGmpNum(gmp.NewInt(4))
	num55 := interpolate5Half.GetGmpNum(gmp.NewInt(5))
	num65 := interpolate5Half.GetGmpNum(gmp.NewInt(6))

	//节点6 拿到了 16 26 36
	b = make([]*gmp.Int, 0)
	b = append(b, num16)
	b = append(b, num26)
	b = append(b, num36)
	//节点6的一半插值多项式
	interpolate6Half, err := LagrangeInterpolate(1, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点6一半拉格朗日插值多项式", interpolate6Half)
	vec = FromVec(0, 113)
	interpolate6Half.AddSelf(vec)
	fmt.Println("偏移后节点6一半拉格朗日插值多项式", interpolate6Half)

	num46 := interpolate6Half.GetGmpNum(gmp.NewInt(4))
	num56 := interpolate6Half.GetGmpNum(gmp.NewInt(5))
	num66 := interpolate6Half.GetGmpNum(gmp.NewInt(6))

	a = make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(4))
	a = append(a, gmp.NewInt(5))
	a = append(a, gmp.NewInt(6))

	//节点4 拿到了 44 45 46
	b = make([]*gmp.Int, 0)
	b = append(b, num44)
	b = append(b, num45)
	b = append(b, num46)
	fmt.Println("节点4收到的44", num44.Bytes())
	fmt.Println("节点4收到的45", num45.Bytes())
	fmt.Println("节点4收到的46", num46.Bytes())
	//节点4的完整插值多项式
	interpolate4, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点4完整拉格朗日插值多项式", interpolate4)

	//节点5 拿到了 54 55 56
	b = make([]*gmp.Int, 0)
	b = append(b, num54)
	b = append(b, num55)
	b = append(b, num56)
	fmt.Println("节点5收到的54", num54.Bytes())
	fmt.Println("节点5收到的55", num55.Bytes())
	fmt.Println("节点5收到的56", num56.Bytes())
	//节点5的完整插值多项式
	interpolate5, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点5完整拉格朗日插值多项式", interpolate5)

	//节点6 拿到了 64 65 66
	b = make([]*gmp.Int, 0)
	b = append(b, num64)
	b = append(b, num65)
	b = append(b, num66)
	fmt.Println("节点6收到的64", num64.Bytes())
	fmt.Println("节点6收到的65", num65.Bytes())
	fmt.Println("节点6收到的66", num66.Bytes())
	//节点6的完整插值多项式
	interpolate6, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("节点6完整拉格朗日插值多项式", interpolate6)

	//进行密钥恢复 获得两个节点就够了
	//这里采用40 50
	num40 := interpolate4.GetGmpNum(gmp.NewInt(0))
	num50 := interpolate5.GetGmpNum(gmp.NewInt(0))

	//计算出最终多项式
	a = make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(4))
	a = append(a, gmp.NewInt(5))

	b = make([]*gmp.Int, 0)
	b = append(b, num40)
	b = append(b, num50)

	interpolateAns, err := LagrangeInterpolate(1, a, b, p)
	if err != nil {
		return
	}
	fmt.Println("完整拉格朗日插值多项式", interpolateAns)

	secrCal := interpolateAns.GetGmpNum(gmp.NewInt(0))
	byteCal := secrCal.Bytes()
	fmt.Println("计算结果是否正确", string(byteCal) == string(i))

}

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
	//fmt.Println("IntSecret", IntSecret.String())
	//fmt.Println("ans", ans.String())

	return ans
}

func TestGmpCal(t *testing.T) {
	//p(x,y)=x+y^2+3*y+2xy+13
	GmpUtil(1, 2, nil)
}

func TestGmpGetNum(t *testing.T) {
	a := make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(1))
	a = append(a, gmp.NewInt(2))
	a = append(a, gmp.NewInt(3))
	a = append(a, gmp.NewInt(4))

	b := make([]*gmp.Int, 0)
	b = append(b, gmp.NewInt(3))
	b = append(b, gmp.NewInt(7))
	b = append(b, gmp.NewInt(13))
	b = append(b, gmp.NewInt(21))

	p := gmp.NewInt(0)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521", 10)

	interpolate, err := LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return
	}
	fmt.Println(interpolate)
	fmt.Println(interpolate.GetGmpNum(gmp.NewInt(10)).Int64())
}

func TestJson(t *testing.T) {
	//var bytes = []byte{}
}
