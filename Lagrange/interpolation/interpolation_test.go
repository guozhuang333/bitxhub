package interpolation

import (
	"bytes"
	"fmt"
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
	p := gmp.NewInt(0)
	p.SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521", 10)
	//p(x,y)=x+y^2+3*y+2xy+13
	//三个节点 1，2，3
	//节点1拿着 p(1,1) p(1,2) p(1,3)
	//节点2拿着 p(2,1) p(2,2) p(2,3)
	//节点3拿着 p(3,1) p(3,2) p(3,3)
	fmt.Println("节点1的值", util(1, 1), util(1, 2), util(1, 3))
	fmt.Println("节点2的值", util(2, 1), util(2, 2), util(2, 3))
	fmt.Println("节点3的值", util(3, 1), util(3, 2), util(3, 3))
	//进入新时期 变成节点 4 5 6 此时的份额是减半的
	//节点4拿着 p(1,4) p(2,4) p(3,4)
	//节点5拿着 p(1,5) p(2,5) p(3,5)
	//节点6拿着 p(1,6) p(2,6) p(3,6)

	//进入份额恢复
	//节点4拿着 p(1,4) p(2,4) p(3,4)    p(4,4) p(4,5) p(4,6)
	//节点5拿着 p(1,5) p(2,5) p(3,5)    p(5,4) p(5,5) p(5,6)
	//节点6拿着 p(1,6) p(2,6) p(3,6)    p(6,4) p(6,5) p(6,6)

	//a := make([]*gmp.Int, 0)
	//a = append(a, gmp.NewInt(1))
	//a = append(a, gmp.NewInt(2))
	//a = append(a, gmp.NewInt(3))
	//
	//b := make([]*gmp.Int, 0)
	//b = append(b, gmp.NewInt(int64(util(1, 0))))
	//b = append(b, gmp.NewInt(int64(util(2, 0))))
	//b = append(b, gmp.NewInt(int64(util(3, 0))))
	//
	//interpolate, err := LagrangeInterpolate(2, a, b, p)
	//if err != nil {
	//	return
	//}
	//fmt.Println(interpolate)

	//c := make([]*gmp.Int, 0)
	//c = append(c, gmp.NewInt(1))
	//c = append(c, gmp.NewInt(2))
	//c = append(c, gmp.NewInt(3))
	//
	//d := make([]*gmp.Int, 0)
	//d = append(d, gmp.NewInt(int64(util(1, 2))))
	//d = append(d, gmp.NewInt(int64(util(2, 2))))
	//d = append(d, gmp.NewInt(int64(util(3, 2))))
	//lagrangeInterpolate, err := LagrangeInterpolate(2, c, d, p)
	//if err != nil {
	//	return
	//}
	//fmt.Println(lagrangeInterpolate)

}
