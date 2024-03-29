package contracts

import (
	"github.com/meshplus/bitxhub-core/boltvm"
)

type SelectHost struct {
	boltvm.Stub
	Selects map[string][]byte //使用对用节点的公钥加密过的临时沟通密钥对中的私钥
}

func (t *SelectHost) Select(data []byte, addr string) *boltvm.Response {
	if len(t.Selects) == 0 {
		temp := make(map[string][]byte)
		t.Selects = temp
	}
	//fmt.Println("存储时收到的加密内容", data)
	//fmt.Println("存储时收到的地址", addr)
	t.Selects[addr] = data
	//fmt.Println("存储后已经收到的条数", len(t.Selects))
	//fmt.Println("存储后的结果", t.Selects)
	return boltvm.Success([]byte("选择成功"))
}

func (t *SelectHost) Verify(addr string) *boltvm.Response {
	bytes, _ := t.Selects[addr]
	//fmt.Println("合约里收到的请求地址", addr)
	//fmt.Println("合约里面的输出加密内容", bytes)
	return boltvm.Success(bytes)
}
