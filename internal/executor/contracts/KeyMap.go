package contracts

import (
	"encoding/json"
	"fmt"
	"github.com/meshplus/bitxhub-core/boltvm"
	"strconv"
)

type KeyMap struct {
	boltvm.Stub
	keyMap map[string][]byte //使用对用节点的公钥加密过的临时沟通密钥对中的私钥
}

func (t *KeyMap) Set(data []byte, addr string) *boltvm.Response {
	if len(t.keyMap) == 0 {
		temp := make(map[string][]byte)
		t.keyMap = temp
	}
	if addr == "" {
		t.keyMap[addr] = data
		return boltvm.Success([]byte("空的上传成功"))
	}
	t.keyMap[addr] = data
	return boltvm.Success([]byte("keymap设置成功"))
}

func (t *KeyMap) GetKeyMapSize() *boltvm.Response {
	i := len(t.keyMap)
	itoa := strconv.Itoa(i)
	return boltvm.Success([]byte(itoa))
}

func (t *KeyMap) Get() *boltvm.Response {
	marshal, err := json.Marshal(t.keyMap)
	if err != nil {
		fmt.Println(err)
	}
	return boltvm.Success(marshal)
}
