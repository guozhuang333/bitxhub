package contracts

import (
	"github.com/meshplus/bitxhub-core/boltvm"
	"strconv"
)

type VrfSort struct {
	boltvm.Stub
	Strings []string
}

func (t *VrfSort) Sort(data []byte) *boltvm.Response {
	t.Strings = append(t.Strings, string(data))
	if len(t.Strings) < 4 {
		l := "已经收到" + strconv.Itoa(len(t.Strings)) + "条消息"
		return boltvm.Success([]byte(l))
	} else {
		return boltvm.Success([]byte("收齐了"))
	}
}
