package contracts

import (
	"github.com/meshplus/bitxhub-core/boltvm"
	"sort"
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
		sort.Strings(t.Strings)
		return boltvm.Success([]byte("收齐了"))
	}
}

func (t *VrfSort) Search(data []byte) *boltvm.Response {
	for i := 0; i < len(t.Strings); i++ {
		if string(data) == t.Strings[i] {
			return boltvm.Success([]byte(strconv.Itoa(i)))
		}
	}
	return boltvm.Success([]byte(strconv.Itoa(-1)))
}
