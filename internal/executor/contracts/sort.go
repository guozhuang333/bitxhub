package contracts

import (
	"github.com/meshplus/bitxhub-core/boltvm"
)

type VrfSort struct {
	boltvm.Stub
	Strings []string
}

func (t *VrfSort) Sort(data []byte) *boltvm.Response {
	t.Strings = append(t.Strings, string(data))
	if len(t.Strings) < 4 {
		return boltvm.Success([]byte("收到1"))
	} else {
		return boltvm.Success([]byte("收齐了"))
	}
}
