package tester

import (
	"fmt"
	"github.com/meshplus/bitxhub-kit/crypto/asym"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxhub/internal/coreapi/api"
	"github.com/stretchr/testify/suite"
	"path/filepath"
)

type Invoke struct {
	suite.Suite
	api api.CoreAPI
}

func (suite *Invoke) TestInvoke() {
	//keyPassword := "bitxhub"
	//var api api.CoreAPI
	//key, err := asym.RestorePrivateKey(filepath.Join("..", "scripts", "build", "node1", "key.json"), keyPassword)
	//if err != nil {
	//	return
	//}
	//bytes, err := key.Bytes()
	//if err != nil {
	//	return
	//}
	//fmt.Println(common.Bytes2Hex(bytes))
	//address, err := key.PublicKey().Address()
	//fmt.Println("address", address.String())
	path1 := "./test_data/config/node1/key.json"
	keyPath1 := filepath.Join(path1)
	priAdmin1, err := asym.RestorePrivateKey(keyPath1, "bitxhub")
	fromAdmin1, err := priAdmin1.PublicKey().Address()
	fmt.Println(fromAdmin1)
	if err != nil {
		return
	}
	k1Nonce := suite.api.Broker().GetPendingNonceByAccount(fromAdmin1.String())
	fmt.Println(k1Nonce)
	ret, err := invokeBVMContract(suite.api, priAdmin1, k1Nonce, constant.VrfSortContractAddr.Address(), "Sort", pb.Bytes([]byte{1, 2, 3}))
	fmt.Println("ret1", string(ret.Ret))
	k1Nonce = suite.api.Broker().GetPendingNonceByAccount(fromAdmin1.String())
	ret, err = invokeBVMContract(suite.api, priAdmin1, k1Nonce, constant.VrfSortContractAddr.Address(), "Sort", pb.Bytes([]byte{1, 2, 3}))
	fmt.Println("ret2", string(ret.Ret))
	k1Nonce = suite.api.Broker().GetPendingNonceByAccount(fromAdmin1.String())
	ret, err = invokeBVMContract(suite.api, priAdmin1, k1Nonce, constant.VrfSortContractAddr.Address(), "Sort", pb.Bytes([]byte{1, 2, 3}))
	fmt.Println("ret3", string(ret.Ret))
	k1Nonce = suite.api.Broker().GetPendingNonceByAccount(fromAdmin1.String())
	ret, err = invokeBVMContract(suite.api, priAdmin1, k1Nonce, constant.VrfSortContractAddr.Address(), "Sort", pb.Bytes([]byte{1, 2, 3}))
	fmt.Println("ret4", string(ret.Ret))
	k1Nonce = suite.api.Broker().GetPendingNonceByAccount(fromAdmin1.String())
	ret, err = invokeBVMContract(suite.api, priAdmin1, k1Nonce, constant.VrfSortContractAddr.Address(), "Sort", pb.Bytes([]byte{1, 2, 3}))
	fmt.Println("ret5", string(ret.Ret))
}
