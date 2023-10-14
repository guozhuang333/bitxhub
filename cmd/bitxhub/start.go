package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Rican7/retry"
	"github.com/Rican7/retry/backoff"
	"github.com/Rican7/retry/strategy"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/crypto/asym"
	"github.com/meshplus/bitxhub-kit/crypto/asym/ecdsa"
	"github.com/meshplus/bitxhub-kit/types"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxhub/Lagrange/interpolation"
	"github.com/meshplus/bitxhub/Lagrange/polyring"
	"github.com/meshplus/bitxhub/internal/coreapi/api"
	"github.com/meshplus/bitxhub/internal/executor"
	"github.com/meshplus/bitxhub/pkg/vm"
	"github.com/meshplus/bitxhub/pkg/vm/boltvm"
	"github.com/meshplus/bitxhub/txcrypto"
	"github.com/ncw/gmp"
	"math/big"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/guozhuang333/bitxhub-core/agency"
	_ "github.com/guozhuang333/off-test"
	"github.com/meshplus/bitxhub"
	"github.com/meshplus/bitxhub-kit/log"
	"github.com/meshplus/bitxhub/api/gateway"
	"github.com/meshplus/bitxhub/api/grpc"
	"github.com/meshplus/bitxhub/api/jsonrpc"
	"github.com/meshplus/bitxhub/internal/app"
	"github.com/meshplus/bitxhub/internal/coreapi"
	"github.com/meshplus/bitxhub/internal/loggers"
	"github.com/meshplus/bitxhub/internal/profile"
	"github.com/meshplus/bitxhub/internal/repo"
	types2 "github.com/meshplus/eth-kit/types"
	"github.com/urfave/cli"
)

var logger = log.NewWithModule("cmd")

func startCMD() cli.Command {
	return cli.Command{
		Name:  "start",
		Usage: "Start a long-running daemon process",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "config",
				Usage: "Specify BitXHub config path",
			},
			cli.StringFlag{
				Name:  "network",
				Usage: "Specify BitXHub network config path",
			},
			cli.StringFlag{
				Name:  "order",
				Usage: "Specify BitXHub order config path",
			},
			cli.StringFlag{
				Name:     "passwd",
				Usage:    "Specify BitXHub node private key password",
				Required: false,
			},
		},
		Action: start,
	}
}

type Node struct {
	//Vrf              []byte
	PrivKey          crypto.PrivateKey
	TempPrivKey      crypto.PrivateKey
	IsSele           bool
	AllNodeAddress   []*repo.NetworkNodes
	PubKeys          []crypto.PublicKey
	TempPubKey       crypto.PublicKey
	TempKeyMap       map[string][]byte
	index            int //自己的节点编号
	FullShareSecret  []byte
	FirstInterpolate polyring.Polynomial
	Interpolate34    polyring.Polynomial
	AfterInterpolate polyring.Polynomial
	isHostPre        bool
	afterIndex       int
}

type Global struct {
	Repo *repo.Repo
	api  *coreapi.CoreAPI
	bxh  *app.BitXHub
}

var MyGlobal Global

var Nonce uint64

var MyNode Node

var p, _ = gmp.NewInt(0).SetString("57896044618658097711785492504343953926634992332820282019728792006155588075521123123", 10)

func start(ctx *cli.Context) error {

	Nonce = 0

	repoRoot, err := repo.PathRootWithDefault(ctx.GlobalString("repo"))
	if err != nil {
		return fmt.Errorf("get repo path: %w", err)
	}

	passwd := ctx.String("passwd")
	configPath := ctx.String("config")
	networkPath := ctx.String("network")
	orderPath := ctx.String("order")
	err = getAdd()
	if err != nil {
		return err
	}

	repo, err := repo.Load(repoRoot, passwd, configPath, networkPath)

	MyGlobal.Repo = repo

	if err != nil {
		return fmt.Errorf("repo load: %w", err)
	}
	err = log.Initialize(
		log.WithReportCaller(repo.Config.Log.ReportCaller),
		log.WithPersist(true),
		log.WithFilePath(filepath.Join(repoRoot, repo.Config.Log.Dir)),
		log.WithFileName(repo.Config.Log.Filename),
		log.WithMaxAge(90*24*time.Hour),
		log.WithRotationTime(24*time.Hour),
	)
	if err != nil {
		return fmt.Errorf("log initialize: %w", err)
	}

	loggers.Initialize(repo.Config)

	types2.InitEIP155Signer(big.NewInt(int64(repo.Config.ChainID)))

	printVersion()

	if err := checkLicense(repo); err != nil {
		return fmt.Errorf("verify license fail:%v", err)
	}

	bxh, err := app.NewBitXHub(repo, orderPath)
	if err != nil {
		return fmt.Errorf("init bitxhub failed: %w", err)
	}
	MyGlobal.bxh = bxh

	monitor, err := profile.NewMonitor(repo.Config)
	if err != nil {
		return err
	}
	if err := monitor.Start(); err != nil {
		return err
	}

	pprof, err := profile.NewPprof(repo.Config)
	if err != nil {
		return err
	}
	if err := pprof.Start(); err != nil {
		return err
	}

	// coreapi
	api, err := coreapi.New(bxh)
	if err != nil {
		return err
	}
	MyGlobal.api = api

	// start grpc service
	b, err := grpc.NewChainBrokerService(api, repo.Config, &repo.Config.Genesis, bxh.Ledger)
	if err != nil {
		return err
	}

	if err := b.Start(); err != nil {
		return fmt.Errorf("start chain broker service failed: %w", err)
	}

	// start json-rpc service
	cbs, err := jsonrpc.NewChainBrokerService(api, repo.Config)
	if err != nil {
		return err
	}

	if err := cbs.Start(); err != nil {
		return fmt.Errorf("start chain broker service failed: %w", err)
	}

	gw := gateway.NewGateway(repo.Config)
	if err := gw.Start(); err != nil {
		fmt.Println(err)
	}

	bxh.Monitor = monitor
	bxh.Pprof = pprof
	bxh.Grpc = b
	bxh.Jsonrpc = cbs
	bxh.Gateway = gw

	var wg sync.WaitGroup
	wg.Add(1)
	handleLicenceCheck(bxh, repo, &wg)
	handleShutdown(bxh, &wg)

	if err := bxh.Start(); err != nil {
		return fmt.Errorf("start bitxhub failed: %w", err)
	}

	MyNode.PrivKey = repo.Key.PrivKey

	address, err := MyNode.PrivKey.PublicKey().Address()
	fmt.Println("自己节点的公钥地址", address)
	for i := 0; i < len(MyNode.PubKeys); i++ {
		address1, _ := MyNode.PubKeys[i].Address()
		if address1.String() == address.String() {
			MyNode.index = i + 1
			break
		}
	}

	http.HandleFunc("/", run)
	listenAddress := "0.0.0.0:" + strconv.Itoa(3300+MyNode.index)
	err = http.ListenAndServe(listenAddress, nil)
	if err != nil {
		fmt.Println("监听出现错误", err)
	}

	wg.Wait()

	return nil
}

func run(w http.ResponseWriter, r *http.Request) {
	fmt.Println("hello")

	offChainTransmissionConstructor, err := agency.GetOffchainTransmissionConstructor("offChain_transmission")
	if err != nil {
		_ = fmt.Errorf("offchain transmission constructor not found")
		return
	}

	offChainTransmissionMgr := offChainTransmissionConstructor()
	err = offChainTransmissionMgr.Start()
	if err != nil {
		_ = fmt.Errorf("offchain transmission start 出问题了")
		return
	}

	vrf, err := offChainTransmissionMgr.VRF([]byte{})
	if err != nil {
		_ = fmt.Errorf("VRF函数 出问题了 : %w", err)
		return
	}
	fmt.Printf("vrf 函数结果是 %v", vrf)

	//------------------------------------------生成排序交易---------------------------------------------
	tx, err := GenSortTX(MyNode.PrivKey, vrf, Nonce)
	Nonce++
	if err != nil {
		_ = fmt.Errorf("GenSortTX 出现问题")
		return
	}

	//--------------------------------------------------调用排序合约-------------------------------------------

	receipt, err := sendTransactionWithReceipt(MyGlobal.api, tx)
	if err != nil {
		fmt.Errorf("调用排序合约sendTransactionWithReceipt出错", err)
		return
	}

	logger.Logger.Println("收到回执", string(receipt.Ret))

	ret, err := InvokeSearchContract(MyGlobal.bxh.BlockExecutor, tx, vrf)
	if err != nil {
		fmt.Errorf("InvokeSearchContract出错", err)
		return
	}
	//fmt.Println("合约调用结果", string(ret))

	//--------------------------------根据合约结果判断是否成为持有秘密节点-----------------------------
	//num, _ := strconv.Atoi(string(ret))
	if MyNode.index <= 2 {
		MyNode.isHostPre = true
	}
	if MyNode.IsSele == true {
		logger.Logger.Println("该节点已被选为选举委员会成员")
	}
	MyNode.AllNodeAddress = MyGlobal.Repo.NetworkConfig.Nodes

	//----------------------------------------------获取自己应该持有的完整碎片----------------------------------

	//secretTx, err := GenGetFullShareSecret(Nonce, int64(MyNode.index))
	//Nonce++
	ret, err = InvokeGetFullShareSecretContract(MyGlobal.bxh.BlockExecutor, tx, int64(MyNode.index))
	if err != nil {
		fmt.Errorf("InvokeGetFullShareSecretContract出错", err)
		return
	}
	if MyNode.isHostPre {
		fmt.Println("获取到的首次完整密钥碎片的byte", gmp.NewInt(0).SetBytes(ret))
		MyNode.FullShareSecret = ret
	}

	//使用0多项式进行秘密偏移
	if MyNode.isHostPre {
		interpolate, err := FirstInterpolate()
		if err != nil {
			fmt.Errorf("FirstInterpolatet出错", err)
			return
		}
		MyNode.FirstInterpolate = interpolate
	}
	fmt.Printf("节点%v拉格朗日插值多项式%v", MyNode.index, MyNode.FirstInterpolate)

	//----------------------------------------------------分别计算34节点的密钥碎片并上传---------------------------------------------------------
	shareBytes := Cal34Share()
	shareTx, err := GenCollect34ShareTx(Nonce, shareBytes)
	Nonce++
	if err != nil {
		fmt.Errorf("GenCollect34ShareTx出错", err)
		return
	}

	receipt, err = sendTransactionWithReceipt(MyGlobal.api, shareTx)
	if err != nil {
		fmt.Errorf("调用GenCollect34ShareTx sendTransactionWithReceipt出错%v", err)
		return
	}

	logger.Logger.Println("收到上传34的回执", string(receipt.Ret))

	////-------------------节点34 获取自己的碎片份额------------------------------------------

	InvokeGet34ShareLength(MyGlobal.bxh.BlockExecutor, tx)

	if MyNode.index > 2 {
		Get34Share, err := InvokeGet34Share(MyGlobal.bxh.BlockExecutor, tx)
		if err != nil {
			fmt.Errorf("调用InvokeGet34Sharet出错%v", err)
			return
		}
		i := make([][]byte, 2)
		err = json.Unmarshal(Get34Share, &i)
		fmt.Println("获取到的来自12的密钥碎片", i)
		Interpolate, err := Interpolate34(i)
		MyNode.Interpolate34 = Interpolate
	} else {
		MyNode.Interpolate34 = polyring.Polynomial{}
	}

	fmt.Println("拉格朗日插值出来34的多项式", MyNode.Interpolate34)

	//--------------------------------------------节点34 为恢复完整密钥进行计算------------------------------------------
	recoveryShare := CalRecoveryShare()
	fmt.Println("节点34为0计算的值", recoveryShare)
	recoveryTx, err := GenSecretRecoveryTx(Nonce, recoveryShare)
	Nonce++
	if err != nil {
		fmt.Errorf("调用GenSecretRecoveryTx出错%v", err)
		return
	}

	receipt, err = sendTransactionWithReceipt(MyGlobal.api, recoveryTx)
	//if err != nil {
	//	return fmt.Errorf("调用上传恢复完整密钥碎片的交易sendTransactionWithReceipt出错%v", err)
	//}
	//
	//logger.Logger.Println("收到上传恢复完整密钥碎片的交易的回执", string(receipt.Ret))

	InvokeGetRecoveryStatus(MyGlobal.bxh.BlockExecutor, tx)

	fmt.Println("----------------------------完整密钥恢复完成-------------------------------------------------")
}

func checkLicense(rep *repo.Repo) error {
	licenseCon, err := agency.GetLicenseConstructor("license")
	if err != nil {
		return nil
	}
	license := rep.Config.License
	licenseVerifier := licenseCon(license.Key, license.Verifier)
	return licenseVerifier.Verify(rep.Config.RepoRoot)
}

func printVersion() {
	fmt.Printf("BitXHub version: %s-%s-%s\n", bitxhub.CurrentVersion, bitxhub.CurrentBranch, bitxhub.CurrentCommit)
	fmt.Printf("App build date: %s\n", bitxhub.BuildDate)
	fmt.Printf("System version: %s\n", bitxhub.Platform)
	fmt.Printf("Golang version: %s\n", bitxhub.GoVersion)
	fmt.Println()
}

func handleLicenceCheck(node *app.BitXHub, repo *repo.Repo, wg *sync.WaitGroup) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := checkLicense(repo); err != nil {
					fmt.Printf("verify license fail:%v", err)
					if err := node.Stop(); err != nil {
						panic(err)
					}
					wg.Done()
					os.Exit(0)
				}
			}
		}
	}()
}
func handleShutdown(node *app.BitXHub, wg *sync.WaitGroup) {
	var stop = make(chan os.Signal)
	signal.Notify(stop, syscall.SIGTERM)
	signal.Notify(stop, syscall.SIGINT)

	go func() {
		<-stop
		fmt.Println("received interrupt signal, shutting down...")
		if err := node.Stop(); err != nil {
			panic(err)
		}
		wg.Done()
		os.Exit(0)
	}()
}

func GenContractTransaction(vmType pb.TransactionData_VMType, privateKey crypto.PrivateKey, nonce uint64, address *types.Address, method string, args ...*pb.Arg) (pb.Transaction, error) {
	from, err := privateKey.PublicKey().Address()
	if err != nil {
		return nil, err
	}

	pl := &pb.InvokePayload{
		Method: method,
		Args:   args[:],
	}

	data, err := pl.Marshal()
	if err != nil {
		return nil, err
	}

	td := &pb.TransactionData{
		Type:    pb.TransactionData_INVOKE,
		VmType:  vmType,
		Payload: data,
	}

	payload, err := td.Marshal()
	if err != nil {
		return nil, err
	}

	tx := &pb.BxhTransaction{
		From:      from,
		To:        address,
		Payload:   payload,
		Timestamp: time.Now().UnixNano(),
		Nonce:     nonce,
	}

	if err := tx.Sign(privateKey); err != nil {
		return nil, fmt.Errorf("tx sign: %w", err)
	}

	tx.TransactionHash = tx.Hash()

	return tx, nil
}

func getAdd() error {
	path1 := "/Users/guozhuang/GolandProjects/hub/bitxhub/bitxhub/scripts/build/node1"
	path2 := "/Users/guozhuang/GolandProjects/hub/bitxhub/bitxhub/scripts/build/node2"
	path3 := "/Users/guozhuang/GolandProjects/hub/bitxhub/bitxhub/scripts/build/node3"
	path4 := "/Users/guozhuang/GolandProjects/hub/bitxhub/bitxhub/scripts/build/node4"
	repo1, _ := repo.Load(path1, "", "", "")
	repo2, _ := repo.Load(path2, "", "", "")
	repo3, _ := repo.Load(path3, "", "", "")
	repo4, _ := repo.Load(path4, "", "", "")
	MyNode.PubKeys = append(MyNode.PubKeys, repo1.Key.PrivKey.PublicKey())
	MyNode.PubKeys = append(MyNode.PubKeys, repo2.Key.PrivKey.PublicKey())
	MyNode.PubKeys = append(MyNode.PubKeys, repo3.Key.PrivKey.PublicKey())
	MyNode.PubKeys = append(MyNode.PubKeys, repo4.Key.PrivKey.PublicKey())
	return nil
}

// FirstInterpolate  第一次节点拉格朗日插值计算
func FirstInterpolate() (polyring.Polynomial, error) {

	i := rand.Intn(10) + 1

	polynomial01 := polyring.FromVec([]int64{0, int64(i)}...)

	err := polynomial01.SetCoefficientBig(0, gmp.NewInt(0).SetBytes(MyNode.FullShareSecret))
	if err != nil {
		return polyring.Polynomial{}, err
	}

	return polynomial01, nil

}

func Interpolate34(bytes [][]byte) (polyring.Polynomial, error) {

	a := make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(1))
	a = append(a, gmp.NewInt(2))

	b := make([]*gmp.Int, 0)

	b = append(b, gmp.NewInt(0).SetBytes(bytes[0]))
	b = append(b, gmp.NewInt(0).SetBytes(bytes[1]))

	//节点的一半份额的插值多项式
	interpolate, err := interpolation.LagrangeInterpolate(1, a, b, p)
	if err != nil {
		return polyring.Polynomial{}, err
	}
	return interpolate, nil

}

func Interpolate456(bytes [][]byte) (polyring.Polynomial, error) {

	a := make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(4))
	a = append(a, gmp.NewInt(5))
	a = append(a, gmp.NewInt(6))
	b := make([]*gmp.Int, 0)

	for i := 0; i < len(bytes); i++ {
		temp := gmp.NewInt(0)
		if len(bytes[i]) == 0 {
			return polyring.Polynomial{}, nil
		}
		temp.SetBytes(bytes[i])
		b = append(b, temp)
	}
	//节点456的完整份额的插值多项式
	interpolate, err := interpolation.LagrangeInterpolate(2, a, b, p)
	if err != nil {
		return polyring.Polynomial{}, err
	}
	return interpolate, nil

}

func InterpolateRecovery(bytes4 []byte, bytes5 []byte) (polyring.Polynomial, error) {

	a := make([]*gmp.Int, 0)
	a = append(a, gmp.NewInt(4))
	a = append(a, gmp.NewInt(5))
	b := make([]*gmp.Int, 0)
	b4 := gmp.NewInt(0).SetBytes(bytes4)
	b5 := gmp.NewInt(0).SetBytes(bytes5)
	b = append(b, b4)
	b = append(b, b5)

	//节点456的完整份额的插值多项式
	interpolate, err := interpolation.LagrangeInterpolate(1, a, b, p)
	if err != nil {
		return polyring.Polynomial{}, err
	}
	return interpolate, nil

}

func Cal34Share() []byte {
	if MyNode.FirstInterpolate.GetDegree() == 0 {
		return nil
	}
	NumFor3 := MyNode.FirstInterpolate.GetGmpNum(gmp.NewInt(3))
	NumFor4 := MyNode.FirstInterpolate.GetGmpNum(gmp.NewInt(4))

	bytes := make([][]byte, 2)
	bytes[0] = NumFor3.Bytes()
	bytes[1] = NumFor4.Bytes()
	fmt.Println("numfor3,numfor4", bytes)

	uploadByte, _ := json.Marshal(bytes)

	return uploadByte

}

func CalRecoveryShare() []byte {
	if MyNode.Interpolate34.GetDegree() == 0 {
		return nil
	}
	NumFor0 := MyNode.Interpolate34.GetGmpNum(gmp.NewInt(0))
	return NumFor0.Bytes()
}

//func Cal456Share() []byte {
//	if MyNode.HalfInterpolate.GetDegree() == 0 {
//		return nil
//	}
//	NumFor4 := MyNode.HalfInterpolate.GetGmpNum(gmp.NewInt(4))
//	fmt.Printf("节点%v产生的NumFor4为%v", MyNode.afterIndex, NumFor4)
//	NumFor5 := MyNode.HalfInterpolate.GetGmpNum(gmp.NewInt(5))
//	fmt.Printf("节点%v产生的NumFor5为%v", MyNode.afterIndex, NumFor5)
//	NumFor6 := MyNode.HalfInterpolate.GetGmpNum(gmp.NewInt(6))
//	fmt.Printf("节点%v产生的NumFor6为%v", MyNode.afterIndex, NumFor6)
//	bytes := make([][]byte, 3)
//	bytes[0] = NumFor4.Bytes()
//	bytes[1] = NumFor5.Bytes()
//	bytes[2] = NumFor6.Bytes()
//
//	uploadByte, _ := json.Marshal(bytes)
//
//	return uploadByte
//
//}

func GenBxhTx(privateKey crypto.PrivateKey, nonce uint64, address *types.Address, method string, args ...*pb.Arg) (pb.Transaction, error) {
	transaction, err := GenContractTransaction(pb.TransactionData_BVM, privateKey, nonce, address, method, args...)
	if err != nil {
		return nil, err
	}
	return transaction, err
}

func sendTransactionWithReceipt(api api.CoreAPI, tx pb.Transaction) (*pb.Receipt, error) {
	err := api.Broker().HandleTransaction(tx)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var receiptErr error
	receipt := &pb.Receipt{}
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("get receipt timeout")
		default:
			time.Sleep(2 * time.Millisecond)
			err = retry.Retry(func(attempt uint) error {
				receipt, err = api.Broker().GetReceipt(tx.GetHash())
				if err != nil {
					return err
				}

				return nil
			},
				strategy.Limit(500),
				strategy.Backoff(backoff.Fibonacci(2*time.Millisecond)),
			)
			if err != nil {
				receiptErr = err
			}
			return receipt, receiptErr
		}
	}

}

// GenSortTX 生成VRF存储排序BXH交易
func GenSortTX(key crypto.PrivateKey, input []byte, nonce uint64) (pb.Transaction, error) {
	tx, err := GenBxhTx(key, nonce, constant.VrfSortContractAddr.Address(), "Sort", pb.Bytes(input))
	if err != nil {
		fmt.Println("GenSortTX出现错了出现错了", err)
	}
	return tx, err
}

// GenSelectHostTX  生成选取秘密持有节点的交易
func GenSelectHostTX(nonce uint64) (pb.Transaction, error) {
	randomNumber := rand.Intn(4)
	//for i := 0; i < len(MyNode.PubKeys); i++ {
	//	if MyNode.PubKeys[i] == MyNode.PrivKey.PublicKey() {
	//		randomNumber = 3 - i
	//	}
	//}
	randomNumber = 4 - MyNode.index
	fmt.Printf("选择节点%d作为托管委员会成员节点", randomNumber+1)

	//生成临时私钥
	privKey1, err := asym.GenerateKeyPair(crypto.Secp256k1)
	bytes, err := privKey1.Bytes()
	if err != nil {
		return nil, err
	}
	MyNode.TempPubKey = privKey1.PublicKey()
	fmt.Println("生成的临时私钥信息", bytes)

	//发送节点私钥构建的加密器
	cryptor, err := txcrypto.NewSimpleCryptor(MyNode.PrivKey, getKeyMap())
	if err != nil {
		return nil, err
	}

	//获取选择节点的公钥地址
	address, err := MyNode.PubKeys[randomNumber].Address()
	fmt.Println("选择节点的公钥地址", address.Address)
	//使用对应公钥地址进行加密
	//加密内容是临时沟通私钥
	encryptBytes, err := cryptor.Encrypt(bytes, address.Address)
	fmt.Println("生成的加密内容", encryptBytes)
	add, _ := MyNode.PrivKey.PublicKey().Address()
	addSelf := add.Address
	fmt.Println("自己节点的公钥地址", addSelf)
	tx, err := GenBxhTx(MyNode.PrivKey, nonce, constant.SelectHostContractAddr.Address(), "Select", pb.Bytes(encryptBytes), pb.String(addSelf))
	if err != nil {
		fmt.Println("GenSelectHostTX出现错了出现错了", err)
	}
	return tx, err
}

// GenEmptySelectHostTX 生成选取秘密持有节点的空的交易
func GenEmptySelectHostTX(nonce uint64) (pb.Transaction, error) {
	add, _ := MyNode.PrivKey.PublicKey().Address()
	addSelf := add.Address
	fmt.Println("自己节点的公钥地址", addSelf)
	tx, err := GenBxhTx(MyNode.PrivKey, nonce, constant.SelectHostContractAddr.Address(), "Select", pb.Bytes(nil), pb.String(""))
	if err != nil {
		fmt.Println("GenEmptySelectHostTX出现错了出现错了", err)
	}
	return tx, err
}

// GenVerifyHostTX 生成选取秘密持有节点的交易
func GenVerifyHostTX(nonce uint64) (pb.Transaction, error) {
	add, _ := MyNode.PrivKey.PublicKey().Address()
	addSelf := add.Address
	tx, err := GenBxhTx(MyNode.PrivKey, nonce, constant.SelectHostContractAddr.Address(), "Select", pb.String(addSelf))
	if err != nil {
		fmt.Println("GenSelectHostTX出现错了出现错了", err)
	}
	return tx, err
}

// GenKeyMapTX 上传临时会话公钥和byte形成临时密钥的keymap
func GenKeyMapTX(nonce uint64) (pb.Transaction, error) {
	key := MyNode.PrivKey
	Byte, _ := MyNode.TempPubKey.Bytes()
	Address, err := MyNode.TempPubKey.Address()
	if err != nil {
		return nil, err
	}
	address := Address.String()
	tx, err := GenBxhTx(key, nonce, constant.TempKeyMapContractAddr.Address(), "Set", pb.Bytes(Byte), pb.String(address))
	if err != nil {
		fmt.Println("GenKeyMapTX出现错了出现错了", err)
	}
	return tx, err
}

// GenEmptyKeyMapTX 上传空的keymap
func GenEmptyKeyMapTX(nonce uint64) (pb.Transaction, error) {
	key := MyNode.PrivKey
	tx, err := GenBxhTx(key, nonce, constant.TempKeyMapContractAddr.Address(), "Set", pb.Bytes(nil), pb.String(""))
	if err != nil {
		fmt.Println("GenKeyMapTX出现错了出现错了", err)
	}
	return tx, err
}

//// GenGetFullShareSecret 生成首次获取完整密钥的交易
//func GenGetFullShareSecret(nonce uint64, index int64) (pb.Transaction, error) {
//	key := MyNode.PrivKey
//	tx, err := GenBxhTx(key, nonce, constant.SecretShareContractAddr.Address(), "GetFullSecretShare", pb.Int64(index))
//	if err != nil {
//		fmt.Println("GenGetFullShareSecret出现错了出现错了", err)
//	}
//	return tx, err
//}

// GenCollect34ShareTx 生成上传恢复一半456密钥碎片的交易
func GenCollect34ShareTx(nonce uint64, bytes []byte) (pb.Transaction, error) {
	index := MyNode.index
	key := MyNode.PrivKey
	tx, err := GenBxhTx(key, nonce, constant.SecretShareContractAddr.Address(), "Collect34Share", pb.Int64(int64(index)), pb.Bytes(bytes))
	if err != nil {
		fmt.Println("GenCollect456ShareTx出现错了出现错了", err)
	}
	return tx, err
}

// GenCollect456ShareTx 生成上传恢复完整456密钥碎片的交易
func GenCollect456ShareTx(nonce uint64, bytes []byte) (pb.Transaction, error) {
	index := MyNode.afterIndex
	key := MyNode.PrivKey
	tx, err := GenBxhTx(key, nonce, constant.SecretShareContractAddr.Address(), "Collect456Share", pb.Int64(int64(index)), pb.Bytes(bytes))
	if err != nil {
		fmt.Println("GenCollect456ShareTx出现错了出现错了", err)
	}
	return tx, err
}

// GenSecretRecoveryTx 生成上传恢复完整密钥碎片的交易
func GenSecretRecoveryTx(nonce uint64, bytes []byte) (pb.Transaction, error) {
	index := MyNode.index
	key := MyNode.PrivKey
	tx, err := GenBxhTx(key, nonce, constant.SecretShareContractAddr.Address(), "CollectSecretRecoveryShare", pb.Int64(int64(index)), pb.Bytes(bytes))
	if err != nil {
		fmt.Println("GenCollect456ShareTx出现错了出现错了", err)
	}
	return tx, err
}

// InvokeSearchContract 不发交易调用查询排序合约
func InvokeSearchContract(executor executor.Executor, tx pb.Transaction, input []byte) ([]byte, error) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "Search",
		Args:   []*pb.Arg{pb.Bytes(input)},
	}
	input, err := payload.Marshal()
	if err != nil {
		return nil, err
	}

	ret, _, err := instance.InvokeBVM(constant.VrfSortContractAddr.Address().String(), input)
	if err != nil {
		fmt.Println("合约调用出现错了出现错了", err)
	}
	return ret, err
}

// InvokeVerifyContract 不发交易调用查询排序合约
func InvokeVerifyContract(executor executor.Executor, tx pb.Transaction, addr string) ([]byte, error) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "Verify",
		Args:   []*pb.Arg{pb.String(addr)},
	}
	input, err := payload.Marshal()
	if err != nil {
		return nil, err
	}

	ret, _, err := instance.InvokeBVM(constant.SelectHostContractAddr.Address().String(), input)
	return ret, err
}

// InvokeGetKeyMapContract 不发交易调用获取keyMap合约
func InvokeGetKeyMapContract(executor executor.Executor, tx pb.Transaction) ([]byte, error) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "Get",
		Args:   []*pb.Arg{},
	}
	input, err := payload.Marshal()
	if err != nil {
		return nil, err
	}

	ret, _, err := instance.InvokeBVM(constant.TempKeyMapContractAddr.Address().String(), input)
	if err != nil {
		fmt.Println("合约调用出现错了出现错了", err)
	}
	return ret, err
}

// InvokeGetFullShareSecretContract  不发交易调用获取首次完整秘密合约
func InvokeGetFullShareSecretContract(executor executor.Executor, tx pb.Transaction, index int64) ([]byte, error) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "GetFullSecretShare",
		Args:   []*pb.Arg{pb.Int64(index)},
	}
	input, err := payload.Marshal()
	if err != nil {
		return nil, err
	}

	ret, _, err := instance.InvokeBVM(constant.SecretShareContractAddr.Address().String(), input)
	if err != nil {
		fmt.Println("InvokeGetFullShareSecretMapContract合约调用出现错了出现错了", err)
	}
	return ret, err
}

// InvokeGet34Share 获取34节点的密钥碎片
func InvokeGet34Share(executor executor.Executor, tx pb.Transaction) ([]byte, error) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "Get34Share",
		Args:   []*pb.Arg{pb.Int64(int64(MyNode.index))},
	}
	input, err := payload.Marshal()
	if err != nil {
		return nil, err
	}

	ret, _, err := instance.InvokeBVM(constant.SecretShareContractAddr.Address().String(), input)
	if err != nil {
		fmt.Println("InvokeGet456Share合约调用出现错了出现错了", err)
	}
	return ret, err
}

func InvokeGet456Share(executor executor.Executor, tx pb.Transaction) ([]byte, error) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "Get456Share",
		Args:   []*pb.Arg{pb.Int64(int64(MyNode.afterIndex))},
	}
	input, err := payload.Marshal()
	if err != nil {
		return nil, err
	}

	ret, _, err := instance.InvokeBVM(constant.SecretShareContractAddr.Address().String(), input)
	if err != nil {
		fmt.Println("InvokeGet456Share合约调用出现错了出现错了", err)
	}
	return ret, err
}

func InvokeGetRecoveryShare(index int64, executor executor.Executor, tx pb.Transaction) ([]byte, error) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "GetRecoveryShare",
		Args:   []*pb.Arg{pb.Int64(index)},
	}
	input, err := payload.Marshal()
	if err != nil {
		return nil, err
	}

	ret, _, err := instance.InvokeBVM(constant.SecretShareContractAddr.Address().String(), input)
	if err != nil {
		fmt.Println("InvokeGetRecoveryShare合约调用出现错了出现错了", err)
	}
	return ret, err
}

func InvokeGet34ShareLength(executor executor.Executor, tx pb.Transaction) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "Get34ShareSize",
		Args:   []*pb.Arg{},
	}
	input, err := payload.Marshal()
	if err != nil {
		return
	}

	for {
		ret, _, err := instance.InvokeBVM(constant.SecretShareContractAddr.Address().String(), input)
		if err != nil {
			fmt.Println("InvokeGet34ShareLength合约调用出现错了出现错了", err)
		}
		if string(ret) == "4" {
			return
		}
	}
}

func InvokeGet456ShareLength(executor executor.Executor, tx pb.Transaction) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "Get456ShareSize",
		Args:   []*pb.Arg{},
	}
	input, err := payload.Marshal()
	if err != nil {
		return
	}

	for {
		ret, _, err := instance.InvokeBVM(constant.SecretShareContractAddr.Address().String(), input)
		if err != nil {
			fmt.Println("Get456ShareSize出现错了出现错了", err)
		}
		if string(ret) == "4" {
			return
		}
	}
}

func InvokeGetRecoveryStatus(executor executor.Executor, tx pb.Transaction) {

	invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
		executor.GetConfig().EnableAudit, nil)

	instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())

	payload := &pb.InvokePayload{
		Method: "GetRecoveryStatus",
		Args:   []*pb.Arg{},
	}
	input, err := payload.Marshal()
	if err != nil {
		return
	}

	for {
		ret, _, err := instance.InvokeBVM(constant.SecretShareContractAddr.Address().String(), input)
		if err != nil {
			fmt.Println("InvokeGetRecoveryStatus", err)
		}
		if len(ret) == 1 {
			return
		}
	}
}

func getKeyMap() map[string][]byte {
	keyMap := make(map[string][]byte)
	for i := 0; i < len(MyNode.PubKeys); i++ {
		address, _ := MyNode.PubKeys[i].Address()
		addr := address.Address
		bytes, _ := MyNode.PubKeys[i].Bytes()
		keyMap[addr] = bytes
	}
	return keyMap
}

func DecryptTempPri(BlockExecutor executor.Executor) error {
	//按照节点公钥的顺序调用Verify合约，获得所有选举节点发送的加密信息
	VerifyTX, _ := GenVerifyHostTX(Nonce)
	//Nonce++
	for i := 0; i < len(MyNode.PubKeys); i++ {
		t, err := MyNode.PubKeys[i].Address()
		fmt.Println("解密时选取的地址", t.Address)
		ret, err := InvokeVerifyContract(BlockExecutor, VerifyTX, t.Address)
		if err != nil {
			fmt.Println("InvokeVerifyContract遇到问题", err.Error())
			continue
		}
		if len(ret) == 0 {
			continue
		}
		fmt.Println("获得选举节点发送的加密信息", ret)
		cryptor, err := txcrypto.NewSimpleCryptor(MyNode.PrivKey, getKeyMap())
		decrypt, err := cryptor.Decrypt(ret, t.Address)
		if err != nil {
			fmt.Println("进行解密时遇到的问题", err)
			continue
		}
		key, err := ecdsa.UnmarshalPrivateKey(decrypt, 3)
		if err != nil {
			fmt.Println("进行UnmarshalPrivateKey时遇到的问题", err)
			//return err
			continue
		}
		bytes, err := key.Bytes()
		MyNode.TempPrivKey = key
		fmt.Println("解密出的临时私钥信息", bytes)
		break
	}
	return nil
}
