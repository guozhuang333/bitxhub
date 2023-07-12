package main

import (
	"context"
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
	"github.com/meshplus/bitxhub/internal/coreapi/api"
	"github.com/meshplus/bitxhub/internal/executor"
	"github.com/meshplus/bitxhub/pkg/vm"
	"github.com/meshplus/bitxhub/pkg/vm/boltvm"
	"github.com/meshplus/bitxhub/txcrypto"
	"math/big"
	"math/rand"
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
	Vrf            []byte
	PrivKey        crypto.PrivateKey
	TempPrivKey    crypto.PrivateKey
	IsSele         bool
	AllNodeAddress []*repo.NetworkNodes
	PubKeys        []crypto.PublicKey
}

var Nonce uint64

var MyNode Node

func start(ctx *cli.Context) error {
	Nonce = 0

	offChainTransmissionConstructor, err := agency.GetOffchainTransmissionConstructor("offChain_transmission")
	if err != nil {
		return fmt.Errorf("offchain transmission constructor not found")
	}

	offChainTransmissionMgr := offChainTransmissionConstructor()
	err = offChainTransmissionMgr.Start()
	if err != nil {
		return fmt.Errorf("offchain transmission start 出问题了")
	}

	vrf, err := offChainTransmissionMgr.VRF([]byte{})
	if err != nil {
		return fmt.Errorf("VRF函数 出问题了 : %w", err)
	}
	MyNode = Node{
		Vrf: vrf,
	}

	fmt.Printf("vrf 函数结果是 %v", vrf)

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

	MyNode.PrivKey = repo.Key.PrivKey

	address, err := MyNode.PrivKey.PublicKey().Address()
	fmt.Println("自己节点的公钥地址", address)

	//生成排序交易
	tx, err := GenSortTX(repo.Key.PrivKey, vrf, Nonce)
	Nonce++
	if err != nil {
		return err
	}

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

	//调用排序合约
	err = api.Broker().HandleTransaction(tx)
	if err != nil {
		return fmt.Errorf("调用排序合约HandleTransaction出错", err)
	}

	receipt, err := sendTransactionWithReceipt(api, tx)
	if err != nil {
		return fmt.Errorf("调用排序合约sendTransactionWithReceipt出错", err)
	}

	logger.Logger.Println("收到回执", string(receipt.Ret))

	ret, err := InvokeSearchContract(bxh.BlockExecutor, tx, vrf)
	if err != nil {
		return err
	}
	//fmt.Println("合约调用结果", string(ret))

	//根据合约结果判断是否成为选举节点
	num, _ := strconv.Atoi(string(ret))
	if num < 2 {
		MyNode.IsSele = true
	}
	if MyNode.IsSele == true {
		logger.Logger.Println("该节点已被选为选举委员会成员")
	}
	MyNode.AllNodeAddress = repo.NetworkConfig.Nodes

	if MyNode.IsSele {
		selectHostTX, err := GenSelectHostTX(Nonce)
		Nonce++
		if err != nil {
			return err
		}

		//调用选举合约
		err = api.Broker().HandleTransaction(selectHostTX)
		if err != nil {
			return fmt.Errorf("调用选举合约HandleTransaction出错", err)
		}

		receipt, err = sendTransactionWithReceipt(api, selectHostTX)
		if err != nil {
			return fmt.Errorf("调用选举合约sendTransactionWithReceipt出错", err)
		}

		logger.Logger.Println("收到回执", string(receipt.Ret))
	} else {
		selectHostTX, err := GenEmptySelectHostTX(Nonce)
		Nonce++
		if err != nil {
			return err
		}

		//调用选举合约
		err = api.Broker().HandleTransaction(selectHostTX)
		if err != nil {
			return fmt.Errorf("调用空选举合约HandleTransaction出错", err)
		}

		receipt, err = sendTransactionWithReceipt(api, selectHostTX)
		if err != nil {
			return fmt.Errorf("调用空选举合约sendTransactionWithReceipt出错", err)
		}

		logger.Logger.Println("收到回执", string(receipt.Ret))
	}

	err = DecryptTempPri(bxh.BlockExecutor)
	if err != nil {
		fmt.Println("DecryptTempPri", err)
		return err
	}

	wg.Wait()

	return nil
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
			time.Sleep(200 * time.Millisecond)
			err = retry.Retry(func(attempt uint) error {
				receipt, err = api.Broker().GetReceipt(tx.GetHash())
				if err != nil {
					return err
				}

				return nil
			},
				strategy.Limit(5),
				strategy.Backoff(backoff.Fibonacci(200*time.Millisecond)),
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
	fmt.Printf("选择节点%d作为托管委员会成员节点", randomNumber+1)
	privKey1, err := asym.GenerateKeyPair(crypto.Secp256k1)
	bytes, err := privKey1.Bytes()
	if err != nil {
		return nil, err
	}
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

// GenEmptySelectHostTX 生成选取秘密持有节点的交易
func GenEmptySelectHostTX(nonce uint64) (pb.Transaction, error) {
	add, _ := MyNode.PrivKey.PublicKey().Address()
	addSelf := add.Address
	fmt.Println("自己节点的公钥地址", addSelf)
	tx, err := GenBxhTx(MyNode.PrivKey, nonce, constant.SelectHostContractAddr.Address(), "Select", pb.Bytes(nil), pb.String(addSelf))
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
	for i := 0; i < len(MyNode.PubKeys); i++ {
		VerifyTX, err := GenVerifyHostTX(Nonce)
		Nonce++
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
		fmt.Println("解密出的临时私钥信息", bytes)
		break
	}
	return nil
}
