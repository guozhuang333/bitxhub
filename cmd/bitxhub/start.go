package main

import (
	"context"
	"fmt"
	"github.com/Rican7/retry"
	"github.com/Rican7/retry/backoff"
	"github.com/Rican7/retry/strategy"
	"github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/types"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxhub/internal/coreapi/api"
	"math/big"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
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

func start(ctx *cli.Context) error {

	fmt.Printf("GetOffchainTransmissionConstructor 之前————————————————————————————————————————————————————————")

	offChainTransmissionConstructor, err := agency.GetOffchainTransmissionConstructor("offChain_transmission")
	if err != nil {
		return fmt.Errorf("offchain transmission constructor not found")
	}

	fmt.Printf("GetOffchainTransmissionConstructor 之后————————————————————————————————————————————————————————")

	offChainTransmissionMgr := offChainTransmissionConstructor()
	err = offChainTransmissionMgr.Start()
	if err != nil {
		return fmt.Errorf("offchain transmission start 出问题了")
	}

	fmt.Printf("start 之后————————————————————————————————————————————————————————-")

	vrf, err := offChainTransmissionMgr.VRF([]byte{})
	if err != nil {
		return fmt.Errorf("VRF函数 出问题了 : %w", err)
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

	//生成BXH交易
	key := repo.Key.PrivKey
	address, err := key.PublicKey().Address()
	if err != nil {
		fmt.Println("出现错了出现错了", err)
	}
	s := address.String()
	nonce := bxh.Order.GetPendingNonceByAccount(s)
	tx, err := genBxhTx(key, nonce, constant.VrfSortContractAddr.Address(), "Sort", pb.Bytes(vrf))
	fmt.Println("toaddress", constant.VrfSortContractAddr.Address().String())
	if err != nil {
		fmt.Println("出现错了出现错了", err)
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

	//调用合约
	//executor := bxh.BlockExecutor
	//
	//invokeCtx := vm.NewContext(tx, uint64(0), nil, executor.GetHeight()+1, executor.GetLedger(), executor.GetLogger(),
	//	executor.GetConfig().EnableAudit, nil)
	//
	//instance := boltvm.New(invokeCtx, executor.GetValidationEngine(), executor.GetEvm(), executor.GetTxsExecutor().GetBoltContracts())
	//
	//payload := &pb.InvokePayload{
	//	Method: "Sort",
	//	Args:   []*pb.Arg{pb.Bytes(vrf)},
	//}
	//input, err := payload.Marshal()
	//if err != nil {
	//	return err
	//}
	//
	//ret, _, err := instance.InvokeBVM(constant.VrfSortContractAddr.Address().String(), input)
	//if err != nil {
	//	fmt.Println("合约调用出现错了出现错了", err)
	//}
	//fmt.Println("合约调用结果", string(ret))

	//ret, err := instance.HandleIBTP(tx.GetIBTP(), executor.GetServiceCache())
	//if err != nil {
	//	fmt.Println("合约调用出现错了出现错了", err)
	//}
	//fmt.Println("合约调用结果", string(ret))

	//err = api.Broker().HandleTransaction(tx)
	//if err != nil {
	//	fmt.Println("HandleTransaction出现错了出现错了", err)
	//}
	//
	//receipt, err := sendTransactionWithReceipt(api, tx)
	//if err != nil {
	//	fmt.Println("sendTransactionWithReceipt出现错误了", err)
	//}
	//
	//fmt.Println("收到回执", receipt)

	var wg sync.WaitGroup
	wg.Add(1)
	handleLicenceCheck(bxh, repo, &wg)
	handleShutdown(bxh, &wg)

	if err := bxh.Start(); err != nil {
		return fmt.Errorf("start bitxhub failed: %w", err)
	}

	err = api.Broker().HandleTransaction(tx)
	if err != nil {
		fmt.Println("HandleTransaction出现错了出现错了", err)
	}

	receipt, err := sendTransactionWithReceipt(api, tx)
	if err != nil {
		fmt.Println("sendTransactionWithReceipt出现错误了", err)
	}

	fmt.Println("收到回执", string(receipt.Ret))

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

func genBxhTx(privateKey crypto.PrivateKey, nonce uint64, address *types.Address, method string, args ...*pb.Arg) (pb.Transaction, error) {
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
