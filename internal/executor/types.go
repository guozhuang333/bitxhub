package executor

import (
	"github.com/ethereum/go-ethereum/event"
	"github.com/meshplus/bitxhub-core/agency"
	"github.com/meshplus/bitxhub-core/validator"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxhub/internal/ledger"
	"github.com/meshplus/bitxhub/internal/model/events"
	"github.com/meshplus/bitxhub/internal/repo"
	vm "github.com/meshplus/eth-kit/evm"
	"github.com/sirupsen/logrus"
	"sync"
)

type Executor interface {
	// Start
	Start() error

	// Stop
	Stop() error

	// ExecutorBlock
	ExecuteBlock(commitEvent *pb.CommitEvent)

	// ApplyReadonlyTransactions execute readonly tx
	ApplyReadonlyTransactions(txs []pb.Transaction) []*pb.Receipt

	// SubscribeBlockEvent
	SubscribeBlockEvent(chan<- events.ExecutedEvent) event.Subscription

	// SubscribeBlockEventForRemote
	SubscribeBlockEventForRemote(chan<- events.ExecutedEvent) event.Subscription

	// SubscribeLogEvent
	SubscribeLogsEvent(chan<- []*pb.EvmLog) event.Subscription

	// SubscribeNodeEvent
	SubscribeNodeEvent(chan<- events.NodeEvent) event.Subscription

	// SubscribeAuditEvent
	SubscribeAuditEvent(chan<- *pb.AuditTxInfo) event.Subscription

	GetBoltContracts() map[string]agency.Contract

	GetHeight() uint64

	GetLedger() *ledger.Ledger

	GetLogger() logrus.FieldLogger

	GetConfig() repo.Config

	GetValidationEngine() validator.Engine

	GetEvm() *vm.EVM

	GetTxsExecutor() agency.TxsExecutor

	GetServiceCache() *sync.Map
}
