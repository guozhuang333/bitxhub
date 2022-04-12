package utils

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	crypto3 "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/meshplus/bitxhub-core/tss"
	"github.com/meshplus/bitxhub-core/tss/conversion"
	"github.com/meshplus/bitxhub-core/tss/keysign"
	crypto2 "github.com/meshplus/bitxhub-kit/crypto"
	"github.com/meshplus/bitxhub-kit/types"
	"github.com/meshplus/bitxhub-model/constant"
	"github.com/meshplus/bitxhub-model/pb"
	"github.com/meshplus/bitxhub/internal/executor/contracts"
	"github.com/meshplus/bitxhub/internal/ledger"
	"github.com/sirupsen/logrus"
)

var AuditEventStrHash = types.NewHash([]byte(fmt.Sprintf("event%d%d%d%d%d%d%d%d",
	pb.Event_AUDIT_PROPOSAL,
	pb.Event_AUDIT_APPCHAIN,
	pb.Event_AUDIT_RULE,
	pb.Event_AUDIT_SERVICE,
	pb.Event_AUDIT_NODE,
	pb.Event_AUDIT_ROLE,
	pb.Event_AUDIT_INTERCHAIN,
	pb.Event_AUDIT_DAPP)))

func GetIBTPSign(ledger *ledger.Ledger, id string, isReq bool, privKey crypto2.PrivateKey) (string, []byte, error) {
	ibtp, err := GetIBTP(ledger, id, isReq)
	if err != nil {
		return "", nil, fmt.Errorf("get ibtp %s isReq %v: %w", id, isReq, err)
	}

	txStatus, err := GetTxStatus(ledger, id)
	if err != nil {
		return "", nil, fmt.Errorf("get tx status of ibtp %s isReq %v: %w", id, isReq, err)
	}

	hash, err := EncodePackedAndHash(ibtp, txStatus)
	if err != nil {
		return "", nil, fmt.Errorf("encode packed and hash for ibtp %s isReq %v: %w", id, isReq, err)
	}

	sign, err := privKey.Sign(hash)
	if err != nil {
		return "", nil, fmt.Errorf("bitxhub sign ibtp %s isReq %v: %w", id, isReq, err)
	}

	addr, err := privKey.PublicKey().Address()
	if err != nil {
		return "", nil, fmt.Errorf("get address from public key failed: %w", err)
	}

	return addr.String(), sign, nil
}

// return :
// - signature data
// - blame nodes id list
// - error
func GetIBTPTssSign(tssMgr tss.Tss, ledger *ledger.Ledger, content string, isReq bool, extra []byte) ([]byte, []string, error) {
	// 1. get msgs to sign
	msgs, err := getMsgToSign(ledger, content, isReq)
	if err != nil {
		return nil, nil, fmt.Errorf("get msg to sign err: %w", err)
	}

	// 2. get pool pubkey
	_, pk, err := tssMgr.GetTssPubkey()
	if err != nil {
		return nil, nil, fmt.Errorf("get tss pubkey error: %w", err)
	}

	// 3. get signers pk
	signersID := strings.Split(string(extra), ",")
	partiesPkMap, err := tssMgr.GetTssKeyGenPartiesPkMap()
	if err != nil {
		return nil, nil, fmt.Errorf("fail to get keygen parties pk map error: %w", err)
	}
	signersPk := []crypto3.PubKey{}
	for _, id := range signersID {
		data, ok := partiesPkMap[id]
		if !ok {
			return nil, nil, fmt.Errorf("party %s is not keygen party", id)
		}
		pk, err := conversion.GetPubKeyFromPubKeyData(data)
		if err != nil {
			return nil, nil, fmt.Errorf("fail to conversion pubkeydata to pubkey: %w", err)
		}
		signersPk = append(signersPk, pk)
	}

	// 4, new req to sign
	keysignReq := keysign.NewRequest(pk, msgs, signersPk)
	resp, err := tssMgr.Keysign(keysignReq)

	if err != nil {
		if errors.Is(err, tss.ErrNotActiveSigner) {
			return nil, nil, err
		} else if len(resp.Blame.BlameNodes) != 0 {
			culpritIDs := []string{}
			for _, node := range resp.Blame.BlameNodes {
				culpritIDs = append(culpritIDs, node.PartyID)
			}
			return nil, culpritIDs, err
		} else {
			return nil, nil, fmt.Errorf("failed to tss key sign: %v", err)
		}
	}

	signData, err := json.Marshal(resp.Signatures)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal tss signatures: %v", err)
	}

	return signData, nil, nil
}

func getMsgToSign(ledger *ledger.Ledger, content string, isReq bool) ([]string, error) {
	ids := strings.Split(strings.Replace(content, " ", "", -1), ",")
	msgs := []string{}
	for _, id := range ids {
		ibtp, err := GetIBTP(ledger, id, isReq)
		if err != nil {
			return nil, fmt.Errorf("get ibtp %s isReq %v: %w", id, isReq, err)
		}
		txStatus, err := GetTxStatus(ledger, id)
		if err != nil {
			return nil, fmt.Errorf("get tx status of ibtp %s isReq %v: %w", id, isReq, err)
		}

		hash, err := EncodePackedAndHash(ibtp, txStatus)
		if err != nil {
			return nil, fmt.Errorf("encode packed and hash for ibtp %s isReq %v: %w", id, isReq, err)
		}

		msgs = append(msgs, base64.StdEncoding.EncodeToString(hash))
	}

	return msgs, nil
}

func VerifyTssSigns(signData []byte, pub *ecdsa.PublicKey, l logrus.FieldLogger) error {
	signs := []conversion.Signature{}
	if err := json.Unmarshal(signData, &signs); err != nil {
		return fmt.Errorf("unmarshal signData err: %w", err)
	}

	for _, sign := range signs {
		msgData, err := base64.StdEncoding.DecodeString(sign.Msg)
		rData, err := base64.StdEncoding.DecodeString(sign.R)
		sData, err := base64.StdEncoding.DecodeString(sign.S)
		if err != nil {
			return fmt.Errorf("sign convert error: %s", err)
		}
		if !ecdsa.Verify(pub, msgData, new(big.Int).SetBytes(rData), new(big.Int).SetBytes(sData)) {
			return fmt.Errorf("fail to verify sign")
		}
	}

	return nil
}

func GetIBTP(ledger *ledger.Ledger, id string, isReq bool) (*pb.IBTP, error) {
	key := contracts.IndexMapKey(id)
	if !isReq {
		key = contracts.IndexReceiptMapKey(id)
	}

	ok, val := ledger.Copy().GetState(constant.InterchainContractAddr.Address(), []byte(key))
	if !ok {
		return nil, fmt.Errorf("cannot get the tx hash which contains the IBTP %s", id)
	}

	var hash types.Hash
	if err := json.Unmarshal(val, &hash); err != nil {
		return nil, fmt.Errorf("unmarshal hash error: %w", err)
	}

	tx, err := ledger.GetTransaction(&hash)
	if err != nil {
		return nil, fmt.Errorf("get transaction %s from ledger failed: %w", hash.String(), err)
	}

	return tx.GetIBTP(), nil
}

// TODO: support global status
func GetTxStatus(ledger *ledger.Ledger, id string) (pb.TransactionStatus, error) {
	ok, val := ledger.Copy().GetState(constant.TransactionMgrContractAddr.Address(), []byte(contracts.TxInfoKey(id)))
	if !ok {
		return 0, fmt.Errorf("no tx status found for ibtp %s", id)
	}
	var record pb.TransactionRecord
	if err := json.Unmarshal(val, &record); err != nil {
		return 0, fmt.Errorf("unmarshal transaction record error: %w", err)
	}

	return record.Status, nil
}

func EncodePackedAndHash(ibtp *pb.IBTP, txStatus pb.TransactionStatus) ([]byte, error) {
	var (
		data []byte
		pd   pb.Payload
	)

	data = append(data, []byte(ibtp.From)...)
	data = append(data, []byte(ibtp.To)...)
	data = append(data, uint64ToBytesInBigEndian(ibtp.Index)...)
	data = append(data, uint64ToBytesInBigEndian(uint64(ibtp.Type))...)

	if err := pd.Unmarshal(ibtp.Payload); err != nil {
		return nil, fmt.Errorf("unmarshal ibtp payload error: %w", err)
	}

	data = append(data, pd.Hash...)
	data = append(data, uint64ToBytesInBigEndian(uint64(txStatus))...)

	hash := crypto.Keccak256(data)

	return hash[:], nil
}

func uint64ToBytesInBigEndian(i uint64) []byte {
	bytes := make([]byte, 8)

	binary.BigEndian.PutUint64(bytes, i)

	return bytes
}

func AddAuditPermitBloom(bloom *types.Bloom, relatedChains, relatedNodes map[string][]byte) {
	if bloom == nil {
		bloom = &types.Bloom{}
	}
	bloom.Add(AuditEventStrHash.Bytes())
	for k, _ := range relatedChains {
		bloom.Add(types.NewHash([]byte(k)).Bytes())
	}
	for k, _ := range relatedNodes {
		bloom.Add(types.NewHash([]byte(k)).Bytes())
	}
}

func TestAuditPermitBloom(logger logrus.FieldLogger, bloom *types.Bloom, relatedChains, relatedNodes map[string]struct{}) bool {
	if !bloom.Test(AuditEventStrHash.Bytes()) {
		return false
	}
	for k, _ := range relatedChains {
		if bloom.Test(types.NewHash([]byte(k)).Bytes()) {
			return true
		}
	}
	for k, _ := range relatedNodes {
		if bloom.Test(types.NewHash([]byte(k)).Bytes()) {
			return true
		}
	}
	return false
}
