// Copyright (c) 2023 TuringBitChain
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// Transaction represents a bitcoin transaction.
type Transaction struct {
	Version    uint32
	LockTime   uint32
	TxIn       []*TxInput
	TxOut      []*TxOutput
	TxInCount  uint
	TxOutCount uint
}

// TxInput represents a bitcoin transaction input.
type TxInput struct {
	Hash            []byte
	Index           uint32
	SignatureScript []byte
	Sequence        uint32
}

// PkScript represents a bitcoin transaction output script.
type PkScript struct {
	Pkscript []byte
}

// TxOutput represents a bitcoin transaction output.
type TxOutput struct {
	Value    uint64
	PkScript PkScript
}

// doubleSha256 计算 sha256(sha256(b)).
func doubleSha256(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// reverseBytes 反转字节序列
func reverseBytes(b []byte) []byte {
	reversed := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		reversed[i] = b[len(b)-1-i]
	}
	return reversed
}

// ConvertWireMsgTxToCommonTransaction 将 wire.MsgTx 转换为 Transaction
func ConvertWireMsgTxToCommonTransaction(msgTx *MsgTx) *Transaction {
	commonTx := &Transaction{
		Version:    uint32(msgTx.Version),
		LockTime:   msgTx.LockTime,
		TxIn:       make([]*TxInput, len(msgTx.TxIn)),
		TxOut:      make([]*TxOutput, len(msgTx.TxOut)),
		TxInCount:  uint(len(msgTx.TxIn)),
		TxOutCount: uint(len(msgTx.TxOut)),
	}

	for i, txIn := range msgTx.TxIn {
		// 直接使用原始哈希（小端序）
		hashBytes := make([]byte, len(txIn.PreviousOutPoint.Hash))
		copy(hashBytes, txIn.PreviousOutPoint.Hash[:])

		commonTx.TxIn[i] = &TxInput{
			Hash:            hashBytes, // 使用小端序字节序列
			Index:           txIn.PreviousOutPoint.Index,
			SignatureScript: txIn.SignatureScript,
			Sequence:        txIn.Sequence,
		}
	}

	for i, txOut := range msgTx.TxOut {
		commonTx.TxOut[i] = &TxOutput{
			Value: uint64(txOut.Value),
			PkScript: PkScript{
				Pkscript: txOut.PkScript,
			},
		}
	}

	return commonTx
}

// CalculateTxID 计算交易ID.
// 如果交易版本为10, 它将使用一个特殊的三层哈希计算方式.
// 否则, 它将对原始交易数据进行标准的 double_sha256 计算.
// rawTxData 是序列化后的原始交易字节.
// tx 是从 transaction_parser.go 反序列化后的交易结构体.
func CalculateTxID(rawTxData []byte, tx *Transaction) []byte {
	if tx.Version != 10 {
		return doubleSha256(rawTxData)
	}

	// 1. 准备各部分数据
	var (
		serialization1 []byte // 输入部分
		serialization2 []byte // 脚本部分
		serialization3 []byte // 输出部分
	)

	// 处理输入部分
	for _, input := range tx.TxIn {
		// 序列化: TXID(小端) + VOUT + Sequence
		serialization1 = append(serialization1, input.Hash...) // 注意: 这里Hash应该已经是小端序

		indexBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(indexBytes, input.Index)
		serialization1 = append(serialization1, indexBytes...)

		sequenceBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequenceBytes, input.Sequence)
		serialization1 = append(serialization1, sequenceBytes...)

		// 脚本哈希
		scriptHash := sha256.Sum256(input.SignatureScript)
		serialization2 = append(serialization2, scriptHash[:]...)
	}

	// 处理输出部分
	for _, output := range tx.TxOut {
		valueBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(valueBytes, output.Value)
		serialization3 = append(serialization3, valueBytes...)

		scriptHash := sha256.Sum256(output.PkScript.Pkscript)
		serialization3 = append(serialization3, scriptHash[:]...)
	}

	// 计算各部分哈希
	hash1 := sha256.Sum256(serialization1)
	hash2 := sha256.Sum256(serialization2)
	hash3 := sha256.Sum256(serialization3)

	// 准备头部数据
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, tx.Version)

	locktimeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktimeBytes, tx.LockTime)

	inputCountBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(inputCountBytes, uint32(len(tx.TxIn)))

	outputCountBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(outputCountBytes, uint32(len(tx.TxOut)))

	// 构建最终序列化数据
	finalSerialization := bytes.Join([][]byte{
		versionBytes,
		locktimeBytes,
		inputCountBytes,
		outputCountBytes,
		hash1[:],
		hash2[:],
		hash3[:],
	}, nil)

	// 计算最终TXID (SHA256d)
	firstHash := sha256.Sum256(finalSerialization)
	finalHash := sha256.Sum256(firstHash[:])

	return finalHash[:]
}
