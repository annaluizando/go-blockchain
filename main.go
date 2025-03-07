package main

import (
	"fmt"
	"path/filepath"
	"time"
)

var logger *BlockchainLogger

func main() {
	logger, err := NewBlockchainLogger(INFO, filepath.Join("logs", fmt.Sprintf("blockchain_%s.log", time.Now().Format("20060102_150405"))), true)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		return
	}
	defer logger.Close()

	logger.Info("Blockchain application starting...")

	logger.Info("Creating new blockchain with difficulty=4")
	bc := NewBlockchain(4)

	logger.Info("Creating new wallet")
	wallet, err := NewWallet()
	if err != nil {
		logger.Fatal("Failed to create wallet: %v", err)
	}
	logger.Info("Wallet created successfully with address: %s", wallet.Address)

	transaction := Transaction{
		From:  wallet.Address,
		To:    "recipient-address",
		Value: 100,
		Data:  "test transaction",
		Time:  time.Now().Unix(),
	}

	wallet.SignTransaction(&transaction)
	logger.Debug("Transaction signed with signature length: %d bytes", len(transaction.Signature))

	logger.Info("Adding transaction to blockchain")
	blockIndex, err := bc.AddTransaction(transaction, wallet.PublicKey)
	if err != nil {
		logger.Error("Failed to add transaction: %v", err)
	} else {
		logger.Info("Transaction added successfully, will be included in block %d", blockIndex)
	}

	logger.LogTransaction(transaction, "PENDING")

	logger.Info("Mining new block...")
	block := bc.AddBlock()

	logger.LogBlock(block, "MINED")

	logger.Info("Validating blockchain...")
	if bc.ValidateChain() {
		logger.Info("Blockchain validation successful")
	} else {
		logger.Error("Blockchain validation failed")
	}

	logger.Info("Blockchain application shutting down")
}
