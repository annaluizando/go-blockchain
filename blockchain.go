package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

type Wallet struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	Address    string
}

type Transaction struct {
	From      string
	To        string
	Value     int64
	Data      string
	Time      int64
	Signature []byte
}

type Block struct {
	Index        int
	Timestamp    int64
	Transactions []Transaction
	PreviousHash string
	Hash         string
	Proof        int
}

type Blockchain struct {
	Chain               []Block
	CurrentTransactions []Transaction
	Difficulty          int
}

func NewWallet() (*Wallet, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	addressHash := sha256.Sum256(publicKey)
	address := fmt.Sprintf("%x", addressHash)

	return &Wallet{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
	}, nil
}

func (w *Wallet) SignTransaction(tx *Transaction) {
	txData := fmt.Sprintf("%s%s%d%s%d", tx.From, tx.To, tx.Value, tx.Data, tx.Time)
	hash := sha256.Sum256([]byte(txData))

	tx.Signature = ed25519.Sign(w.PrivateKey, hash[:])
}
func VerifyTransaction(tx Transaction, publicKey ed25519.PublicKey) bool {
	txData := fmt.Sprintf("%s%s%d%s%d", tx.From, tx.To, tx.Value, tx.Data, tx.Time)
	hash := sha256.Sum256([]byte(txData))

	return ed25519.Verify(publicKey, hash[:], tx.Signature)
}

func (bc *Blockchain) GetBalance(address string) int64 {
	var balance int64 = 0

	for _, block := range bc.Chain {
		for _, tx := range block.Transactions {
			if tx.To == address {
				balance += tx.Value
			}

			if tx.From == address {
				balance -= tx.Value
			}
		}
	}

	return balance
}

func (bc *Blockchain) AddTransaction(transaction Transaction, publicKey ed25519.PublicKey) (int, error) {
	if !VerifyTransaction(transaction, publicKey) {
		return -1, errors.New("invalid transaction signature")
	}

	senderBalance := bc.GetBalance(transaction.From)
	if senderBalance < transaction.Value {
		return -1, errors.New("insufficient balance")
	}

	bc.CurrentTransactions = append(bc.CurrentTransactions, transaction)
	return bc.GetLastBlock().Index + 1, nil
}

func NewBlockchain(difficulty int) *Blockchain {
	bc := &Blockchain{
		Chain:               []Block{},
		CurrentTransactions: []Transaction{},
		Difficulty:          difficulty,
	}
	bc.CreateGenesisBlock()
	return bc
}

func (bc *Blockchain) ValidateChain() bool {
	for i := 1; i < len(bc.Chain); i++ {
		currentBlock := bc.Chain[i]
		previousBlock := bc.Chain[i-1]

		if currentBlock.Hash != currentBlock.CalculateHash() {
			return false
		}

		if currentBlock.PreviousHash != previousBlock.Hash {
			return false
		}

		if !bc.IsValidProof(previousBlock.Proof, currentBlock.Proof) {
			return false
		}
	}
	return true
}

func (b *Block) CalculateHash() string {
	transactionsBytes, err := json.Marshal(b.Transactions)
	if err != nil {
		log.Fatalf("Failed to marshal transactions: %v", err)
	}

	data := fmt.Sprintf("%d%d%s%s%d",
		b.Index,
		b.Timestamp,
		transactionsBytes,
		b.PreviousHash,
		b.Proof)

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func (bc *Blockchain) CreateGenesisBlock() {
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Transactions: []Transaction{},
		PreviousHash: "0",
		Proof:        0,
	}

	genesisBlock.Hash = genesisBlock.CalculateHash()
	bc.Chain = append(bc.Chain, genesisBlock)
}

func (bc *Blockchain) AddBlock() Block {
	lastBlock := bc.GetLastBlock()
	proof := bc.ProofOfWork(lastBlock.Proof)

	block := Block{
		Index:        lastBlock.Index + 1,
		Timestamp:    time.Now().Unix(),
		Transactions: bc.CurrentTransactions,
		Proof:        proof,
		PreviousHash: lastBlock.Hash,
	}

	block.Hash = block.CalculateHash()
	bc.Chain = append(bc.Chain, block)
	bc.CurrentTransactions = []Transaction{}

	return block
}

func (bc *Blockchain) ProofOfWork(lastProof int) int {
	proof := 0
	for !bc.IsValidProof(lastProof, proof) {
		proof++
	}
	return proof
}

func (bc *Blockchain) IsValidProof(lastProof, proof int) bool {
	guess := fmt.Sprintf("%d%d", lastProof, proof)
	hash := sha256.Sum256([]byte(guess))
	hexHash := fmt.Sprintf("%x", hash)

	prefix := strings.Repeat("0", bc.Difficulty)

	return hexHash[:bc.Difficulty] == prefix
}

func (bc *Blockchain) GetLastBlock() Block {
	return bc.Chain[len(bc.Chain)-1]
}
