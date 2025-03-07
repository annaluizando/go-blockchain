package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	FATAL
)

var logLevelNames = map[LogLevel]string{
	DEBUG:   "DEBUG",
	INFO:    "INFO",
	WARNING: "WARNING",
	ERROR:   "ERROR",
	FATAL:   "FATAL",
}

type BlockchainLogger struct {
	level      LogLevel
	logger     *log.Logger
	logFile    *os.File
	showSource bool
}

func NewBlockchainLogger(level LogLevel, logFilePath string, showSource bool) (*BlockchainLogger, error) {
	logDir := filepath.Dir(logFilePath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	multiWriter := io.MultiWriter(os.Stdout, logFile)

	logger := log.New(multiWriter, "", 0)

	return &BlockchainLogger{
		level:      level,
		logger:     logger,
		logFile:    logFile,
		showSource: showSource,
	}, nil
}

func (l *BlockchainLogger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// getSource returns the file and line number of the caller
func getSource(skip int) string {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "unknown:0"
	}
	// Get just the filename, not the full path
	short := filepath.Base(file)
	return fmt.Sprintf("%s:%d", short, line)
}

func (l *BlockchainLogger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	levelStr := logLevelNames[level]

	var sourceInfo string
	if l.showSource {
		sourceInfo = " " + getSource(3) // Skip 3 levels to get to the original caller
	}

	msg := fmt.Sprintf(format, args...)
	l.logger.Printf("[%s] [%s]%s %s", timestamp, levelStr, sourceInfo, msg)

	if level == FATAL {
		l.logger.Println("Exiting due to FATAL error")
		os.Exit(1)
	}
}

func (l *BlockchainLogger) Debug(format string, args ...any) {
	l.log(DEBUG, format, args...)
}

func (l *BlockchainLogger) Info(format string, args ...any) {
	l.log(INFO, format, args...)
}

func (l *BlockchainLogger) Warning(format string, args ...any) {
	l.log(WARNING, format, args...)
}

func (l *BlockchainLogger) Error(format string, args ...any) {
	l.log(ERROR, format, args...)
}

func (l *BlockchainLogger) Fatal(format string, args ...any) {
	l.log(FATAL, format, args...)
}

func (l *BlockchainLogger) LogTransaction(tx Transaction, status string) {
	l.Info("Transaction [%s]: From=%s, To=%s, Value=%d, Data=%s, Time=%d",
		status,
		truncateString(tx.From, 10),
		truncateString(tx.To, 10),
		tx.Value,
		truncateString(tx.Data, 20),
		tx.Time)
}

func (l *BlockchainLogger) LogBlock(block Block, status string) {
	l.Info("Block [%s]: Index=%d, Hash=%s, PrevHash=%s, Transactions=%d, Timestamp=%d",
		status,
		block.Index,
		truncateString(block.Hash, 10),
		truncateString(block.PreviousHash, 10),
		len(block.Transactions),
		block.Timestamp)
}

// Helper function to truncate long strings
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen/2] + "..." + s[len(s)-maxLen/2:]
}
