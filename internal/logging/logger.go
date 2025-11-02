package logging

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type Logger struct {
	file   *os.File
	logger *log.Logger
}

var defaultLogger *Logger

func Init(logDir string) error {
	// Create log directory
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// Create log file
	logFile := filepath.Join(logDir, fmt.Sprintf("ifrit-%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	logger := &Logger{
		file:   file,
		logger: log.New(file, "", log.LstdFlags|log.Lshortfile),
	}

	defaultLogger = logger
	return nil
}

func Info(msg string, args ...interface{}) {
	text := fmt.Sprintf(msg, args...)
	fmt.Printf("[INFO] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.logger.Printf("[INFO] %s", text)
	}
}

func Error(msg string, args ...interface{}) {
	text := fmt.Sprintf(msg, args...)
	fmt.Printf("[ERROR] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.logger.Printf("[ERROR] %s", text)
	}
}

func Debug(msg string, args ...interface{}) {
	text := fmt.Sprintf(msg, args...)
	fmt.Printf("[DEBUG] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.logger.Printf("[DEBUG] %s", text)
	}
}

func Attack(sourceIP, method, path, attackType, stage string) {
	text := fmt.Sprintf("ATTACK | IP: %s | %s %s | Type: %s | %s", sourceIP, method, path, attackType, stage)
	fmt.Printf("[ATTACK] %s\n", text)
	if defaultLogger != nil {
		defaultLogger.logger.Printf("[ATTACK] %s", text)
	}
}

func Close() {
	if defaultLogger != nil && defaultLogger.file != nil {
		defaultLogger.file.Close()
	}
}
