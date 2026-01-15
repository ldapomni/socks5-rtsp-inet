package logger

import (
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelError
)

var (
	currLevel = LevelInfo
	logger    *log.Logger
	mu        sync.Mutex
)

// Init initializes the global logger
func Init(path string, levelStr string) error {
	mu.Lock()
	defer mu.Unlock()

	// Parse Level
	switch strings.ToLower(levelStr) {
	case "debug":
		currLevel = LevelDebug
	case "info":
		currLevel = LevelInfo
	case "error":
		currLevel = LevelError
	default:
		currLevel = LevelInfo
	}

	// Setup Output
	var out io.Writer = os.Stderr
	if path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		out = io.MultiWriter(os.Stderr, f) // Log to both stderr and file
	}

	logger = log.New(out, "", log.LstdFlags)
	return nil
}

func Debugf(format string, v ...interface{}) {
	if currLevel <= LevelDebug {
		output("DEBUG", format, v...)
	}
}

func Infof(format string, v ...interface{}) {
	if currLevel <= LevelInfo {
		output("INFO", format, v...)
	}
}

func Errorf(format string, v ...interface{}) {
	if currLevel <= LevelError {
		output("ERROR", format, v...)
	}
}

func Fatalf(format string, v ...interface{}) {
	output("FATAL", format, v...)
	os.Exit(1)
}

func output(prefix, format string, v ...interface{}) {
	if logger == nil {
		// Fallback if not initialized
		log.Printf("[%s] "+format, append([]interface{}{prefix}, v...)...)
		return
	}
	logger.Printf("[%s] "+format, append([]interface{}{prefix}, v...)...)
}
