package logging

import (
	"fmt"
	"log"
	"os"
)

// Logger wraps the standard library logger with structured logging methods
type Logger struct {
	logger *log.Logger
}

// New creates a new Logger instance
func New() *Logger {
	return &Logger{
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// Info logs an informational message with structured key-value pairs
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.log("INFO", msg, keysAndValues...)
}

// Error logs an error message with structured key-value pairs
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	l.log("ERROR", msg, keysAndValues...)
}

// log formats and outputs a log message with key-value pairs
// keysAndValues should be pairs like: "key1", value1, "key2", value2
func (l *Logger) log(level, msg string, keysAndValues ...interface{}) {
	// Start with level and message
	output := fmt.Sprintf("[%s] %s", level, msg)

	// Add key-value pairs
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := keysAndValues[i]
			value := keysAndValues[i+1]
			output += fmt.Sprintf(" %v=%v", key, value)
		}
	}

	l.logger.Println(output)
}
