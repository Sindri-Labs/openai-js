// Package logger provides a WASM-compatible stub for github.com/google/logger
// to resolve build issues when compiling for WASM target.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

// Level represents the logger verbosity level.
type Level int32

// Verbose represents a verbose logger that can be enabled/disabled.
type Verbose struct {
	enabled bool
	logger  *Logger
}

// Info logs an info message if verbose logging is enabled.
func (v Verbose) Info(args ...interface{}) {
	if v.enabled {
		// For WASM builds, just print to console
		fmt.Println(args...)
	}
}

// Infoln logs an info message with newline if verbose logging is enabled.
func (v Verbose) Infoln(args ...interface{}) {
	if v.enabled {
		fmt.Println(args...)
	}
}

// Infof logs a formatted info message if verbose logging is enabled.
func (v Verbose) Infof(format string, args ...interface{}) {
	if v.enabled {
		fmt.Printf(format, args...)
	}
}

// Logger is a stub implementation for WASM builds.
type Logger struct {
	infoLog    *log.Logger
	warningLog *log.Logger
	errorLog   *log.Logger
}

// Info logs an info message.
func (l *Logger) Info(v ...interface{}) {
	if l.infoLog != nil {
		l.infoLog.Print(v...)
	}
}

// Infof logs a formatted info message.
func (l *Logger) Infof(format string, v ...interface{}) {
	if l.infoLog != nil {
		l.infoLog.Printf(format, v...)
	}
}

// Warning logs a warning message.
func (l *Logger) Warning(v ...interface{}) {
	if l.warningLog != nil {
		l.warningLog.Print(v...)
	}
}

// Warningf logs a formatted warning message.
func (l *Logger) Warningf(format string, v ...interface{}) {
	if l.warningLog != nil {
		l.warningLog.Printf(format, v...)
	}
}

// Error logs an error message.
func (l *Logger) Error(v ...interface{}) {
	if l.errorLog != nil {
		l.errorLog.Print(v...)
	}
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, v ...interface{}) {
	if l.errorLog != nil {
		l.errorLog.Printf(format, v...)
	}
}

// Close closes the logger (no-op for WASM).
func (l *Logger) Close() {}

// Init creates a new logger for WASM builds.
// This is a simplified version that writes to stdout/stderr instead of syslog.
func Init(name string, verbose, systemLog bool, logFile io.Writer) *Logger {
	if logFile == nil {
		logFile = os.Stderr
	}

	return &Logger{
		infoLog:    log.New(logFile, "INFO: ", log.LstdFlags),
		warningLog: log.New(logFile, "WARNING: ", log.LstdFlags),
		errorLog:   log.New(logFile, "ERROR: ", log.LstdFlags),
	}
}

// setup is a stub function for WASM builds.
// The original logger package calls this function but it's only defined
// for specific platforms (linux/darwin/freebsd/windows).
func setup(name string) (io.Writer, io.Writer, io.Writer, error) {
	// Return nil writers for WASM builds since we can't use syslog
	return nil, nil, nil, nil
}

// V returns a verbose logger for WASM builds.
// This is used by go-tdx-guest for conditional logging.
func V(level Level) Verbose {
	// For WASM builds, disable verbose logging
	return Verbose{
		enabled: false,
		logger:  nil,
	}
}

// Warning logs a warning message using the default logger.
func Warning(args ...interface{}) {
	fmt.Printf("WARNING: %s\n", fmt.Sprint(args...))
}

// Warningf logs a formatted warning message using the default logger.
func Warningf(format string, args ...interface{}) {
	fmt.Printf("WARNING: "+format, args...)
}

// Info logs an info message using the default logger.
func Info(args ...interface{}) {
	fmt.Println(args...)
}

// Infof logs a formatted info message using the default logger.
func Infof(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}
