// Package logger provides a stub implementation for WASM builds.
// The real github.com/google/logger doesn't work in WASM environments.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
)

// Logger is a stub implementation.
type Logger struct {
	verbose bool
}

// VerboseLogger is returned by V() to allow conditional logging.
type VerboseLogger interface {
	Info(v ...interface{})
	Infof(format string, v ...interface{})
}

// verboseLogger implements VerboseLogger.
type verboseLogger struct {
	enabled bool
	logger  *Logger
}

// Info logs informational messages if verbose is enabled.
func (vl *verboseLogger) Info(v ...interface{}) {
	if vl.enabled && vl.logger != nil {
		vl.logger.Info(v...)
	}
}

// Infof logs formatted informational messages if verbose is enabled.
func (vl *verboseLogger) Infof(format string, v ...interface{}) {
	if vl.enabled && vl.logger != nil {
		vl.logger.Infof(format, v...)
	}
}

// Init initializes the logger (no-op in stub).
func Init(name string, verbose, systemLog bool, logFile io.Writer) *Logger {
	return &Logger{verbose: verbose}
}

// Close closes the logger (no-op in stub).
func (l *Logger) Close() {}

// Info logs informational messages.
func (l *Logger) Info(v ...interface{}) {
	if l != nil && l.verbose {
		log.Print(v...)
	}
}

// Infof logs formatted informational messages.
func (l *Logger) Infof(format string, v ...interface{}) {
	if l != nil && l.verbose {
		log.Printf(format, v...)
	}
}

// Warning logs warning messages.
func (l *Logger) Warning(v ...interface{}) {
	log.Print(v...)
}

// Warningf logs formatted warning messages.
func (l *Logger) Warningf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Error logs error messages.
func (l *Logger) Error(v ...interface{}) {
	log.Print(v...)
}

// Errorf logs formatted error messages.
func (l *Logger) Errorf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// Fatal logs fatal messages and exits.
func (l *Logger) Fatal(v ...interface{}) {
	log.Print(v...)
	os.Exit(1)
}

// Fatalf logs formatted fatal messages and exits.
func (l *Logger) Fatalf(format string, v ...interface{}) {
	log.Printf(format, v...)
	os.Exit(1)
}

// V returns a VerboseLogger for conditional logging.
func (l *Logger) V(level int) VerboseLogger {
	if l != nil && l.verbose {
		return &verboseLogger{enabled: true, logger: l}
	}
	return &verboseLogger{enabled: false, logger: l}
}

// SetFlags sets log flags (no-op in stub).
func SetFlags(flag int) {}

// Default logger functions.
var defaultLogger = &Logger{verbose: true}

// Info logs informational messages.
func Info(v ...interface{}) {
	fmt.Println(v...)
}

// Infof logs formatted informational messages.
func Infof(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

// Warning logs warning messages.
func Warning(v ...interface{}) {
	fmt.Println("WARNING:", fmt.Sprint(v...))
}

// Warningf logs formatted warning messages.
func Warningf(format string, v ...interface{}) {
	fmt.Printf("WARNING: "+format+"\n", v...)
}

// Error logs error messages.
func Error(v ...interface{}) {
	fmt.Println("ERROR:", fmt.Sprint(v...))
}

// Errorf logs formatted error messages.
func Errorf(format string, v ...interface{}) {
	fmt.Printf("ERROR: "+format+"\n", v...)
}

// Fatal logs fatal messages and exits.
func Fatal(v ...interface{}) {
	fmt.Println("FATAL:", fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf logs formatted fatal messages and exits.
func Fatalf(format string, v ...interface{}) {
	fmt.Printf("FATAL: "+format+"\n", v...)
	os.Exit(1)
}

// V returns a VerboseLogger for conditional logging.
func V(level int) VerboseLogger {
	return &verboseLogger{enabled: true, logger: defaultLogger}
}
