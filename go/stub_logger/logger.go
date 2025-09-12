// Package logger provides a minimal stub for WASM builds.
// The real github.com/google/logger doesn't work in WASM environments.
package logger

import (
	"fmt"
	"io"
	"os"
)

// Logger is a minimal stub implementation.
type Logger struct{}

// VerboseLogger is a simple interface for conditional logging.
type VerboseLogger struct{}

// Info does nothing in verbose logger.
func (vl *VerboseLogger) Info(v ...interface{}) {}

// Infof does nothing in verbose logger.
func (vl *VerboseLogger) Infof(format string, v ...interface{}) {}

// Init returns an empty logger.
func Init(name string, verbose, systemLog bool, logFile io.Writer) *Logger {
	return &Logger{}
}

// Close is a no-op.
func (*Logger) Close() {}

// Info prints to stdout.
func (*Logger) Info(v ...interface{}) {
	fmt.Println(v...)
}

// Infof prints formatted to stdout.
func (*Logger) Infof(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

// Warning prints with WARNING prefix.
func (*Logger) Warning(v ...interface{}) {
	fmt.Println("WARNING:", fmt.Sprint(v...))
}

// Warningf prints formatted with WARNING prefix.
func (*Logger) Warningf(format string, v ...interface{}) {
	fmt.Printf("WARNING: "+format+"\n", v...)
}

// Error prints with ERROR prefix.
func (*Logger) Error(v ...interface{}) {
	fmt.Println("ERROR:", fmt.Sprint(v...))
}

// Errorf prints formatted with ERROR prefix.
func (*Logger) Errorf(format string, v ...interface{}) {
	fmt.Printf("ERROR: "+format+"\n", v...)
}

// Fatal prints with FATAL prefix and exits.
func (*Logger) Fatal(v ...interface{}) {
	fmt.Println("FATAL:", fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf prints formatted with FATAL prefix and exits.
func (*Logger) Fatalf(format string, v ...interface{}) {
	fmt.Printf("FATAL: "+format+"\n", v...)
	os.Exit(1)
}

// V returns a no-op VerboseLogger.
func (*Logger) V(level int) *VerboseLogger {
	return &VerboseLogger{}
}

// SetFlags is a no-op.
func SetFlags(flag int) {}

// Package-level functions for compatibility.

// Info prints to stdout.
func Info(v ...interface{}) {
	fmt.Println(v...)
}

// Infof prints formatted to stdout.
func Infof(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

// Warning prints with WARNING prefix.
func Warning(v ...interface{}) {
	fmt.Println("WARNING:", fmt.Sprint(v...))
}

// Warningf prints formatted with WARNING prefix.
func Warningf(format string, v ...interface{}) {
	fmt.Printf("WARNING: "+format+"\n", v...)
}

// Error prints with ERROR prefix.
func Error(v ...interface{}) {
	fmt.Println("ERROR:", fmt.Sprint(v...))
}

// Errorf prints formatted with ERROR prefix.
func Errorf(format string, v ...interface{}) {
	fmt.Printf("ERROR: "+format+"\n", v...)
}

// Fatal prints with FATAL prefix and exits.
func Fatal(v ...interface{}) {
	fmt.Println("FATAL:", fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf prints formatted with FATAL prefix and exits.
func Fatalf(format string, v ...interface{}) {
	fmt.Printf("FATAL: "+format+"\n", v...)
	os.Exit(1)
}

// V returns a no-op VerboseLogger.
func V(level int) *VerboseLogger {
	return &VerboseLogger{}
}
