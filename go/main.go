//go:build wasm
// +build wasm

package main

// Global state variables that persist between function calls.
var (
	// Counter that increments with each call.
	callCounter int32 = 0

	// Accumulator that maintains a running sum.
	accumulator int32 = 0

	// Store the last operation result.
	lastResult int32 = 0
)

// helloWorld prints "Hello, world!" to the console.
// The //export directive makes this available as exports.helloWorld.
//
//export helloWorld
func helloWorld() {
	println("Hello, world!")
}

// add demonstrates exporting a function with parameters.
//
//export add
func add(a, b int32) int32 {
	result := a + b
	lastResult = result
	return result
}

// multiply demonstrates another exported function.
//
//export multiply
func multiply(a, b int32) int32 {
	result := a * b
	lastResult = result
	return result
}

// incrementCounter increments and returns a global counter.
// This demonstrates that state persists between calls.
//
//export incrementCounter
func incrementCounter() int32 {
	callCounter++
	return callCounter
}

// getCounter returns the current counter value without incrementing.
//
//export getCounter
func getCounter() int32 {
	return callCounter
}

// resetCounter resets the counter to zero.
//
//export resetCounter
func resetCounter() {
	callCounter = 0
}

// addToAccumulator adds a value to the accumulator and returns the new total.
//
//export addToAccumulator
func addToAccumulator(value int32) int32 {
	accumulator += value
	return accumulator
}

// getAccumulator returns the current accumulator value.
//
//export getAccumulator
func getAccumulator() int32 {
	return accumulator
}

// resetAccumulator resets the accumulator to zero.
//
//export resetAccumulator
func resetAccumulator() {
	accumulator = 0
}

// getLastResult returns the result of the last add or multiply operation.
//
//export getLastResult
func getLastResult() int32 {
	return lastResult
}

func main() {
	// Empty main function - all our exports are handled via //export directive.
}
