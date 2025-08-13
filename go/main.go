//go:build wasm
// +build wasm

package main

import (
	"fmt"
	"syscall/js"
)

// helloWorld is a simple function that prints "Hello, World!" to the console.
func helloWorld(this js.Value, args []js.Value) any {
	fmt.Println("Hello, World!")
	return nil
}

func main() {
	// Register the helloWorld function as a global JavaScript function.
	js.Global().Set("helloWorld", js.FuncOf(helloWorld))

	// Keep the Go program running.
	// In WASM, the main function needs to keep running to maintain the registered functions.
	select {}
}
