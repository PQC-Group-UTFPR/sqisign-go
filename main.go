package main

import (
    "fmt"
    "log"

    "sqisign-go/sqisign" 
)

func main() {
    // Generate a keypair
    pk, sk, err := sqisign.Keypair()
    if err != nil {
        log.Fatalf("Error generating keypair: %v", err)
    }

    fmt.Printf("Public Key: %x\n", pk)
    fmt.Printf("Secret Key: %x\n", sk)
}
