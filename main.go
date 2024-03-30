package main

import (
	"fmt"
	"log"
)

func main() {
	testdoct := `{
    "PolicyName": "root"
}`
	ap := NewPolicy()
	err, b := ap.verifyIAM(testdoct)
	if err != nil {
		fmt.Println("Dziala tutaj ")
		log.Fatal(err)
	}
	fmt.Println(*ap.PolicyName)
	fmt.Println(b)
}
