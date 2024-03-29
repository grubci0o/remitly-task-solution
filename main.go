package main

import (
	"fmt"
	"log"
)

func main() {
	testdoct := `{
    "PolicyName": "root"
}`
	ap := AWSPolicy{}
	err, b := ap.verifyIAM(testdoct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(*ap.PolicyName)
	fmt.Println(b)
}
