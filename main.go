package main

import (
	"fmt"
	"log"
)

func main() {
	testdoct := `{
    "PolicyName": "root",	
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "IamListAccess",
                "Effect": "Allow",
                "Action": [
                    "iam:ListRoles",
                    "iam:ListUsers"
                ],
                "Resource": "*"
            }
        ]
    }
}`
	ap := NewPolicy()
	err, b := ap.verifyIAM(testdoct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(*ap.PolicyName)
	fmt.Println(b)
}
