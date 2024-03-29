package main

import (
	"testing"
)

func TestVerifyIAM(t *testing.T) {
	var tests = []struct {
		name      string
		jsonInput string
		want      bool
	}{{"* should return false",
		`{
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
}`,
		false},
		{"** should return true",
			`{
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
                "Resource": "**"
            }
        ]
    }
}`,
			true},
		{"empty string in Resource field should return true",
			`{
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
                "Resource": ""
            }
        ]
    }
}`,
			true}}

	var awsPolicy AWSPolicy
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, ans := awsPolicy.verifyIAM(tt.jsonInput)
			if err != nil {
				t.Fatal(err)
			}

			if ans != tt.want {
				t.Errorf("got %t, want %t", ans, tt.want)
			}
		})
	}
}

func TestVerifyIAM_ErrorOnInvalidInput(t *testing.T) {
	var tests = []struct {
		name        string
		invalidJson string
	}{
		{"invalid json should throw error", `{
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
                Resource: "*"
            }
        ]	
    }
}`},
		{"missing PolicyName field should throw error",
			`{
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
}`}, {"missing PolicyDocument field should throw error",
			`{
    "PolicyName": "root"
}`},
	}

	var awsPolicy AWSPolicy
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, ans := awsPolicy.verifyIAM(tt.invalidJson)
			if err == nil {
				t.Errorf("got %t, wanted error", ans)
			}

		})
	}
}
