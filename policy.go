package main

import (
	"encoding/json"
	"errors"
)

type AWSPolicy struct {
	PolicyName     *string         `json:"PolicyName"`
	PolicyDocument *PolicyDocument `json:"PolicyDocument"`
}

type PolicyDocument struct {
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Resource *string `json:"Resource"`
}

func NewPolicy() AWSPolicy {
	return AWSPolicy{}
}

func (policy *AWSPolicy) parseJson(jsonString string) error {
	err := json.Unmarshal([]byte(jsonString), &policy)
	if err != nil {
		return err
	}
	return nil
}

func (policy *AWSPolicy) verifyIAM(jsonString string) (error, bool) {
	err := policy.parseJson(jsonString)
	if err != nil {
		return err, false
	}

	if policy.PolicyName == nil || policy.PolicyDocument == nil {
		return errors.New("missing required field"), false
	}

	for _, stmt := range policy.PolicyDocument.Statement {
		if stmt.Resource != nil {
			if *stmt.Resource == "*" {
				return nil, false
			}
		}
	}
	return nil, true
}
