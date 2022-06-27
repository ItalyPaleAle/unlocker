package server

import (
	"time"
)

type requestOperation uint8

const (
	OperationWrap requestOperation = iota
	OperationUnwrap
)

type requestStatus uint8

const (
	StatusPending requestStatus = iota
	StatusComplete
	StatusCanceled
)

type requestState struct {
	Status     requestStatus
	Operation  requestOperation
	Processing bool
	Input      []byte
	Output     []byte
	Vault      string
	KeyId      string
	KeyVersion string
	Requestor  string
	Date       time.Time
	Expiry     time.Time
	Token      *AccessToken
}

// Expired returns true if the request has expired
func (rs requestState) Expired() bool {
	return rs.Expiry.Before(time.Now())
}
