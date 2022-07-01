package server

import (
	"time"
)

type requestOperation uint8

const (
	OperationWrap requestOperation = iota
	OperationUnwrap
)

// String representation
func (r requestOperation) String() string {
	switch r {
	case OperationWrap:
		return "wrap"
	case OperationUnwrap:
		return "unwrap"
	default:
		return ""
	}
}

type requestStatus uint8

const (
	// Request is pending
	StatusPending requestStatus = iota
	// Request is completed and was successful
	StatusComplete
	// Request is completed and was canceled
	StatusCanceled
	// Request has been removed
	// This is only used in the public response
	StatusRemoved
)

// String representation
func (r requestStatus) String() string {
	switch r {
	case StatusPending:
		return "pending"
	case StatusComplete:
		return "complete"
	case StatusCanceled:
		return "canceled"
	case StatusRemoved:
		return "removed"
	default:
		return ""
	}
}

// requestState contains a state request
// All fields have tag `json:"-"` to prevent accidental exposure
type requestState struct {
	Status     requestStatus    `json:"-"`
	Operation  requestOperation `json:"-"`
	Processing bool             `json:"-"`
	Input      []byte           `json:"-"`
	Output     []byte           `json:"-"`
	Vault      string           `json:"-"`
	KeyId      string           `json:"-"`
	KeyVersion string           `json:"-"`
	Requestor  string           `json:"-"`
	Date       time.Time        `json:"-"`
	Expiry     time.Time        `json:"-"`
}

// Expired returns true if the request has expired
func (rs requestState) Expired() bool {
	return rs.Expiry.Before(time.Now())
}

// Public returns the public version of the object
func (rs requestState) Public(stateId string) requestStatePublic {
	return requestStatePublic{
		State:     stateId,
		Status:    rs.Status.String(),
		Operation: rs.Operation.String(),
		KeyId:     rs.KeyId,
		VaultName: rs.Vault,
		Requestor: rs.Requestor,
		Date:      rs.Date.Unix(),
		Expiry:    rs.Expiry.Unix(),
	}
}

// requestStatePublic is a version of requestState that can be sent to clients
type requestStatePublic struct {
	State     string `json:"state"`
	Status    string `json:"status"`
	Operation string `json:"operation,omitempty"`
	KeyId     string `json:"keyId,omitempty"`
	VaultName string `json:"vaultName,omitempty"`
	Requestor string `json:"requestor,omitempty"`
	Date      int64  `json:"date,omitempty"`
	Expiry    int64  `json:"expiry,omitempty"`
}
