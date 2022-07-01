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
	StatusPending requestStatus = iota
	StatusComplete
	StatusCanceled
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
	default:
		return ""
	}
}

// requestState contains a state request
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
	Operation string `json:"operation"`
	KeyId     string `json:"keyId"`
	VaultName string `json:"vaultName"`
	Requestor string `json:"requestor"`
	Date      int64  `json:"date"`
	Expiry    int64  `json:"expiry"`
}
