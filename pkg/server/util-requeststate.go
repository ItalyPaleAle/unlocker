package server

import (
	"time"
)

type requestOperation uint8

const (
	OperationEncrypt requestOperation = iota
	OperationDecrypt
	OperationSign
	OperationVerify
	OperationWrap
	OperationUnwrap
)

// String representation
func (r requestOperation) String() string {
	switch r {
	case OperationEncrypt:
		return "encrypt"
	case OperationDecrypt:
		return "decrypt"
	case OperationSign:
		return "sign"
	case OperationVerify:
		return "verify"
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
	Operation  requestOperation `json:"-"`
	Status     requestStatus    `json:"-"`
	Processing bool             `json:"-"`

	Vault      string `json:"-"`
	KeyId      string `json:"-"`
	KeyVersion string `json:"-"`

	Algorithm      string `json:"-"`
	Input          []byte `json:"-"`
	Output         []byte `json:"-"`
	AdditionalData []byte `json:"-"`

	Requestor string    `json:"-"`
	Date      time.Time `json:"-"`
	Expiry    time.Time `json:"-"`
	Note      string    `json:"-"`
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
		Note:      rs.Note,
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
	Note      string `json:"note,omitempty"`
}
