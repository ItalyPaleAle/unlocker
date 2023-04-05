package server

import (
	"encoding/json"
)

// ErrorResponse is used to send JSON responses with an error
type ErrorResponse string

// MarshalJSON implements a JSON marshaller that returns an object with the error key
func (e ErrorResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Error string `json:"error"`
	}{
		Error: string(e),
	})
}

// InternalServerError is an ErrorResponse for Internal Server Error messages
const InternalServerError ErrorResponse = "An internal error occurred"
