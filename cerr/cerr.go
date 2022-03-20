package cerr

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ErrResponse struct {
	Error string `json:"error"`
}

func Wrap(err error, msg string) error {
	return errors.New(msg + " - " + err.Error())
}

func WrapMC(err error, msg string, code codes.Code) error {
	err = errors.New(msg + " - " + err.Error())
	return status.Error(code, err.Error())
}

func New(msg string) error {
	return errors.New(msg)
}

func NewC(msg string, code codes.Code) error {
	return status.Error(code, msg)
}
