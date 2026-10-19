package protocol

import (
	"strconv"

	"github.com/go-directory/common"
)

var itoa = strconv.Itoa

type commonErr = common.Error

func protocolError(msg ...string) (err commonErr) {
	err = common.LDAPResultProtocolError.New(msg...)
	err.SetHeader("protocol:")
	return
}

func constraintViolation(msg ...string) (err commonErr) {
	err = common.LDAPResultConstraintViolation.New(msg...)
	err.SetHeader("constraint violation:")
	return
}

var (
	errTextMaxIntOutOfBounds = `out of bounds; must be 0 .. 2147483647`
)
