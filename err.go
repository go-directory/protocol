package protocol

import (
	"strconv"

	"github.com/go-directory/common"
)

var itoa = strconv.Itoa
var atoi = strconv.Atoi

func protocolError(msg ...string) error {
	m := append([]string{"Protocol error"}, msg...)
	return common.LDAPResultProtocolError.New(m...)
}

func constraintViolation(msg ...string) error {
	m := append([]string{"Constraint violation"}, msg...)
	return common.LDAPResultConstraintViolation.New(m...)
}

var (
	errTextMaxIntOutOfBounds = `out of bounds; must be 0 .. 2147483647`
)
