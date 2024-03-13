package check

import "fmt"

type validateError struct {
	msg       string
	permanent bool
}

func newValidateRuntimeError(format string, a ...interface{}) *validateError {
	return &validateError{
		msg: fmt.Sprintf(format, a...),
	}
}

func newValidateWarning(format string, a ...interface{}) *validateError {
	return &validateError{
		msg: fmt.Sprintf(format, a...),
	}
}

func newValidateCritical(format string, a ...interface{}) *validateError {
	return &validateError{
		msg: fmt.Sprintf("[CRITICAL] " + format, a...),
	}
}

func (err *validateError) AsPermanent() *validateError {
	err.permanent = true
	return err
}
