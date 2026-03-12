package tls

import "errors"

func errorsAsType[E error](err error) (pe E, ok bool) {
	ok = errors.As(err, &pe)
	return
}
