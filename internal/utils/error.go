package utils

import "errors"

var (
	ErrSecretNotFound     = errors.New("secret not found")
	ErrFailedToGetSecret  = errors.New("failed to getsecret")
	ErrSomethingWentWrong = errors.New("something went wrong")
)
