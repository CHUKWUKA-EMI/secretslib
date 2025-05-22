package utils

import "log"

func NewLogger() *log.Logger {
	return log.New(log.Writer(), "secretslib: ", log.LstdFlags|log.Lshortfile)
}
