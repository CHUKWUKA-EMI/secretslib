package utils

import (
	"net/http"
	"time"
)

var HTTPClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	},
}
