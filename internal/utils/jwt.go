package utils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type JWTClaims struct {
	Iat int64 `json:"iat"`
}

// DecodeJWT extracts the payload from a JWT token
func DecodeJWT(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	// Decode Base64 payload (second part of JWT)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}
