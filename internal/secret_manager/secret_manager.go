package secretmanager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chukwuka-emi/secretslib/internal/utils"
)

var (
	ErrSecretNotFound     = errors.New("secret not found")
	ErrFailedToGetSecret  = errors.New("failed to getsecret")
	ErrSomethingWentWrong = errors.New("something went wrong")
)

type authCredentials struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int    `json:"expiresIn"`
}

type SecretManager struct {
	authURL         string
	secretBaseURL   string
	secretPath      string
	clientID        string
	clientSecret    string
	authCredentials *authCredentials
	httpClient      *http.Client
	logger          *log.Logger
}

func NewInfisicalSecretManager(authURL string, secretPath string, clientID string, clientSecret string, httpClient *http.Client, logger *log.Logger) *SecretManager {
	secretManager := &SecretManager{
		authURL:       authURL,
		secretBaseURL: "https://app.infisical.com/api/v3",
		secretPath:    secretPath,
		clientID:      clientID,
		clientSecret:  clientSecret,
		httpClient:    httpClient,
		logger:        logger,
	}

	if secretManager.httpClient == nil {
		secretManager.httpClient = &http.Client{}
	}

	if secretManager.logger == nil {
		secretManager.logger = log.New(os.Stdout, "SecretManager: ", log.LstdFlags)
	}

	authCredentials, err := secretManager.getAuthToken()
	if err != nil {
		panic(err)
	}
	secretManager.authCredentials = authCredentials
	return secretManager
}

func (s *SecretManager) GetSecret(secretID string, version *int) (string, error) {
	httpClient := s.httpClient

	url := strings.ReplaceAll(s.secretPath, "%SECRET%", secretID)

	if version != nil {
		url = fmt.Sprintf("%s&version=%d", url, *version)
	}

	if err := s.refreshTokenIfExpired(); err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s", s.authCredentials.TokenType, s.authCredentials.AccessToken))
	response, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	if response.StatusCode == http.StatusNotFound {
		return "", ErrSecretNotFound
	}

	if response.StatusCode != http.StatusOK {

		if response.StatusCode == http.StatusNotFound {
			return "", ErrSecretNotFound
		}

		return "", ErrSomethingWentWrong
	}

	defer response.Body.Close()

	responseBody := map[string]interface{}{
		"secret": map[string]interface{}{},
	}

	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		s.logger.Println("Error decoding response body")
		return "", err
	}

	secretValue := responseBody["secret"].(map[string]interface{})["secretValue"].(string)

	return secretValue, nil
}

func (s *SecretManager) getAuthToken() (*authCredentials, error) {
	s.logger.Println("Getting auth token")

	httpClient := s.httpClient

	payload := map[string]string{
		"clientId":     s.clientID,
		"clientSecret": s.clientSecret,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", s.authURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, errors.New("Failed to get auth token")
	}

	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	responsePayload := authCredentials{}

	err = json.Unmarshal(responseBody, &responsePayload)
	if err != nil {
		return nil, err
	}

	return &responsePayload, nil
}

func (s *SecretManager) refreshTokenIfExpired() error {
	s.logger.Println("Checking if token is expired")
	claims, err := utils.DecodeJWT(s.authCredentials.AccessToken)
	if err != nil {
		return err
	}

	expirationTime := time.Unix(claims.Iat+int64(s.authCredentials.ExpiresIn), 0)
	if time.Now().Unix() > expirationTime.Unix() {
		authCredentials, err := s.getAuthToken()
		if err != nil {
			return err
		}
		s.logger.Println("Token refreshed")
		s.authCredentials = authCredentials
	}
	return nil
}
