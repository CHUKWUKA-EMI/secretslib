package infisical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/chukwuka-emi/secretslib/internal/utils"
)

type authCredentials struct {
	AccessToken string `json:"accessToken"`
	TokenType   string `json:"tokenType"`
	ExpiresIn   int    `json:"expiresIn"`
}

type SecretManager struct {
	baseURL         string
	clientID        string
	clientSecret    string
	authCredentials *authCredentials
	httpClient      *http.Client
	logger          *log.Logger
}

type RetrieveSecretOptions struct {
	SecretKey   string
	Environment string
	ProjectID   string
	Version     int
	SecretPath  string
}

func NewSecretManager(clientID string, clientSecret string, httpClient *http.Client, logger *log.Logger) *SecretManager {
	secretManager := &SecretManager{
		baseURL:      "https://app.infisical.com/api",
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   httpClient,
		logger:       logger,
	}
	if secretManager.httpClient == nil {
		secretManager.httpClient = &http.Client{}
	}

	if secretManager.logger == nil {
		secretManager.logger = log.New(log.Writer(), "SecretManager: ", log.LstdFlags|log.Lshortfile)
	}

	authCredentials, err := secretManager.getAuthToken()
	if err != nil {
		panic(err)
	}

	secretManager.authCredentials = authCredentials
	return secretManager
}

func (s *SecretManager) GetSecret(options interface{}) (string, error) {
	retrieveOptions, ok := options.(RetrieveSecretOptions)
	if !ok {
		return "", errors.New("Invalid options type")
	}
	return s.getSecretV3(retrieveOptions)
}

func (s *SecretManager) getSecretV3(options RetrieveSecretOptions) (string, error) {
	httpClient := s.httpClient

	url := fmt.Sprintf("%s/v3/secrets/raw/%s", s.baseURL, options.SecretKey)

	if err := s.refreshTokenIfExpired(); err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	if options.SecretPath == "" {
		options.SecretPath = "/"
	}

	queryParams := map[string]string{
		"workspaceId": options.ProjectID,
		"environment": options.Environment,
		"secretPath":  options.SecretPath,
	}

	if options.Version != 0 {
		queryParams["version"] = fmt.Sprintf("%d", options.Version)
	}

	q := req.URL.Query()
	for key, value := range queryParams {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", s.authCredentials.TokenType, s.authCredentials.AccessToken))
	response, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}

	if response.StatusCode == http.StatusNotFound {
		return "", utils.ErrSecretNotFound
	}

	if response.StatusCode != http.StatusOK {

		if response.StatusCode == http.StatusNotFound {
			return "", utils.ErrSecretNotFound
		}

		return "", utils.ErrSomethingWentWrong
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

	authURL := fmt.Sprintf("%s/v1/auth/universal-auth/login", s.baseURL)
	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(payloadBytes))
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
