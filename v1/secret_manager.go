package secretmanager

import (
	"log"
	"net/http"

	"github.com/chukwuka-emi/secretslib/internal/secret_manager/infisical"
	"github.com/chukwuka-emi/secretslib/internal/utils"
)

type Provider string

const (
	Vault     Provider = "vault"
	Infisical Provider = "infisical"
)

type InfisicalRetrieveSecretOptions = infisical.RetrieveSecretOptions

// SecretManager is an interface for managing secrets
type SecretManager interface {
	GetSecret(options interface{}) (string, error)
}

type Options struct {
	Provider     Provider
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	Logger       *log.Logger
}

// New creates a new SecretManager instance based on the provided options
func New(options Options) SecretManager {
	if options.Provider == "" {
		panic("secret manager provider is required")
	}
	if options.ClientID == "" {
		panic("client ID is required")
	}
	if options.ClientSecret == "" {
		panic("client secret is required")
	}

	// Set default HTTP client and logger if not provided
	if options.HTTPClient == nil {
		options.HTTPClient = utils.HTTPClient
	}
	if options.Logger == nil {
		options.Logger = utils.NewLogger()
	}

	switch options.Provider {
	case Infisical:
		return infisical.NewSecretManager(options.ClientID, options.ClientSecret, options.HTTPClient, options.Logger)
	case Vault:
		panic("vault secret manager not implemented yet")
	default:
		panic("unsupported secret manager provider")
	}
}
