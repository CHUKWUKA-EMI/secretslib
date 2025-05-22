package secretmanagerv1

import (
	"log"
	"net/http"

	"github.com/chukwuka-emi/secretslib/internal/secret_manager/infisical"
	"github.com/chukwuka-emi/secretslib/internal/utils"
)

type SecretProvider string

const (
	Vault     SecretProvider = "vault"
	Infisical SecretProvider = "infisical"
)

type InfisicalRetrieveSecretOptions = infisical.RetrieveSecretOptions

// SecretManager is an interface for managing secrets
type SecretManager interface {
	GetSecret(options interface{}) (string, error)
}

type SecretManagerOptions struct {
	Provider     SecretProvider
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	Logger       *log.Logger
}

func NewSecretManager(options SecretManagerOptions) SecretManager {
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
