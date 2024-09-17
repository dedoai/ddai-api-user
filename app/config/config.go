package config

import (
	"os"

	"github.com/Nerzal/gocloak/v12"
	"github.com/dedoai/ddai-api-user/models"
)

func LoadConfig() *models.Options {
	return &models.Options{
		Client:                *gocloak.NewClient(os.Getenv("KEYCLOAK_URL")),
		Realm:                 os.Getenv("KEYCLOAK_REALM"),
		ClientID:              os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret:          os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		TwilioAccountSeed:     os.Getenv("TWILIO_ACCOUNT_SEED"),
		TwilioAccountToken:    os.Getenv("TWILIO_ACCOUNT_TOKEN"),
		TwilioSmsSenderNumber: os.Getenv("TWILIO_SMS_SENDER_NUMBER"),
	}
}
