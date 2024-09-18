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
		ClientID:              os.Getenv("KEYCLOAK_ADMIN_USERNAME"),
		ClientSecret:          os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
		TwilioAccountSeed:     os.Getenv("TWILIO_ACCOUNT_SEED"),
		TwilioAccountToken:    os.Getenv("TWILIO_ACCOUNT_TOKEN"),
		TwilioSmsSenderNumber: os.Getenv("TWILIO_SMS_SENDER_NUMBER"),
		SendgridAPIKey:        os.Getenv("SENDGRID_API_KEY"),
	}
}
