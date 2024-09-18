package models

import "github.com/Nerzal/gocloak/v12"

type Options struct {
	Client                gocloak.GoCloak
	Realm                 string
	ClientID              string
	ClientSecret          string
	TwilioAccountSeed     string
	TwilioAccountToken    string
	TwilioSmsSenderNumber string
	SendgridAPIKey        string
}
