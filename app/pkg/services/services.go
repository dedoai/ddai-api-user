package services

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/Nerzal/gocloak/v12"
	"github.com/dedoai/ddai-api-user/models"
	"github.com/dedoai/ddai-api-user/pkg/repository"
	"github.com/pquerna/otp/totp"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

type UserService interface {
	GetUserProfile(ctx context.Context, username string) (*gocloak.User, error)
	ResetPassword(ctx context.Context, email, newPassword string) error
	Login(ctx context.Context, email, password string) (*gocloak.JWT, error)
	Signup(ctx context.Context, email, phone, password string) (string, string, error)
	SendOTP(ctx context.Context, email string) (string, string, error)
	SendSmsOTP(ctx context.Context, phone, userID string) error
	VerifySmsOTP(ctx context.Context, phone, otpToken, userID string) (bool, error)
	VerifyOTP(ctx context.Context, email, otpToken string) error
}

type userService struct {
	repo    repository.UserRepository
	options *models.Options
}

func NewService(repo repository.UserRepository, options *models.Options) UserService {
	return &userService{
		repo:    repo,
		options: options,
	}
}

func (s *userService) GetUserProfile(ctx context.Context, username string) (*gocloak.User, error) {
	return s.repo.GetUserByEmail(ctx, username)
}

func (s *userService) ResetPassword(ctx context.Context, email, newPassword string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to get user by email: %v", err)
	}
	err = s.repo.SetPassword(ctx, *user.ID, newPassword, false)
	if err != nil {
		return fmt.Errorf("failed to reset password: %v", err)
	}
	return nil
}

func (s *userService) Login(ctx context.Context, email, password string) (*gocloak.JWT, error) {
	jwt, err := s.options.Client.Login(ctx, s.options.ClientID, s.options.ClientSecret, s.options.Realm, email, password)
	if err != nil {
		return nil, fmt.Errorf("failed to login: %v", err)
	}
	return jwt, nil
}

func (s *userService) Signup(ctx context.Context, email, phone, password string) (string, string, error) {
	user := gocloak.User{
		Email:      gocloak.StringP(email),
		Enabled:    gocloak.BoolP(true),
		Attributes: &map[string][]string{"phone": {phone}},
	}
	userID, err := s.repo.CreateUser(ctx, user)
	if err != nil {
		return "", "", fmt.Errorf("failed to create user: %v", err)
	}
	err = s.repo.SetPassword(ctx, userID, password, false)
	if err != nil {
		return "", "", fmt.Errorf("failed to set password: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Your App",
		AccountName: email,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate OTP secret: %v", err)
	}
	err = s.repo.UpdateUser(ctx, gocloak.User{
		ID:         &userID,
		Attributes: &map[string][]string{"otp_secret": {key.Secret()}},
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to update user attribute: %v", err)
	}
	return userID, key.Secret(), nil
}

func (s *userService) SendOTP(ctx context.Context, email string) (string, string, error) {
	otpToken := generateOTP(6)

	users, err := s.repo.GetUsers(ctx, gocloak.GetUsersParams{Email: gocloak.StringP(email)})
	if err != nil {
		return "", "", fmt.Errorf("failed to get user by email: %v", err)
	}

	var userID string
	if len(users) == 0 {
		user := gocloak.User{
			Email:   gocloak.StringP(email),
			Enabled: gocloak.BoolP(true),
			Attributes: &map[string][]string{
				"draft": {"true"},
			},
		}
		userID, err = s.repo.CreateUser(ctx, user)
		if err != nil {
			return "", "", fmt.Errorf("failed to create user: %v", err)
		}
	} else {
		userID = *users[0].ID
	}

	err = s.repo.UpdateUser(ctx, gocloak.User{
		ID:    &userID,
		Email: &email,
		Attributes: &map[string][]string{
			"mail_otp":           {otpToken},
			"validated_mail_otp": {"false"},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to update user attribute: %v", err)
	}

	err = sendOTPEmail(email, otpToken, s.options.SendgridAPIKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to send OTP email: %v", err)
	}

	return otpToken, userID, nil
}

func (s *userService) SendSmsOTP(ctx context.Context, phone, userID string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user by ID: %v", err)
	}
	otpToken := generateOTP(6)
	err = s.repo.UpdateUser(ctx, gocloak.User{
		ID:    &userID,
		Email: user.Email,
		Attributes: &map[string][]string{
			"sms_otp":           {otpToken},
			"validated_sms_otp": {"false"},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update user attribute: %v", err)
	}
	err = sendSmsOTP(phone, otpToken, s.options.TwilioAccountSeed, s.options.TwilioAccountToken, s.options.TwilioSmsSenderNumber)
	if err != nil {
		return fmt.Errorf("failed to send SMS OTP: %v", err)
	}
	return nil
}

func (s *userService) VerifySmsOTP(ctx context.Context, phone, otpToken, userID string) (bool, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user by ID: %v", err)
	}
	attributes := *user.Attributes
	if storedOTP, ok := attributes["sms_otp"]; ok && len(storedOTP) > 0 && storedOTP[0] == otpToken {
		err = s.repo.UpdateUser(ctx, gocloak.User{
			ID:         user.ID,
			Email:      user.Email,
			Attributes: &map[string][]string{"validated_sms_otp": {"true"}},
		})
		if err != nil {
			return false, fmt.Errorf("failed to update user attribute: %v", err)
		}
		return true, nil
	}
	return false, nil
}

func (s *userService) VerifyOTP(ctx context.Context, email, otpToken string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to get user by email: %v", err)
	}
	attributes := *user.Attributes
	if storedOTP, ok := attributes["mail_otp"]; ok && len(storedOTP) > 0 && storedOTP[0] == otpToken {
		err = s.repo.UpdateUser(ctx, gocloak.User{
			ID:         user.ID,
			Email:      &email,
			Attributes: &map[string][]string{"validated_mail_otp": {"true"}},
		})
		if err != nil {
			return fmt.Errorf("failed to update user attribute: %v", err)
		}
		return nil
	}
	return fmt.Errorf("invalid OTP token")
}

func generateOTP(length int) string {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	otp := make([]byte, length)
	for i := 0; i < length; i++ {
		otp[i] = digits[rand.Intn(len(digits))]
	}
	return string(otp)
}

func sendOTPEmail(email, otpToken, sendgridAPIKey string) error {
	from := mail.NewEmail("Dedo OTP token", "web@dedoai.org")
	to := mail.NewEmail("", email)

	templateID := "d-a1088449da3a498d902679a2cee9b49f"

	message := mail.NewV3Mail()
	message.SetFrom(from)
	message.SetTemplateID(templateID)

	p := mail.NewPersonalization()
	p.AddTos(to)
	p.SetDynamicTemplateData("otp_token", otpToken)
	message.AddPersonalizations(p)

	client := sendgrid.NewSendClient(sendgridAPIKey)

	_, err := client.Send(message)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func sendSmsOTP(phone, otpToken, twilioAccountSID, twilioAuthToken, twilioPhoneNumber string) error {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: twilioAccountSID,
		Password: twilioAuthToken,
	})
	params := &openapi.CreateMessageParams{}
	params.SetTo(phone)
	params.SetFrom(twilioPhoneNumber)
	params.SetBody(fmt.Sprintf("Your OTP is: %s", otpToken))
	_, err := client.Api.CreateMessage(params)
	return err
}
