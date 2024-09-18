package services

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/Nerzal/gocloak/v12"
	"github.com/dedoai/ddai-api-user/models"
	"github.com/dedoai/ddai-api-user/pkg/repository"
	"github.com/pquerna/otp/totp"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
)

type UserService struct {
	repo    repository.UserRepository
	options *models.Options
}

func NewService(repo repository.UserRepository, options *models.Options) *UserService {
	return &UserService{
		repo:    repo,
		options: options,
	}
}

func (s *UserService) GetUserProfile(ctx context.Context, username string) (*gocloak.User, error) {
	return s.repo.GetUserByEmail(ctx, username)
}

func (s *UserService) ResetPassword(ctx context.Context, email, newPassword string) error {
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

func (s *UserService) Login(ctx context.Context, email, password string) (*gocloak.JWT, error) {
	jwt, err := s.options.Client.Login(ctx, s.options.ClientID, s.options.ClientSecret, s.options.Realm, email, password)
	if err != nil {
		return nil, fmt.Errorf("failed to login: %v", err)
	}
	return jwt, nil
}

func (s *UserService) Signup(ctx context.Context, email, phone, password string) (string, string, error) {
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

func (s *UserService) SendOTP(ctx context.Context, email string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to get user by email: %v", err)
	}
	otpToken := generateOTP(6)
	err = s.repo.UpdateUser(ctx, gocloak.User{
		ID:         user.ID,
		Attributes: &map[string][]string{"mail_otp": {otpToken}},
	})
	if err != nil {
		return fmt.Errorf("failed to update user attribute: %v", err)
	}
	err = sendOTPEmail(email, otpToken)
	if err != nil {
		return fmt.Errorf("failed to send OTP email: %v", err)
	}
	return nil
}

func (s *UserService) SendSmsOTP(ctx context.Context, phone, userID string) error {
	otpToken := generateOTP(6)
	err := s.repo.UpdateUser(ctx, gocloak.User{
		ID:         &userID,
		Attributes: &map[string][]string{"sms_otp": {otpToken}},
	})
	if err != nil {
		return fmt.Errorf("failed to update user attribute: %v", err)
	}
	err = sendSmsOTP(phone, otpToken)
	if err != nil {
		return fmt.Errorf("failed to send SMS OTP: %v", err)
	}
	return nil
}

func (s *UserService) VerifySmsOTP(ctx context.Context, phone, otpToken, userID string) (bool, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user by ID: %v", err)
	}
	attributes := *user.Attributes
	if storedOTP, ok := attributes["sms_otp"]; ok && len(storedOTP) > 0 && storedOTP[0] == otpToken {
		err = s.repo.UpdateUser(ctx, gocloak.User{
			ID:         user.ID,
			Attributes: &map[string][]string{"validated_sms_otp": {"true"}},
		})
		if err != nil {
			return false, fmt.Errorf("failed to update user attribute: %v", err)
		}
		return true, nil
	}
	return false, nil
}

func (s *UserService) VerifyOTP(ctx context.Context, email, otpToken string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to get user by email: %v", err)
	}
	attributes := *user.Attributes
	if storedOTP, ok := attributes["mail_otp"]; ok && len(storedOTP) > 0 && storedOTP[0] == otpToken {
		err = s.repo.UpdateUser(ctx, gocloak.User{
			ID:         user.ID,
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

func sendOTPEmail(email, otpToken string) error {
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

	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))

	_, err := client.Send(message)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func sendSmsOTP(phone, otpToken string) error {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: os.Getenv("TWILIO_ACCOUNT_SID"),
		Password: os.Getenv("TWILIO_AUTH_TOKEN"),
	})

	params := &twilioApi.CreateMessageParams{}
	params.SetTo(phone)
	params.SetFrom(os.Getenv("TWILIO_PHONE_NUMBER"))
	params.SetBody(fmt.Sprintf("Your OTP is: %s", otpToken))
	_, err := client.Api.CreateMessage(params)
	return err
}
