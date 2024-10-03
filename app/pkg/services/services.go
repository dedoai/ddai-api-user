package services

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/Nerzal/gocloak/v12"
	"github.com/dedoai/ddai-api-user/models"
	"github.com/dedoai/ddai-api-user/pkg/repository"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
)

type UserService interface {
	GetUserProfile(ctx context.Context, username string) (*gocloak.User, error)
	ResetPassword(ctx context.Context, email, newPassword string) error
	Login(ctx context.Context, email, password string) (*gocloak.JWT, error)
	Signup(ctx context.Context, email, password string) (string, error)
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
	user, err := s.repo.GetUserByEmail(ctx, username)
	if err != nil {
		log.Println("Error in GetUserProfile:", err)
		return nil, models.NewCustomError(models.ErrUserNotFound, "User not found")
	}
	return user, nil
}

func (s *userService) ResetPassword(ctx context.Context, email, newPassword string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Println("Error in ResetPassword - GetUserByEmail:", err)
		return models.NewCustomError(models.ErrUserNotFound, "User not found")
	}
	err = s.repo.SetPassword(ctx, *user.ID, newPassword, false)
	if err != nil {
		log.Println("Error in ResetPassword - SetPassword:", err)
		return models.NewCustomError(models.ErrInternalServer, "Failed to reset password")
	}
	return nil
}

func (s *userService) Login(ctx context.Context, email, password string) (*gocloak.JWT, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Println("Error in Login - GetUserByEmail:", err)
		return nil, models.NewCustomError(models.ErrInvalidCredentials, "Invalid credentials")
	}

	if user.Attributes != nil {
		if vals, ok := (*user.Attributes)["validated_mail_otp"]; ok {
			if len(vals) == 0 || vals[0] != "true" {
				return nil, models.NewCustomError(models.ErrEmailOTPNotValidated, "Email OTP not validated")
			}
		} else {
			return nil, models.NewCustomError(models.ErrEmailOTPNotValidated, "Email OTP not validated")
		}

		if vals, ok := (*user.Attributes)["validated_sms_otp"]; ok {
			if len(vals) == 0 || vals[0] != "true" {
				return nil, models.NewCustomError(models.ErrSMSOTPNotValidated, "SMS OTP not validated")
			}
		} else {
			return nil, models.NewCustomError(models.ErrSMSOTPNotValidated, "SMS OTP not validated")
		}
	} else {
		return nil, models.NewCustomError(models.ErrUserAttributesMissing, "User attributes are missing")
	}

	jwt, err := s.options.Client.Login(ctx, "web-app", s.options.ClientSecret, s.options.Realm, email, password)
	if err != nil {
		log.Println("Error in Login - Keycloak Login:", err)
		return nil, models.NewCustomError(models.ErrInvalidCredentials, "Invalid credentials")
	}
	return jwt, nil
}

func (s *userService) Signup(ctx context.Context, email, password string) (string, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Println("Error in Signup - GetUserByEmail:", err)
		return "", models.NewCustomError(models.ErrInternalServer, "Failed to create user")
	}

	if user.Attributes != nil {
		if vals, ok := (*user.Attributes)["validated_mail_otp"]; ok {
			if len(vals) == 0 || vals[0] != "true" {
				return "", models.NewCustomError(models.ErrEmailOTPNotValidated, "Email OTP not validated")
			}
		} else {
			return "", models.NewCustomError(models.ErrEmailOTPNotValidated, "Email OTP validation not found")
		}

		if vals, ok := (*user.Attributes)["validated_sms_otp"]; ok {
			if len(vals) == 0 || vals[0] != "true" {
				return "", models.NewCustomError(models.ErrSMSOTPNotValidated, "SMS OTP not validated")
			}
		} else {
			return "", models.NewCustomError(models.ErrSMSOTPNotValidated, "SMS OTP validation not found")
		}
	} else {
		return "", models.NewCustomError(models.ErrUserAttributesMissing, "User attributes are missing")
	}

	err = s.repo.SetPassword(ctx, *user.ID, password, false)
	if err != nil {
		log.Println("Error in Signup - SetPassword:", err)
		return "", models.NewCustomError(models.ErrInternalServer, "Failed to set password")
	}
	err = s.repo.UpdateUser(ctx, s.options.Realm, gocloak.User{
		ID:            user.ID,
		Email:         &email,
		EmailVerified: gocloak.BoolP(true),
		Enabled:       gocloak.BoolP(true),
	})
	if err != nil {
		log.Println("Error in Signup - UpdateUser:", err)
		return "", models.NewCustomError(models.ErrInternalServer, "Failed to update user")
	}
	return *user.ID, nil
}

func (s *userService) SendOTP(ctx context.Context, email string) (string, string, error) {
	otpToken := generateOTP(6)

	users, _ := s.repo.GetUsers(ctx, s.options.Realm, gocloak.GetUsersParams{Email: gocloak.StringP(email)})
	// if err != nil {
	// 	log.Println("Error in SendOTP - GetUsers:", err)
	// 	return "", "", models.NewCustomError(models.ErrInternalServer, "Failed to get user by email")
	// }

	var userID string
	if len(users) == 0 {
		user := gocloak.User{
			Email:   gocloak.StringP(email),
			Enabled: gocloak.BoolP(true),
			Attributes: &map[string][]string{
				"draft": {"true"},
			},
		}
		userID, err = s.repo.CreateUser(ctx, s.options.Realm, user)
		if err != nil {
			log.Println("Error in SendOTP - CreateUser:", err)
			return "", "", models.NewCustomError(models.ErrInternalServer, "Failed to create user")
		}
	} else {
		userID = *users[0].ID
	}

	userData, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		log.Println("Error in SendOTP - GetUserByID:", err)
		return "", "", models.NewCustomError(models.ErrInternalServer, "Failed to get user by ID")
	}
	mergedAttributes := mergeAttributes(userData.Attributes, &map[string][]string{
		"mail_otp":           {otpToken},
		"validated_mail_otp": {"false"},
	})
	err = s.repo.UpdateUser(ctx, s.options.Realm, gocloak.User{
		ID:         &userID,
		Email:      &email,
		Attributes: &mergedAttributes,
	})
	if err != nil {
		log.Println("Error in SendOTP - UpdateUser:", err)
		return "", "", models.NewCustomError(models.ErrInternalServer, "Failed to update user")
	}

	err = sendOTPEmail(email, otpToken, s.options.SendgridAPIKey)
	if err != nil {
		log.Println("Error in SendOTP - sendOTPEmail:", err)
		return "", "", models.NewCustomError(models.ErrInternalServer, "Failed to send OTP email")
	}

	return otpToken, userID, nil
}

func (s *userService) SendSmsOTP(ctx context.Context, phone, userID string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		log.Println("Error in SendSmsOTP - GetUserByID:", err)
		return models.NewCustomError(models.ErrInternalServer, "Failed to get user by ID")
	}
	otpToken := generateOTP(6)
	mergedAttributes := mergeAttributes(user.Attributes, &map[string][]string{
		"sms_otp":           {otpToken},
		"validated_sms_otp": {"false"},
		"phone":             {phone},
	})
	err = s.repo.UpdateUser(ctx, s.options.Realm, gocloak.User{
		ID:         &userID,
		Email:      user.Email,
		Attributes: &mergedAttributes,
	})
	if err != nil {
		log.Println("Error in SendSmsOTP - UpdateUser:", err)
		return models.NewCustomError(models.ErrInternalServer, "Failed to update user")
	}
	err = sendSmsOTP(phone, otpToken, s.options.TwilioAccountSeed, s.options.TwilioAccountToken, s.options.TwilioSmsSenderNumber)
	if err != nil {
		log.Println("Error in SendSmsOTP - sendSmsOTP:", err)
		return models.NewCustomError(models.ErrInternalServer, "Failed to send SMS OTP")
	}
	return nil
}

func (s *userService) VerifySmsOTP(ctx context.Context, phone, otpToken, userID string) (bool, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		log.Println("Error in VerifySmsOTP - GetUserByID:", err)
		return false, models.NewCustomError(models.ErrInternalServer, "Failed to get user by ID")
	}
	if storedOTP, ok := (*user.Attributes)["sms_otp"]; ok && len(storedOTP) > 0 && storedOTP[0] == otpToken {
		mergedAttributes := mergeAttributes(user.Attributes, &map[string][]string{
			"validated_sms_otp": {"true"},
		})
		err = s.repo.UpdateUser(ctx, s.options.Realm, gocloak.User{
			ID:         user.ID,
			Email:      user.Email,
			Attributes: &mergedAttributes,
		})
		if err != nil {
			log.Println("Error in VerifySmsOTP - UpdateUser:", err)
			return false, models.NewCustomError(models.ErrInternalServer, "Failed to update user")
		}
		return true, nil
	}
	return false, nil
}

func (s *userService) VerifyOTP(ctx context.Context, email, otpToken string) error {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		log.Println("Error in VerifyOTP - GetUserByEmail:", err)
		return models.NewCustomError(models.ErrUserNotFound, "User not found")
	}
	if storedOTP, ok := (*user.Attributes)["mail_otp"]; ok && len(storedOTP) > 0 && storedOTP[0] == otpToken {
		mergedAttributes := mergeAttributes(user.Attributes, &map[string][]string{
			"validated_mail_otp": {"true"},
		})
		err = s.repo.UpdateUser(ctx, s.options.Realm, gocloak.User{
			ID:         user.ID,
			Email:      &email,
			Attributes: &mergedAttributes,
		})
		if err != nil {
			log.Println("Error in VerifyOTP - UpdateUser:", err)
			return models.NewCustomError(models.ErrInternalServer, "Failed to update user")
		}
		return nil
	}
	return models.NewCustomError(models.ErrOTPValidationError, "Invalid OTP token")
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

func mergeAttributes(existing, updates *map[string][]string) map[string][]string {
	merged := make(map[string][]string)
	for k, v := range *existing {
		merged[k] = v
	}
	for k, v := range *updates {
		merged[k] = v
	}
	return merged
}
