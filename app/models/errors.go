package models

import "fmt"

const (
	ErrInternalServer   = "INTERNAL_SERVER_ERROR"
	ErrInvalidRequest   = "INVALID_REQUEST"
	ErrEndpointNotFound = "ENDPOINT_NOT_FOUND"

	ErrInvalidCredentials    = "INVALID_CREDENTIALS"
	ErrEmailOTPNotValidated  = "EMAIL_OTP_NOT_VALIDATED"
	ErrSMSOTPNotValidated    = "SMS_OTP_NOT_VALIDATED"
	ErrOTPValidationError    = "OTP_VALIDATION_ERROR"
	ErrUserNotFound          = "USER_NOT_FOUND"
	ErrUserAttributesMissing = "USER_ATTRIBUTES_MISSING"
	ErrUnauthorized          = "UNAUTHORIZED"

	ErrInvalidRequestBody = "INVALID_REQUEST_BODY"
	ErrMissingParameter   = "MISSING_PARAMETER"

	ErrKYCProcessError      = "KYC_PROCESS_ERROR"
	ErrUnsupportedEventType = "UNSUPPORTED_EVENT_TYPE"
)

type CustomError struct {
	ErrorCode   string
	Description string
}

func (e *CustomError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.Description)
}

func NewCustomError(errorCode, description string) error {
	return &CustomError{
		ErrorCode:   errorCode,
		Description: description,
	}
}
