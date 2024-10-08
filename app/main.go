package main

import (
	"context"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/dedoai/ddai-api-user/config"
	"github.com/dedoai/ddai-api-user/models"
	"github.com/dedoai/ddai-api-user/pkg/controller"
	"github.com/dedoai/ddai-api-user/pkg/repository"
	"github.com/dedoai/ddai-api-user/pkg/services"
)

func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	options := config.LoadConfig()
	repo := repository.NewRepository(options.Client, options.Realm, options)
	service := services.NewService(repo, options)
	kycService := services.NewKYCService(repo)
	ctrl := controller.NewController(service, kycService)

	switch request.HTTPMethod {
	case "GET":
		if strings.HasPrefix(request.Path, "/account/") {
			return ctrl.HandleGetUserProfile(request)
		} else if request.Path == "/v1/auth/otp/email" {
			return ctrl.HandleSendOTP(request)
		} else if request.Path == "/v1/auth/otp/sms" {
			return ctrl.HandleSendSmsOTP(request)
		}
	case "POST":
		if request.Path == "/v1/auth/signin" {
			return ctrl.HandleLogin(request)
		} else if request.Path == "/v1/auth/signup" {
			return ctrl.HandleSignup(request)
		} else if request.Path == "/v1/auth/reset-password" {
			return ctrl.HandleResetPassword(request)
		} else if request.Path == "/v1/auth/otp/email" {
			return ctrl.HandleVerifyOTP(request)
		} else if request.Path == "/v1/auth/otp/sms" {
			return ctrl.HandleVerifySmsOTP(request)
		} else if request.Path == "/kyc" {
			return ctrl.HandleSumsubWebhook(request)
		}
	case "OPTIONS":
		return controller.RespondWithJSON(nil, 200, "", "")
	default:
		return controller.RespondWithJSON(nil, 404, models.ErrEndpointNotFound, "Endpoint not found")
	}

	return controller.RespondWithJSON(nil, 404, models.ErrEndpointNotFound, "Endpoint not found")
}

func main() {
	lambda.Start(Handler)
}
