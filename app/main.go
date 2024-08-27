package main

import (
	"context"
	"github.com/aws/aws-lambda-go/lambda"
)

// Response è la struttura della risposta in JSON
type Response struct {
	Message string `json:"message"`
}

// Handler è la funzione che verrà invocata da AWS Lambda
func Handler(ctx context.Context) (Response, error) {
	// Creiamo un'istanza di Response con il messaggio "Hello, World!"
	resp := Response{
		Message: "Hello, World!",
	}
	return resp, nil
}

func main() {
	// lambda.Start lancia la funzione Lambda
	lambda.Start(Handler)
}
