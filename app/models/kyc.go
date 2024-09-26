package models

type KycData struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type SumsubWebhook struct {
	EventType string         `json:"eventType"`
	Payload   WebhookPayload `json:"payload"`
}

type WebhookPayload struct {
	ApplicantID string `json:"applicantId"`
	Status      string `json:"status"`
}
