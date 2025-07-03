package token

type Payload struct {
	UserId string `json:"user_id"`
	Role   string `json:"role"`
}

type Strategy interface {
	Generate(payload Payload) (string, error)
	Parse(token string) (*Payload, error)
}
