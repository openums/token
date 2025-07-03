package token

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type jwtClaims struct {
	jwt.RegisteredClaims
	Payload
}

type JWTStrategy struct {
	secret []byte
}

func (s *JWTStrategy) Generate(payload Payload) (string, error) {
	expiryTime := time.Now().Add(24 * time.Hour)
	claims := &jwtClaims{
		Payload: payload,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "identity-service-issuer",
			ExpiresAt: jwt.NewNumericDate(expiryTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "identity-jwt"

	return token.SignedString(s.secret)
}

func (s *JWTStrategy) Parse(token string) (*Payload, error) {
	var claims jwtClaims

	t, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return s.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if !t.Valid {
		return nil, nil
	}

	return &claims.Payload, nil
}

func NewJWTStrategy(secret string) Strategy {
	return &JWTStrategy{
		secret: []byte(secret),
	}
}
