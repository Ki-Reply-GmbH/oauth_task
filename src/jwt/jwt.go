package jwt

import (
	"errors"

	jwtgo "github.com/dgrijalva/jwt-go"
)

type Role string
type StandardClaims = jwtgo.StandardClaims

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type Claims struct {
	StandardClaims
	Role Role `json:"role,omitempty"`
}

func GenerateToken(claims Claims, privateKey interface{}) (string, error) {
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

// * This function is not used yet but will be useful in the future when we implement token validation. *
func ParseToken(tokenString string, publicKey interface{}) (*Claims, error) {
	token, err := jwtgo.ParseWithClaims(tokenString, &Claims{}, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

func (c *Claims) ValidateRole() error {
	if c.Role != RoleAdmin && c.Role != RoleUser {
		return errors.New("invalid role: must be 'admin' or 'user'")
	}
	return nil
}
