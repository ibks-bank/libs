package auth

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

type Claims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Password string `json:"password"`
}

type authorizer struct {
	key            string
	expireDuration time.Duration
}

func NewAuthorizer(key string, expireDuration time.Duration) *authorizer {
	return &authorizer{key: key, expireDuration: expireDuration}
}

func (a *authorizer) GetToken(login, password, salt string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: jwt.At(time.Now().Add(a.expireDuration)),
			IssuedAt:  jwt.At(time.Now()),
		},
		Username: login,
		Password: HashPassword(password, salt),
	})

	return token.SignedString([]byte(a.key))
}

func HashPassword(password, salt string) string {
	pwd := sha256.New()
	pwd.Write([]byte(password))
	pwd.Write([]byte(salt))
	return fmt.Sprintf("%x", pwd.Sum(nil))
}
