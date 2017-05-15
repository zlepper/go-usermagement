package usermanagement

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
)

var (
	ErrNoAuthHeader      error = errors.New("No authorization header")
	ErrInvalidAuthHeader error = errors.New("Invalid authorization header")
)

func getValidationKeyGetter(secret []byte) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		} else {
			if method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("Unexpected signing method: %v", method)
			}
		}
		return secret, nil
	}
}

func GetTokenData(tokenString string, secret []byte, output interface{}) error {
	token, err := jwt.Parse(tokenString, getValidationKeyGetter(secret))
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		sub := claims["sub"].(string)
		err = json.Unmarshal([]byte(sub), output)
		return err
	} else {
		return err
	}
}

func GetTokenDataFromRequest(request *http.Request, secret []byte, output interface{}) error {
	authHeader := request.Header.Get("authorization")
	if authHeader == "" {
		return ErrNoAuthHeader
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ErrInvalidAuthHeader
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return ErrInvalidAuthHeader
	}

	tokenString := parts[1]

	return GetTokenData(tokenString, secret, output)

}
