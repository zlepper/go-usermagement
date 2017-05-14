package usermanagement

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	PasswordCost int = bcrypt.DefaultCost
)

func CreateUser(creation Options, username, password string, data map[string]interface{}) error {
	err := creation.ValidateUser(username, password, data)
	if err != nil {
		return err
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}

	err = creation.CreateUser(username, hashedPassword, data)
	return err
}

func hashPassword(password string) (hashedPassword string, err error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), PasswordCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
