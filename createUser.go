package usermanagement

import (
	"github.com/zlepper/go-usermagement/internal"
	"golang.org/x/crypto/bcrypt"
)

const (
	PasswordCost int = bcrypt.DefaultCost
)

type UserCreation interface {
	// Should validate if the username is valid (e.g. validate that it's an email if
	// that is the kind of usernames being used)
	ValidateUser(username, password string, data map[string]interface{}) error
	// Should save the User to some sort of persistence layer (A database would be a good idea)
	CreateUser(username, password string, data map[string]interface{}) error
	// Should return a key to sign the jwt token with
	GetSigningSecret() (signingKey string, err error)
}

func CreateUser(creation UserCreation, user internal.User) error {
	err := creation.ValidateUser(user.Username, user.Password, user.Data)
	if err != nil {
		return err
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		return err
	}

	err = creation.CreateUser(user.Username, hashedPassword, user.Data)
	return err
}

func hashPassword(password string) (hashedPassword string, err error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), PasswordCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
