package usermanagement

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidPassword error = errors.New("Password does not match current password")
)

func ChangePassword(options Options, username, oldPassword, newPassword string) (err error) {
	// Ensure new password survives the harsh standard the dev set
	err = options.ValidatePassword(newPassword)
	if err != nil {
		return err
	}

	currentPassword, err := options.GetPassword(username)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(currentPassword), []byte(oldPassword))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return ErrInvalidPassword
		} else {
			return err
		}
	}

	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		return err
	}

	return options.SetUserPassword(username, hashedPassword)
}
