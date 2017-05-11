package usermanagement

type Options interface {
	UserCreation
	UserLogin
	ResetUser
}
