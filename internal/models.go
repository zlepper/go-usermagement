package internal

type User struct {
	Username, Password string
	Data               map[string]interface{}
}

type LoginInfo struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RememberMe bool   `json:"rememberMe"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type ResetUserRequest struct {
	Username string `json:"username"`
}

type FinishResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}
