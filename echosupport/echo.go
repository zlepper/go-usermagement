package echosupport

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/zlepper/go-usermagement"
	"github.com/zlepper/go-usermagement/internal"
	"net/http"
)

// Contains some generated values that should help in hooking up the application
type Result struct {
	AuthMiddleware echo.MiddlewareFunc
}

func GetUserManagementRouter(g echo.Group, options usermanagement.Options) (Result, error) {
	g.POST("/create", getCreateUserHandler(options))
	g.POST("/login", getLoginUserHandler(options))
	g.POST("/startreset", getStartResetUserHandler(options))
	g.POST("/finishreset", getFinishUserResetHandler(options))

	r := Result{
		AuthMiddleware: middleware.JWT([]byte(options.GetSigningSecret())),
	}

	return r, nil
}

func getStartResetUserHandler(resetUser usermanagement.ResetUser) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request internal.ResetUserRequest
		err := c.Bind(&request)
		if err != nil {
			return err
		}

		err = usermanagement.StartResetUser(resetUser, request.Username)
		if err != nil {
			return err
		}
		return c.NoContent(http.StatusAccepted)
	}
}

func getLoginUserHandler(userLogin usermanagement.UserLogin) echo.HandlerFunc {
	return func(c echo.Context) error {
		var loginInfo internal.LoginInfo
		err := c.Bind(&loginInfo)
		if err != nil {
			return err
		}

		token, err := usermanagement.Login(userLogin, loginInfo)
		if err != nil {
			return err
		}

		return c.JSON(http.StatusOK, internal.LoginResponse{Token: token})
	}
}

func getCreateUserHandler(creation usermanagement.UserCreation) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user internal.User
		err := c.Bind(&user)
		if err != nil {
			return err
		}

		err = usermanagement.CreateUser(creation, user.Username, user.Password, user.Data)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusCreated)
	}
}

func getFinishUserResetHandler(resetUser usermanagement.ResetUser) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request internal.FinishResetRequest
		err := c.Bind(&request)
		if err != nil {
			return err
		}

		err = usermanagement.FinishUserReset(resetUser, request.Token, request.Password)
		if err != nil {
			return err
		}

		return c.NoContent(http.StatusOK)
	}
}
