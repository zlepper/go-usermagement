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

func GetUserManagementRouter(g *echo.Group, options usermanagement.Options) (*Result, error) {
	secret, err := options.GetSigningSecret()

	if err != nil {
		return nil, err
	}

	g.POST("/create", getCreateUserHandler(options))
	g.POST("/login", getLoginUserHandler(options))
	g.POST("/startreset", getStartResetUserHandler(options))
	g.POST("/finishreset", getFinishUserResetHandler(options))

	r := &Result{
		AuthMiddleware: middleware.JWT([]byte(secret)),
	}

	return r, err
}

func getStartResetUserHandler(resetUser usermanagement.Options) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request internal.ResetUserRequest
		err := c.Bind(&request)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		err = usermanagement.StartResetUser(resetUser, request.Username)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		return c.NoContent(http.StatusAccepted)
	}
}

func getLoginUserHandler(userLogin usermanagement.Options) echo.HandlerFunc {
	return func(c echo.Context) error {
		var loginInfo internal.LoginInfo
		err := c.Bind(&loginInfo)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		token, err := usermanagement.Login(userLogin, loginInfo)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		return c.JSON(http.StatusOK, internal.LoginResponse{Token: token})
	}
}

func getCreateUserHandler(creation usermanagement.Options) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user internal.User
		err := c.Bind(&user)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		err = usermanagement.CreateUser(creation, user.Username, user.Password, user.Data)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		return c.NoContent(http.StatusCreated)
	}
}

func getFinishUserResetHandler(resetUser usermanagement.Options) echo.HandlerFunc {
	return func(c echo.Context) error {
		var request internal.FinishResetRequest
		err := c.Bind(&request)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		err = usermanagement.FinishUserReset(resetUser, request.Token, request.Password)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		return c.NoContent(http.StatusOK)
	}
}
