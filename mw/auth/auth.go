package auth

import (
	"context"
	"errors"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/hertz-contrib/jwt"
	"time"
	"webx/dal/db"
	"webx/pkg/constants"
	"webx/pkg/errno"
)

var (
	once *jwt.HertzJWTMiddleware
)

func Init() {
	// 创建jwt middleware
	once, _ = jwt.New(&jwt.HertzJWTMiddleware{
		Key:     []byte(constants.SecretKey),
		Timeout: time.Hour * 24,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(int64); ok {
				return jwt.MapClaims{
					constants.IdentityKey: v,
				}
			}
			return jwt.MapClaims{}
		},
		HTTPStatusMessageFunc: func(e error, ctx context.Context, c *app.RequestContext) string {
			var errNo errno.ErrNo
			switch {
			case errors.As(e, &errNo):
				return e.(errno.ErrNo).ErrMsg
			default:
				return e.Error()
			}
		},
		LoginResponse: func(ctx context.Context, c *app.RequestContext, code int, token string, expire time.Time) {
			c.JSON(consts.StatusOK, map[string]interface{}{
				"status_code": errno.SuccessCode,
				"status_msg":  errno.SuccessMsg,
				"token":       token,
			})
		},
		Unauthorized: func(ctx context.Context, c *app.RequestContext, code int, message string) {
			c.JSON(code, map[string]interface{}{
				"status_code": errno.AuthorizationFailedErrCode,
				"status_msg":  message,
			})
		},
		Authenticator: func(ctx context.Context, c *app.RequestContext) (interface{}, error) {
			type LoginParam struct {
				Username string
				Password string
			}

			var param LoginParam
			if err := c.BindAndValidate(&param); err != nil {
				return nil, err
			}
			uid, err := db.VerifyUser(ctx, param.Username, param.Password)
			if uid == 0 {
				err = errno.PasswordIsNotVerified
				return nil, err
			}
			if err != nil {
				return nil, err
			}
			c.Set("user_id", uid)

			return uid, nil
		},
		Authorizator: func(data interface{}, ctx context.Context, c *app.RequestContext) bool {
			if v, ok := data.(float64); ok {
				currentUserId := int64(v)
				c.Set("current_user_id", currentUserId)
				hlog.CtxInfof(ctx, "Token is verified clientIP: "+c.ClientIP())
				return true
			}
			return false
		},
		IdentityKey:   constants.IdentityKey,
		TokenLookup:   "header: Authorization, query: token, cookie: jwt, form: token",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
}

func UserLogin(ctx context.Context, c *app.RequestContext) {
	once.LoginHandler(ctx, c)
}

func MiddlewareFunc() app.HandlerFunc {
	return once.MiddlewareFunc()
}
