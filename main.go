// Code generated by hertz generator.

package main

import (
	"context"
	"github.com/T4t4KAU/webx/biz/dal"
	"github.com/T4t4KAU/webx/biz/dal/query"
	"github.com/T4t4KAU/webx/pkg/constant"
	"github.com/T4t4KAU/webx/pkg/mw/auth"
	"github.com/T4t4KAU/webx/pkg/mw/cache"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/middlewares/server/recovery"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func Init() {
	initDB()
	initAuth()
	initCache()
	initLogger()
}

func main() {
	Init()

	h := server.Default()

	h.Use(recovery.Recovery(recovery.WithRecoveryHandler(LogRecoveryHandler)))

	register(h)
	h.Spin()
}

func initDB() {
	dal.DB = dal.ConnectDB(constant.MySQLDSN).Debug()
	query.SetDefault(dal.DB)
}

func initAuth() {
	auth.Init()
}

func initCache() {
	cache.RD = redis.NewClient(&redis.Options{
		Addr:     constant.RedisAddr,
		Password: constant.RedisPassword,
		DB:       0,
	})
}

func initLogger() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)
}

func LogRecoveryHandler(c context.Context, ctx *app.RequestContext, err interface{}, stack []byte) {
	hlog.SystemLogger().CtxErrorf(c, "[Recovery] err=%v\nstack=%s", err, stack)
	hlog.SystemLogger().Infof("Client: %s", ctx.Request.Header.UserAgent())
	ctx.AbortWithStatus(consts.StatusInternalServerError)
}
