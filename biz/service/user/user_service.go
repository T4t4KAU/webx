package service

import (
	"context"
	"github.com/T4t4KAU/webx/biz/dal"
	"github.com/T4t4KAU/webx/biz/dal/model"
	"github.com/T4t4KAU/webx/biz/model/common"
	"github.com/T4t4KAU/webx/biz/model/user"
	"github.com/T4t4KAU/webx/pkg/errno"
	"github.com/T4t4KAU/webx/pkg/mw/cache"
	"github.com/bytedance/gopkg/util/logger"
	"github.com/cloudwego/hertz/pkg/app"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	ctx context.Context
	c   *app.RequestContext
}

func NewUserService(ctx context.Context, c *app.RequestContext) *UserService {
	return &UserService{
		ctx: ctx,
		c:   c,
	}
}

func (svc *UserService) Register(req *user.UserRegisterReq) error {
	u, err := dal.QueryUserByName(svc.ctx, req.Username)
	if err != nil {
		return err
	}
	if u != (model.User{}) {
		return errno.UserAlreadyExistErr
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errno.ErrInternalError.WithMessage("generate hashed password failed")
	}

	return dal.InsertUser(svc.ctx, model.User{
		Username: req.Username,
		Password: string(hashed),
	})
}

func (svc *UserService) Edit(req *user.UserEditReq) error {
	uid, _ := svc.c.Get("current_user_id")
	u, err := dal.QueryUserById(svc.ctx, uid.(int64))
	if u == (model.User{}) {
		return errno.UserIsNotExistErr
	}
	if err != nil {
		logger.Warn("Failed to query user by id, error=", err.Error())
		return err
	}

	u.Email = req.Email
	u.Signature = req.Signature
	return dal.UpdateUser(svc.ctx, u)
}

func (svc *UserService) Profile(req *user.UserProfileReq) (common.User, error) {
	data, err := cache.GetUserById(svc.ctx, req.UserID)
	if err == nil {
		return data, err
	}

	u, err := dal.QueryUserById(svc.ctx, req.UserID)
	if err != nil {
		logger.Warn("Failed to query user by id, error=", err.Error())
		return common.User{}, err
	}
	if u == (model.User{}) {
		return common.User{}, errno.UserIsNotExistErr
	}

	res := common.User{
		Name:      u.Username,
		Email:     u.Email,
		Signature: u.Signature,
	}

	go func(ctx context.Context) {
		_ = cache.SetUserById(ctx, req.UserID, res)
	}(svc.ctx)

	return res, nil
}
