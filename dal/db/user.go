package db

import (
	"context"
	"webx/pkg/errno"
)

type User struct {
	Id       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (User) TableName() string {
	return "tb_user"
}

func CreateUser(ctx context.Context, user *User) (int64, error) {
	err := dao.WithContext(ctx).Create(user).Error
	if err != nil {
		return 0, err
	}
	return user.Id, nil
}

func VerifyUser(username string, password string) (int64, error) {
	var user User
	err := dao.Where("username = ? AND password = ?", username, password).Find(&user).Error
	if err != nil {
		return 0, err
	}
	if user.Id == 0 {
		return user.Id, errno.PasswordIsNotVerified
	}
	return user.Id, nil
}
