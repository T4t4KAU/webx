package db

import (
	"context"
	"golang.org/x/crypto/bcrypt"
	"webx/dal/cache"
	"webx/pkg/errno"
)

type User struct {
	Id        int64  `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	Signature string `json:"signature"`
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

func VerifyUser(ctx context.Context, username string, password string) (int64, error) {
	var user User
	err := dao.WithContext(ctx).Where("username = ?", username).Find(&user).Error
	if err != nil {
		return 0, err
	}
	if user.Id == 0 {
		return 0, nil
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return 0, err
	}

	return user.Id, nil
}

func QueryUserById(ctx context.Context, id int64) (User, error) {
	if user, err := cache.GetUserById(ctx, id); err == nil {
		return user, err
	}

	var user User
	err := dao.WithContext(ctx).Where("id = ?", id).Find(&user).Error
	if err != nil {
		return User{}, err
	}
	if user.Id == 0 {
		return User{}, nil
	}

	return user, nil
}

func QueryUserByName(ctx context.Context, username string) (User, error) {
	if user, err := cache.GetUserByName(ctx, username); err == nil {
		return user, err
	}

	var user User
	err := dao.WithContext(ctx).Where("username = ?", username).Find(&user).Error
	if err != nil {
		return User{}, err
	}
	if user.Id == 0 {
		return User{}, nil
	}
	return user, nil
}

func EditUserProfile(ctx context.Context, user User) error {
	var u User
	err := dao.WithContext(ctx).Where("id = ?", user.Id).Find(&u).Error
	if err != nil {
		return err
	}

	if u.Id == 0 {
		return errno.UserIsNotExistErr
	}

	u.Email = user.Email
	u.Signature = user.Signature

	return dao.WithContext(ctx).Model(&user).Updates(u).Error
}
