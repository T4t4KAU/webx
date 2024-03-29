package cache

import (
	"context"
	"fmt"
	"github.com/T4t4KAU/webx/biz/model/common"
	"github.com/bytedance/sonic"
	"time"
)

var expiration = time.Minute * 15

// GetUserById 获取用户信息
func GetUserById(ctx context.Context, id int64) (common.User, error) {
	key := KeyByUserId(id)
	bytes, err := RD.Get(ctx, key).Bytes()
	if err != nil {
		return common.User{}, err
	}

	var u common.User
	err = sonic.Unmarshal(bytes, &u)
	if err != nil {
		return common.User{}, err
	}
	return u, nil
}

// SetUserById 存储用户信息
func SetUserById(ctx context.Context, id int64, user common.User) error {
	val, err := sonic.Marshal(user)
	if err != nil {
		return err
	}
	key := KeyByUserId(id)
	return RD.Set(ctx, key, val, expiration).Err()
}

func GetUserByName(ctx context.Context, name string) (common.User, error) {
	key := KeyByUserName(name)
	bytes, err := RD.Get(ctx, key).Bytes()
	if err != nil {
		return common.User{}, err
	}

	var u common.User
	err = sonic.Unmarshal(bytes, &u)
	if err != nil {
		return common.User{}, err
	}
	return u, nil
}

func SetUserByName(ctx context.Context, name string, user common.User) error {
	val, err := sonic.Marshal(user)
	if err != nil {
		return err
	}
	key := KeyByUserName(name)
	return RD.Set(ctx, key, val, expiration).Err()
}

func KeyByUserId(id int64) string {
	return fmt.Sprintf("user:id:%d", id)
}

func KeyByUserName(name string) string {
	return fmt.Sprintf("user:name:%s", name)
}
