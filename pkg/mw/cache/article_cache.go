package cache

import (
	"context"
	"fmt"
	"github.com/T4t4KAU/webx/biz/model/common"
	"github.com/bytedance/sonic"
)

func GetArticleByIdAndPage(ctx context.Context, id, page int64) (common.Article, error) {
	key := keyByArticleIdAndPage(id, page)
	bytes, err := RD.Get(ctx, key).Bytes()
	if err != nil {
		return common.Article{}, err
	}

	var ar common.Article
	err = sonic.Unmarshal(bytes, ar)
	if err != nil {
		return common.Article{}, err
	}
	return ar, nil
}

func SetArticleByIdAndPage(ctx context.Context, article common.Article, id, page int64) error {
	val, err := sonic.Marshal(article)
	if err != nil {
		return err
	}
	key := keyByArticleIdAndPage(id, page)
	return RD.Set(ctx, key, val, expiration).Err()
}

func keyByArticleIdAndPage(id, page int64) string {
	return fmt.Sprintf("article:id:%d:page:%d", id, page)
}
