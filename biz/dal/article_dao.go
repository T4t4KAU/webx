package dal

import (
	"context"
	"github.com/T4t4KAU/webx/biz/dal/model"
	"github.com/T4t4KAU/webx/biz/dal/query"
	"github.com/T4t4KAU/webx/pkg/errno"
)

func InsertArticle(ctx context.Context, article model.Article) error {
	return query.Article.WithContext(ctx).Create(&article)
}

func QueryArticleById(ctx context.Context, id int64) (*model.Article, error) {
	article, err := query.Article.WithContext(ctx).Where(query.Article.ID.Eq(id)).First()
	if err != nil {
		return &model.Article{}, errno.DatabaseError(err.Error())
	}
	return article, nil
}

func DeleteArticleById(ctx context.Context, id int64) error {
	res, err := query.Article.WithContext(ctx).Where(query.Article.ID.Eq(id)).Delete()
	if err != nil {
		return errno.DatabaseError(err.Error())
	}
	if res.RowsAffected <= 0 {
		return errno.ErrNoRowsAffected
	}

	return nil
}

func UpdateArticleById(ctx context.Context, article *model.Article) error {
	res, err := query.Article.WithContext(ctx).Where(query.Article.AuthorID.Eq(article.ID)).Updates(article)
	if err != nil {
		return errno.DatabaseError(err.Error())
	}
	if res.RowsAffected <= 0 {
		return errno.ErrNoRowsAffected
	}

	return nil
}
