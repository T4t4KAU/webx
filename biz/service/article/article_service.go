package service

import (
	"context"
	"github.com/T4t4KAU/webx/biz/dal"
	"github.com/T4t4KAU/webx/biz/dal/model"
	"github.com/T4t4KAU/webx/biz/model/article"
	"github.com/T4t4KAU/webx/biz/model/common"
	"github.com/T4t4KAU/webx/pkg/errno"
	"github.com/bytedance/gopkg/util/logger"
	"github.com/cloudwego/hertz/pkg/app"
	"time"
)

type ArticleService struct {
	ctx context.Context
	c   *app.RequestContext
}

func NewArticleService(ctx context.Context, c *app.RequestContext) *ArticleService {
	return &ArticleService{
		ctx: ctx,
		c:   c,
	}
}

func (svc *ArticleService) Create(req *article.ArticleCreateReq) error {
	id, _ := svc.c.Get("current_user_id")
	err := dal.InsertArticle(svc.ctx, model.Article{
		Title:     req.Title,
		Content:   []byte(req.Content),
		AuthorID:  id.(int64),
		Ctime:     time.Now().UnixNano(),
		Utime:     time.Now().UnixNano(),
		Published: req.Publish,
	})
	if err != nil {
		logger.Warn("Failed to insert article to database, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) Publish(req *article.ArticlePublishReq) error {
	id, _ := svc.c.Get("current_user_id")
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to query article by id, error=" + err.Error())
		return err
	}
	if id != ar.AuthorID {
		return errno.ArticlePermssionDenied
	}

	ar.Published = true
	err = dal.UpdateArticleById(svc.ctx, ar)
	if err != nil {
		logger.Warn("Fail to update article by id, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) Delete(req *article.ArticleDeleteReq) error {
	id, _ := svc.c.Get("current_user_id")
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to query article by id, error=" + err.Error())
		return err
	}
	if ar.AuthorID != id {
		return errno.ArticlePermssionDenied
	}
	err = dal.DeleteArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to delete article by id, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) Edit(req *article.ArticleEditReq) error {
	id, _ := svc.c.Get("current_user_id")
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		logger.Warn("Failed to query article by id, error=" + err.Error())
		return err
	}
	if ar.AuthorID != id {
		return errno.ArticlePermssionDenied
	}

	ar.Title = *req.Title
	ar.Content = []byte(*req.Content)
	ar.Utime = time.Now().UnixNano()
	err = dal.UpdateArticleById(svc.ctx, ar)
	if err != nil {
		logger.Warn("Fail to update article by id, error=" + err.Error())
		return err
	}
	return nil
}

func (svc *ArticleService) GetInfo(req *article.ArticleInfoReq) (common.Article, error) {
	ar, err := dal.QueryArticleById(svc.ctx, req.ArticleID)
	if err != nil {
		return common.Article{}, err
	}
	if ar == (&model.Article{}) {
		return common.Article{}, nil
	}
	return common.Article{
		AuthorID: ar.AuthorID,
		Title:    ar.Title,
		Content:  string(ar.Content),
	}, nil
}
