namespace go article

include "common.thrift"

struct ArticleCreateReq {
    1: required string title
    2: required string content
    3: required string token
    4: required bool publish
}

struct ArticleCreateResp {
    1: required i64 article_id
    2: required i32 status_code
    3: required string status_msg
}

struct ArticlePublishReq {
    1: required i64 article_id
}

struct ArticlePublishResp {
    1: required i32 status_code
    2: required string status_msg
}

struct ArticleDeleteReq {
    1: required i64 article_id
    2: required string token
}

struct ArticleDeleteResp {
    1: required i32 status_code
    2: required string status_msg
}

struct ArticleEditReq {
    1: required i64 article_id
    2: optional string title
    3: optional string content
    4: required string token
}

struct ArticleEditResp {
    1: required i32 status_code
    2: required string status_msg
}

struct ArticleInfoReq {
    1: required i64 article_id
}

struct ArticleInfoResp {
    1: required i32 status_code
    2: required string status_msg
    3: optional common.Article article,
}

struct ArticleHideReq {
    1: required i64 article_id
    2: required string token
}

struct ArticleHideResp {
    1: required i32 status_code
    2: required string status_msg
}


service ArticleService {
    ArticlePublishResp Publish(1: ArticlePublishReq request) (api.post="/article/publish"),
    ArticleDeleteResp Delete(1: ArticleDeleteReq request) (api.post="/article/delete"),
    ArticleEditResp Edit(1: ArticleEditReq request) (api.post="/article/edit"),
    ArticleInfoResp GetInfo(1: ArticleInfoReq request) (api.get="/article/info"),
    ArticleCreateResp Create(1: ArticleCreateReq request) (api.post="/article/create")
    ArticleHideResp Hide(1: ArticleHideReq request) (api.get="/article/hide")
}
