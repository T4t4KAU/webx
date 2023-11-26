namespace go user

include "common.thrift"

struct UserRegisterReq {
    1: required string username
    2: required string password
}

struct UserRegisterResp {
    1: required i32 status_code
    2: required string status_msg
    3: required i64 user_id
    4: required string token
}

struct UserLoginReq {
    1: required string username
    2: required string password
}

struct UserLoginResp {
    1: required i32 status_code
    2: required string status_msg
    3: required i64 user_id
    4: required string token
}

struct UserProfileReq {
    1: required i64 user_id
    2: required string token
}

struct UserProfileResp {
    1: required i32 status_code
    2: required string status_msg
    3: required common.User user;
}

struct UserEditReq {
    1: required string token
    2: required string email
    3: required string signature
}

struct UserEditResp {
    1: required i32 status_code
    2: required string status_msg
}

service UserService {
    UserRegisterResp Register(1: UserRegisterReq req) (api.post="/user/register")
    UserLoginResp Login(1: UserLoginReq req) (api.post="/user/login")
    UserProfileResp Profile(1: UserProfileReq req) (api.post="/user/profile")
    UserEditResp Edit(1: UserEditReq req) (api.post="/user/edit")
}