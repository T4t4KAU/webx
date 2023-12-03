namespace go common

struct User {
    1: required i64 id; // user id
    2: required string name; // user name
    3: required string email // user email
    4: required string signature // user signature
}

struct Article {
    1: required i64 id;
    2: required i64 author_id
    3: required string title
    4: required string content
}