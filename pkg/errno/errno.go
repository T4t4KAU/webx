package errno

import (
	"errors"
	"fmt"
)

const (
	SuccessCode    = 0
	ServiceErrCode = iota + 10000
	ParamErrCode
	AuthorizationFailedErrCode

	UserAlreadyExistErrCode
	UserIsNotExistErrCode
	ArticleIsNotExistErrCode

	ErrInternalErrorCode
	ErrDatabaseErrorCode
	ErrNoRowsAffectedCode
)

const (
	SuccessMsg                = "Success"
	ServerErrMsg              = "Service is unable to start successfully"
	ParamErrMsg               = "Wrong Parameter has been given"
	UserIsNotExistErrMsg      = "user is not exist"
	PasswordIsNotVerifiedMsg  = "username or password not verified"
	ArticleIsNotExistMsg      = "article is not exist"
	ArticlePermssionDeniedMsg = "permssion denied"

	InternalErrorMsg  = "internal error"
	DatabaseErrorMsg  = "database error"
	NoRowsAffectedMsg = "no rows affected"
)

type ErrNo struct {
	ErrCode int32
	ErrMsg  string
}

func (e ErrNo) Error() string {
	return fmt.Sprintf("err_code=%d, err_msg=%s", e.ErrCode, e.ErrMsg)
}

func NewErrNo(code int32, msg string) ErrNo {
	return ErrNo{code, msg}
}

func (e ErrNo) WithMessage(msg string) ErrNo {
	e.ErrMsg = msg
	return e
}

var (
	Success                = NewErrNo(SuccessCode, SuccessMsg)
	ServiceErr             = NewErrNo(ServiceErrCode, ServerErrMsg)
	ParamErr               = NewErrNo(ParamErrCode, ParamErrMsg)
	UserAlreadyExistErr    = NewErrNo(UserAlreadyExistErrCode, "User already exists")
	AuthorizationFailedErr = NewErrNo(AuthorizationFailedErrCode, "Authorization failed")
	UserIsNotExistErr      = NewErrNo(UserIsNotExistErrCode, UserIsNotExistErrMsg)
	PasswordIsNotVerified  = NewErrNo(AuthorizationFailedErrCode, PasswordIsNotVerifiedMsg)
	ArticleIsNotExistErr   = NewErrNo(ArticleIsNotExistErrCode, ArticleIsNotExistMsg)
	ArticlePermssionDenied = NewErrNo(AuthorizationFailedErrCode, ArticlePermssionDeniedMsg)

	ErrInternalError  = NewErrNo(ErrInternalErrorCode, InternalErrorMsg)
	ErrDatabaseError  = NewErrNo(ErrDatabaseErrorCode, DatabaseErrorMsg)
	ErrNoRowsAffected = NewErrNo(ErrNoRowsAffectedCode, NoRowsAffectedMsg)
)

// ConvertErr convert error to Errno
func ConvertErr(err error) ErrNo {
	Err := ErrNo{}
	if errors.As(err, &Err) {
		return Err
	}

	s := ServiceErr
	s.ErrMsg = err.Error()
	return s
}

func InternalError(msg string) error {
	return ErrInternalError.WithMessage(msg)
}

func DatabaseError(msg string) error {
	return ErrDatabaseError.WithMessage(msg)
}
