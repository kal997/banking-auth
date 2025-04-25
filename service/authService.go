package service

import (
	"github.com/kal997/banking-auth/dto"
	"github.com/kal997/banking-lib/errs"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
}
