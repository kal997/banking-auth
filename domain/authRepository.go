package domain

import "github.com/kal997/banking-lib/errs"

type AuthRepository interface {
	FindBy(username string, password string) (*Login, *errs.AppError)
}
