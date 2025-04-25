package domain

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/kal997/banking-lib/errs"
	"github.com/kal997/banking-lib/logger"
)

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func (ar AuthRepositoryDb) FindBy(username string, password string) (*Login, *errs.AppError) {
	var login Login
	sqlVerify := `SELECT MAX(username) as username, u.customer_id, MAX(role) as role, group_concat(a.account_id) as account_numbers FROM users u
                  LEFT JOIN accounts a ON a.customer_id = u.customer_id
                WHERE username = ? and password = ?
                GROUP BY u.customer_id`
	err := ar.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("Invalid Credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return &login, nil
}

func NewAuthRepository(client *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{client: client}
}
