package database

import (
	"context"
	"database/sql"
	"errors"
)

var errMissingSqlDB = errors.New("cannot open transaction without sql.DB")

func (q *Queries) UseTx(ctx context.Context, cb func(tx *Queries) error) error {
	sqlDB, ok := q.db.(*sql.DB)
	if !ok {
		return errMissingSqlDB
	}
	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = cb(q.WithTx(tx))
	if err != nil {
		return err
	}
	return tx.Commit()
}
