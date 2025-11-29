package servers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/logger"
	"github.com/gobuffalo/nulls"
	"github.com/julienschmidt/httprouter"
	"io"
	"net/http"
)

type PatchCertOptions struct {
	AutoRenew nulls.Bool `json:"auto_renew"`
}

type patchCertQueries interface {
	SetCertificateAutoRenew(ctx context.Context, args database.SetCertificateAutoRenewParams) error
	UseTx(ctx context.Context, cb func(tx *database.Queries) error) error
}

func certPatch(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, b AuthClaims, certId int64, db patchCertQueries) {
	// Reject if content length is too large
	if req.ContentLength > MaxBodySize {
		http.Error(rw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}

	// Limit processing to the max size
	rawBody := io.LimitReader(req.Body, MaxBodySize)

	var body PatchCertOptions
	if err := json.NewDecoder(rawBody).Decode(&body); err != nil {
		http.Error(rw, "Failed to parse body", http.StatusBadRequest)
		return
	}

	err := db.UseTx(req.Context(), func(tx *database.Queries) error {
		var errs []error
		if body.AutoRenew.Valid {
			errs = append(errs, tx.SetCertificateAutoRenew(req.Context(), database.SetCertificateAutoRenewParams{
				AutoRenew: body.AutoRenew.Bool,
				ID:        certId,
			}))
		}
		return errors.Join(errs...)
	})
	if err != nil {
		http.Error(rw, "Failed to update certificate in the database", http.StatusInternalServerError)
		logger.Logger.Error("Failed to update certificate in the database", "err", err)
		return
	}

	http.Error(rw, "{\"result\":\"Updated certificate\"}", http.StatusOK)
}
