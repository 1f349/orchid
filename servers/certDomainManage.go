package servers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/1f349/mjwt"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/renewal"
	"github.com/1f349/orchid/utils"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func certDomainManageGET(db *database.Queries, signer *mjwt.KeyStore) httprouter.Handle {
	return checkAuthForCertificate(signer, "orchid:cert:edit", db, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims, certId int64) {
		rows, err := db.GetDomainStatesForCert(context.Background(), certId)
		if err != nil {
			apiError(rw, http.StatusInsufficientStorage, "Database error")
			return
		}

		// write output
		rw.WriteHeader(http.StatusAccepted)
		m := map[string]any{
			"id":      fmt.Sprintf("%d", certId),
			"domains": rows,
		}
		_ = json.NewEncoder(rw).Encode(m)
	})
}

func certDomainManagePUTandDELETE(db *database.Queries, signer *mjwt.KeyStore, domains utils.DomainChecker) httprouter.Handle {
	return checkAuthForCertificate(signer, "orchid:cert:edit", db, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims, certId int64) {
		// check request type
		isAdd := req.Method == http.MethodPut

		// read domains from request body
		var d []string
		if json.NewDecoder(req.Body).Decode(&d) != nil {
			apiError(rw, http.StatusBadRequest, "Invalid request body")
			return
		}

		// validate all domains
		for _, i := range d {
			if !validateDomainOwnershipClaims(i, b.Claims.Perms) {
				apiError(rw, http.StatusBadRequest, "Token cannot modify a specified domain")
				return
			}
			if !domains.ValidateDomain(i) {
				apiError(rw, http.StatusBadRequest, "Invalid domain")
				return
			}
		}

		// run a safe transaction to insert or update the certificate domains
		if db.UseTx(req.Context(), func(tx *database.Queries) error {
			if isAdd {
				// insert domains to add
				for _, i := range d {
					err := tx.AddDomains(req.Context(), database.AddDomainsParams{
						CertID: certId,
						Domain: i,
						State:  renewal.DomainStateAdded,
					})
					if err != nil {
						return fmt.Errorf("failed to add domains to the database")
					}
				}
			} else {
				// update domains to removed state
				err := tx.UpdateDomains(req.Context(), database.UpdateDomainsParams{
					State:   renewal.DomainStateRemoved,
					Domains: d,
				})
				if err != nil {
					return fmt.Errorf("failed to remove domains from the database")
				}
			}
			return nil
		}) != nil {
			apiError(rw, http.StatusInsufficientStorage, "Database error")
			return
		}

		// write output
		rw.WriteHeader(http.StatusAccepted)
		m := map[string]any{
			"id": fmt.Sprintf("%d", certId),
		}
		if isAdd {
			m["add_domains"] = d
		} else {
			m["remove_domains"] = d
		}
		_ = json.NewEncoder(rw).Encode(m)
	})
}
