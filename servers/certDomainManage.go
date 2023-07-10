package servers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/orchid/renewal"
	"github.com/MrMelon54/orchid/utils"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

func certDomainManageGET(db *sql.DB, signer mjwt.Verifier) httprouter.Handle {
	return checkAuthForCertificate(signer, "orchid:cert:edit", db, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims, certId uint64) {
		query, err := db.Query(`SELECT domain, state FROM certificate_domains WHERE cert_id = ?`, certId)
		if err != nil {
			apiError(rw, http.StatusInsufficientStorage, "Database error")
			return
		}

		// collect all the domains and state values
		var domainStates []DomainStateValue
		for query.Next() {
			var a DomainStateValue
			err := query.Scan(&a.Domain, &a.State)
			if err != nil {
				apiError(rw, http.StatusInsufficientStorage, "Database error")
				return
			}
			domainStates = append(domainStates, a)
		}

		// write output
		rw.WriteHeader(http.StatusAccepted)
		m := map[string]any{
			"id":      fmt.Sprintf("%d", certId),
			"domains": domainStates,
		}
		_ = json.NewEncoder(rw).Encode(m)
	})
}

func certDomainManagePUTandDELETE(db *sql.DB, signer mjwt.Verifier, domains utils.DomainChecker) httprouter.Handle {
	return checkAuthForCertificate(signer, "orchid:cert:edit", db, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims, certId uint64) {
		// check request type
		isAdd := req.Method == http.MethodPut

		if len(b.Audience) == 0 {
			apiError(rw, http.StatusForbidden, "Missing audience tag, to specify owned domains")
			return
		}

		// read domains from request body
		var d []string
		if json.NewDecoder(req.Body).Decode(&d) != nil {
			apiError(rw, http.StatusBadRequest, "Invalid request body")
			return
		}

		// validate all domains
		for _, i := range d {
			if !validateDomainAudienceClaims(i, b.Audience) {
				apiError(rw, http.StatusBadRequest, "Token cannot modify a specified domain")
				return
			}
			if !domains.ValidateDomain(i) {
				apiError(rw, http.StatusBadRequest, "Invalid domain")
				return
			}
		}

		// run a safe transaction to insert or update the certificate domains
		if safeTransaction(rw, db, func(rw http.ResponseWriter, tx *sql.Tx) error {
			if isAdd {
				// insert domains to add
				for _, i := range d {
					_, err := tx.Exec(`INSERT INTO certificate_domains (cert_id, domain, state) VALUES (?, ?, ?)`, certId, i, renewal.DomainStateAdded)
					if err != nil {
						return fmt.Errorf("failed to add domains to the database")
					}
				}
			} else {
				// update domains to removed state
				_, err := tx.Exec(`UPDATE certificate_domains SET state = ? WHERE domain IN ?`, renewal.DomainStateRemoved, d)
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
