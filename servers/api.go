package servers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/MrMelon54/mjwt"
	oUtils "github.com/MrMelon54/orchid/utils"
	vUtils "github.com/MrMelon54/violet/utils"
	"github.com/golang-jwt/jwt/v4"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"strconv"
	"time"
)

type DomainStateValue struct {
	Domain string `json:"domain"`
	State  int    `json:"state"`
}

// NewApiServer creates and runs a http server containing all the API
// endpoints for the software
//
// `/cert` - edit certificate
func NewApiServer(listen string, db *sql.DB, signer mjwt.Verifier, domains oUtils.DomainChecker) *http.Server {
	r := httprouter.New()

	// Endpoint for looking up a certificate
	r.GET("/lookup/:domain", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := params.ByName("domain")
		if !domains.ValidateDomain(domain) {
			vUtils.RespondVioletError(rw, http.StatusBadRequest, "Invalid domain")
			return
		}
	}))

	r.POST("/cert", checkAuthWithPerm(signer, "orchid:cert:create", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		_, err := db.Exec(`INSERT INTO certificates (owner, dns, updated_at) VALUES (?, ?, ?)`, b.Subject, 0, time.Now())
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Failed to delete certificate")
			return
		}
		rw.WriteHeader(http.StatusAccepted)
	}))
	r.DELETE("/cert/:id", checkAuthForCertificate(signer, "orchid:cert:delete", db, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims, certId uint64) {
		_, err := db.Exec(`UPDATE certificates SET active = 0 WHERE id = ?`, certId)
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Failed to delete certificate")
			return
		}
		rw.WriteHeader(http.StatusAccepted)
	}))

	// Endpoint for adding/removing domains to/from a certificate
	manageGet, managePutDelete := certDomainManageGET(db, signer), certDomainManagePUTandDELETE(db, signer, domains)
	r.GET("/cert/:id/domains", manageGet)
	r.PUT("/cert/:id/domains", managePutDelete)
	r.DELETE("/cert/:id/domains", managePutDelete)

	// Endpoint for generating a temporary certificate for modified domains
	r.POST("/cert/:id/temp", checkAuth(signer, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		if !b.Claims.Perms.Has("orchid:cert:quick") {
			apiError(rw, http.StatusForbidden, "No permission")
			return
		}

		// lookup certificate owner
		id, err := checkCertOwner(db, "", b)
		if err != nil {
			apiError(rw, http.StatusInsufficientStorage, "Database error")
			return
		}

		// run a safe transaction to create the temporary certificate
		if safeTransaction(rw, db, func(rw http.ResponseWriter, tx *sql.Tx) error {
			// insert temporary certificate into database
			_, err := db.Exec(`INSERT INTO certificates (owner, dns, active, updated_at, temp_parent) VALUES (?, 0, 1, ?, ?)`, b.Subject, time.Now(), id)
			return err
		}) != nil {
			apiError(rw, http.StatusInsufficientStorage, "Database error")
			fmt.Printf("Internal error: %s\n", err)
			return
		}
	}))

	// Create and run http server
	return &http.Server{
		Addr:              listen,
		Handler:           r,
		ReadTimeout:       time.Minute,
		ReadHeaderTimeout: time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    2500,
	}
}

// apiError outputs a generic JSON error message
func apiError(rw http.ResponseWriter, code int, m string) {
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(map[string]string{
		"error": m,
	})
}

// lookupCertOwner finds the certificate matching the id string and returns the
// numeric id, owner and possible error, only works for active certificates.
func checkCertOwner(db *sql.DB, idStr string, b AuthClaims) (uint64, error) {
	// parse the id
	rawId, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, err
	}

	// run database query
	row := db.QueryRow(`SELECT id, owner FROM certificates WHERE active = 1 and id = ?`, rawId)

	// scan in result values
	var id uint64
	var owner string
	err = row.Scan(&id, &owner)
	if err != nil {
		return 0, fmt.Errorf("scan error: %w", err)
	}

	// check the owner is the mjwt token subject
	if b.Subject != owner {
		return id, fmt.Errorf("not the certificate owner")
	}

	// it's all valid, return the values
	return id, nil
}

// safeTransaction completes a database transaction safely allowing for rollbacks
// if the callback errors
func safeTransaction(rw http.ResponseWriter, db *sql.DB, cb func(rw http.ResponseWriter, tx *sql.Tx) error) error {
	// start a transaction
	begin, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin a transaction")
	}

	// init defer rollback
	needsRollback := true
	defer func() {
		if needsRollback {
			_ = begin.Rollback()
		}
	}()

	// run main code within the transaction session
	err = cb(rw, begin)
	if err != nil {
		return err
	}

	// clear the rollback flag and commit the transaction
	needsRollback = false
	if begin.Commit() != nil {
		return fmt.Errorf("failed to commit a transaction")
	}
	return nil
}

// validateDomainAudienceClaims validates if the audience claims contain the
// `owns=<fqdn>` field with the matching top level domain
func validateDomainAudienceClaims(a string, aud jwt.ClaimStrings) bool {
	if fqdn, ok := vUtils.GetTopFqdn(a); ok {
		for _, i := range aud {
			if i == "owns="+fqdn {
				return true
			}
		}
	}
	return false
}
