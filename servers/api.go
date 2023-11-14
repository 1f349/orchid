package servers

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/claims"
	oUtils "github.com/1f349/orchid/utils"
	vUtils "github.com/1f349/violet/utils"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"strconv"
	"time"
)

type DomainStateValue struct {
	Domain string `json:"domain"`
	State  int    `json:"state"`
}

type Certificate struct {
	Id          int       `json:"id"`
	AutoRenew   bool      `json:"auto_renew"`
	Active      bool      `json:"active"`
	Renewing    bool      `json:"renewing"`
	RenewFailed bool      `json:"renew_failed"`
	NotAfter    time.Time `json:"not_after"`
	UpdatedAt   time.Time `json:"updated_at"`
	Domains     []string  `json:"domain"`
}

//go:embed find-owned-certs.sql
var findOwnedCerts string

// NewApiServer creates and runs a http server containing all the API
// endpoints for the software
//
// `/cert` - edit certificate
func NewApiServer(listen string, db *sql.DB, signer mjwt.Verifier, domains oUtils.DomainChecker) *http.Server {
	r := httprouter.New()

	r.GET("/", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		http.Error(rw, "Orchid API Endpoint", http.StatusOK)
	})

	// Endpoint for grabbing owned certificates
	r.GET("/owned", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domains := getDomainOwnershipClaims(b.Claims.Perms)
		domainMap := make(map[string]bool)
		for _, i := range domains {
			domainMap[i] = true
		}

		// query database
		query, err := db.Query(findOwnedCerts)
		if err != nil {
			http.Error(rw, "Database Error", http.StatusInternalServerError)
			return
		}

		mOther := make(map[int]*Certificate) // other certificates
		m := make(map[int]*Certificate)      // certificates owned by this user

		// loop over query rows
		for query.Next() {
			var c Certificate
			var d string
			err := query.Scan(&c.Id, &c.AutoRenew, &c.Active, &c.Renewing, &c.RenewFailed, &c.NotAfter, &c.UpdatedAt, &d)
			if err != nil {
				log.Println("Failed to read certificate from database: ", err)
				http.Error(rw, "Database Error", http.StatusInternalServerError)
				return
			}

			// check in owned map
			if cert, ok := m[c.Id]; ok {
				cert.Domains = append(cert.Domains, d)
				continue
			}

			// get etld+1
			topFqdn, found := vUtils.GetTopFqdn(d)
			if !found {
				log.Println("Invalid domain found: ", d)
				http.Error(rw, "Database Error", http.StatusInternalServerError)
				return
			}

			// if found in other, add domain and put in main if owned
			if cert, ok := mOther[c.Id]; ok {
				cert.Domains = append(cert.Domains, d)
				if domainMap[topFqdn] {
					m[c.Id] = cert
				}
				return
			}

			// add to other and main if owned
			c.Domains = []string{d}
			mOther[c.Id] = &c
			if domainMap[topFqdn] {
				m[c.Id] = &c
			}
		}
		if err := query.Err(); err != nil {
			log.Println("Failed after reading certificates from database: ", err)
			http.Error(rw, "Database Error", http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rw).Encode(m)
	}))

	// Endpoint for looking up a certificate
	r.GET("/lookup/:domain", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := params.ByName("domain")
		if !domains.ValidateDomain(domain) {
			vUtils.RespondVioletError(rw, http.StatusBadRequest, "Invalid domain")
			return
		}
	}))

	r.POST("/cert", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		_, err := db.Exec(`INSERT INTO certificates (owner, dns, updated_at) VALUES (?, ?, ?)`, b.Subject, 0, time.Now())
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Failed to delete certificate")
			return
		}
		rw.WriteHeader(http.StatusAccepted)
	}))
	r.DELETE("/cert/:id", checkAuthForCertificate(signer, "orchid:cert", db, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims, certId uint64) {
		_, err := db.Exec(`UPDATE certificates SET active = 0 WHERE id = ?`, certId)
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Failed to delete certificate")
			return
		}
		rw.WriteHeader(http.StatusAccepted)
	}))

	// Endpoint for adding/removing domains to/from a certificate
	managePutDelete := certDomainManagePUTandDELETE(db, signer, domains)
	r.GET("/cert/:id/domains", certDomainManageGET(db, signer))
	r.PUT("/cert/:id/domains", managePutDelete)
	r.DELETE("/cert/:id/domains", managePutDelete)

	// Endpoint for generating a temporary certificate for modified domains
	r.POST("/cert/:id/temp", checkAuth(signer, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		if !b.Claims.Perms.Has("orchid:cert") {
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

// getDomainOwnershipClaims returns the domains marked as owned from PermStorage,
// they match `domain:owns=<fqdn>` where fqdn will be returned
func getDomainOwnershipClaims(perms *claims.PermStorage) []string {
	a := perms.Search("domain:owns=*")
	for i := range a {
		a[i] = a[i][len("domain:owns="):]
	}
	return a
}

// validateDomainOwnershipClaims validates if the claims contain the
// `domain:owns=<fqdn>` field with the matching top level domain
func validateDomainOwnershipClaims(a string, perms *claims.PermStorage) bool {
	if fqdn, ok := vUtils.GetTopFqdn(a); ok {
		if perms.Has("domain:owns=" + fqdn) {
			return true
		}
	}
	return false
}
