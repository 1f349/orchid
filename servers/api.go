package servers

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/1f349/mjwt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/database/types"
	oUtils "github.com/1f349/orchid/utils"
	vUtils "github.com/1f349/violet/utils"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

type DomainStateValue struct {
	Domain string `json:"domain"`
	State  int    `json:"state"`
}

type Certificate struct {
	Id         int64           `json:"id"`
	Name       string          `json:"name"`
	Authority  types.Authority `json:"authority"`
	AutoRenew  bool            `json:"auto_renew"`
	Active     bool            `json:"active"`
	Renewing   bool            `json:"renewing"`
	RenewRetry time.Time       `json:"renew_retry"`
	NotAfter   time.Time       `json:"not_after"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Domains    []string        `json:"domains"`
	Addresses  []netip.Addr    `json:"addresses"`
	Subject    Subject         `json:"subject"`
}

// NewApiServer creates and runs a http server containing all the API
// endpoints for the software
//
// `/cert` - edit certificate
func NewApiServer(listen string, db *database.Queries, signer *mjwt.KeyStore, domains oUtils.DomainChecker) *http.Server {
	r := httprouter.New()

	r.GET("/", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		http.Error(rw, "Orchid API Endpoint", http.StatusOK)
	})

	// Endpoint for grabbing owned certificates
	// TODO(melon): support legacy /owned route for now, but remove later
	r.GET("/owned", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		certList(rw, req, params, b, db)
	}))
	r.GET("/certs", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		certList(rw, req, params, b, db)
	}))

	// Endpoint for looking up a certificate
	r.GET("/lookup/:domain", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		domain := params.ByName("domain")
		if !domains.ValidateDomain(domain) {
			vUtils.RespondVioletError(rw, http.StatusBadRequest, "Invalid domain")
			return
		}
	}))

	r.POST("/certs", checkAuthWithPerm(signer, "orchid:cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims) {
		certCreate(rw, req, params, b, db)
	}))
	r.DELETE("/certs/:id", checkAuthForCertificate(signer, "orchid:cert", db, func(rw http.ResponseWriter, req *http.Request, params httprouter.Params, b AuthClaims, certId int64) {
		err := db.RemoveCertificate(req.Context(), certId)
		if err != nil {
			apiError(rw, http.StatusInternalServerError, "Failed to delete certificate")
			return
		}
		http.Error(rw, "Removed certificate", http.StatusAccepted)
	}))

	// Endpoint for adding/removing domains to/from a certificate
	// TODO: Potentially enable domain management later?
	//managePutDelete := certDomainManagePUTandDELETE(db, signer, domains)
	//r.GET("/cert/:id/domains", certDomainManageGET(db, signer))
	//r.PUT("/cert/:id/domains", managePutDelete)
	//r.DELETE("/cert/:id/domains", managePutDelete)

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
func checkCertOwner(db *database.Queries, idStr string, b AuthClaims) (int64, error) {
	// parse the id
	rawId, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, err
	}

	// run database query
	row, err := db.CheckCertOwner(context.Background(), database.CheckCertOwnerParams{ID: int64(rawId), Owner: b.Subject})
	if err != nil {
		return 0, err
	}

	// check the owner is the mjwt token subject
	if row == 0 {
		return 0, fmt.Errorf("not the certificate owner")
	}

	// it's all valid, return the values
	return row, nil
}

// getDomainOwnershipClaims returns the domains marked as owned from PermStorage,
// they match `domain:owns=<fqdn>` where fqdn will be returned
func getDomainOwnershipClaims(perms *auth.PermStorage) []string {
	a := perms.Search("domain:owns=*")
	for i := range a {
		a[i] = a[i][len("domain:owns="):]
	}
	return a
}

// validateDomainOwnershipClaims validates if the claims contain the
// `domain:owns=<fqdn>` field with the matching top level domain
func validateDomainOwnershipClaims(a string, perms *auth.PermStorage) bool {
	if fqdn, ok := vUtils.GetTopFqdn(a); ok {
		if perms.Has("domain:owns=" + fqdn) {
			return true
		}
	}
	return false
}
