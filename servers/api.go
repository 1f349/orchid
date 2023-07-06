package servers

import (
	"github.com/MrMelon54/mjwt"
	"github.com/MrMelon54/mjwt/auth"
	oUtils "github.com/MrMelon54/orchid/utils"
	vUtils "github.com/MrMelon54/violet/utils"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"time"
)

// NewApiServer creates and runs a http server containing all the API
// endpoints for the software
//
// `/cert` - edit certificate
func NewApiServer(listen string, signer mjwt.Verifier, domains oUtils.DomainChecker) *http.Server {
	r := httprouter.New()

	// Endpoint for adding a certificate
	r.POST("/cert", func(rw http.ResponseWriter, req *http.Request, params httprouter.Params) {
		// TODO: register domains to a certificate
		vUtils.RespondVioletError(rw, http.StatusNotImplemented, "API unavailable")
		rw.WriteHeader(http.StatusNotImplemented)
		return

		if !hasPerms(signer, req, "orchid:cert:") {
			vUtils.RespondHttpStatus(rw, http.StatusForbidden)
			return
		}
		domain := params.ByName("domain")
		if !domains.ValidateDomain(domain) {
			vUtils.RespondVioletError(rw, http.StatusBadRequest, "Invalid domain")
			return
		}
		rw.WriteHeader(http.StatusAccepted)
	})

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

func hasPerms(verify mjwt.Verifier, req *http.Request, perm string) bool {
	// Get bearer token
	bearer := vUtils.GetBearer(req)
	if bearer == "" {
		return false
	}

	// Read claims from mjwt
	_, b, err := mjwt.ExtractClaims[auth.AccessTokenClaims](verify, bearer)
	if err != nil {
		return false
	}

	// Token must have perm
	return b.Claims.Perms.Has(perm)
}
