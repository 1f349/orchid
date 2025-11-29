package servers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/1f349/mjwt/auth"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/database/types"
	"github.com/1f349/orchid/logger"
	"github.com/1f349/orchid/utils"
	"github.com/gobuffalo/nulls"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
	"go4.org/netipx"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/http"
	"net/netip"
	"time"
)

type PostCertOptions struct {
	Name      string          `json:"name"`
	Authority types.Authority `json:"authority"`
	AutoRenew bool            `json:"auto_renew"`
	Subject   Subject         `json:"subject"`
	Domains   []string        `json:"domains"`
	Addresses []netip.Addr    `json:"addresses"`
}

type Subject struct {
	CommonName string `json:"common_name"` // CN - 2.5.4.3
	Country    string `json:"country"`     // C - 2.5.4.6
	Org        string `json:"org"`         // O - 2.5.4.10
	OrgUnit    string `json:"org_unit"`    // OU - 2.5.4.11
	Locality   string `json:"locality"`    // L - 2.5.4.7
	Province   string `json:"province"`    // ST - 2.5.4.8
}

func (s Subject) Validate() error {
	_, ok := dns.IsDomainName(s.CommonName)
	if !ok {
		return fmt.Errorf("invalid common name %s, expected a valid fully qualified domain name", s.CommonName)
	}
	if len(s.Country) != 0 && len(s.Country) != 2 {
		return fmt.Errorf("invalid country %s, expected 2 characters", s.Country)
	}
	return nil
}

const MaxBodySize = 1024 * 1024

type postCertQueries interface {
	AddCertificate(ctx context.Context, opts database.AddCertificateParams) (int64, error)
	AddCertificateOwner(ctx context.Context, opts database.AddCertificateOwnerParams) error
	UseTx(ctx context.Context, cb func(tx database.Queries) error) error
}

func certCreate(rw http.ResponseWriter, req *http.Request, _ httprouter.Params, b AuthClaims, db postCertQueries) {
	// Reject if content length is too large
	if req.ContentLength > MaxBodySize {
		http.Error(rw, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}

	// Limit processing to the max size
	rawBody := io.LimitReader(req.Body, MaxBodySize)

	var body PostCertOptions
	if err := json.NewDecoder(rawBody).Decode(&body); err != nil {
		http.Error(rw, "Failed to parse body", http.StatusBadRequest)
		return
	}

	if err := body.Subject.Validate(); err != nil {
		http.Error(rw, "Failed to validate subject: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !validateCertificateOptionsOwnershipClaims(body, b.Claims.Perms) {
		http.Error(rw, "User does not have permission to create certificates for the requested domains or IP addresses", http.StatusForbidden)
		return
	}

	options := database.AddCertificateParams{
		Name:       body.Name,
		Dns:        nulls.Int64{},
		NotAfter:   nulls.Time{},
		UpdatedAt:  time.Now(),
		Authority:  body.Authority,
		CommonName: body.Subject.CommonName,
		Country:    body.Subject.Country,
		Org:        body.Subject.Org,
		OrgUnit:    body.Subject.OrgUnit,
		Locality:   body.Subject.Locality,
		Province:   body.Subject.Province,
	}

	var err error
	switch body.Authority {
	case types.AuthorityLetsEncrypt:
		err = db.UseTx(req.Context(), func(tx database.Queries) error {
			id, err := db.AddCertificate(req.Context(), options)
			if err != nil {
				return err
			}
			return db.AddCertificateOwner(req.Context(), database.AddCertificateOwnerParams{
				Owner:  b.Subject,
				CertID: id,
			})
		})
	case types.AuthorityCustom:
		// TODO: Implement Custom
		http.Error(rw, "Custom authority is currently not supported", http.StatusBadRequest)
		return
	case types.AuthorityDN42:
		// TODO: Implement DN42
		http.Error(rw, "DN42 authority is currently not supported", http.StatusBadRequest)
		return
	case types.Authority(255):
		err = fmt.Errorf("database error")
	default:
		http.Error(rw, "Invalid authority", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(rw, "Failed to add certificate to the database", http.StatusInternalServerError)
		logger.Logger.Error("Failed to add certificate to the database", "err", err)
		return
	}

	http.Error(rw, "Added certificate", http.StatusOK)
}

func validateCertificateOptionsOwnershipClaims(body PostCertOptions, perms *auth.PermStorage) bool {
	if !validateDomainOwnershipClaims(body.Subject.CommonName, perms) {
		return false
	}

	for _, i := range body.Domains {
		etldPlusOne, err := publicsuffix.EffectiveTLDPlusOne(i)
		if err != nil {
			return false
		}
		if !validateDomainOwnershipClaims(etldPlusOne, perms) {
			return false
		}
	}

	// Construct the IPSet from ownership claims
	var builder netipx.IPSetBuilder
	claims := getDomainOwnershipClaims(perms)
	for _, i := range claims {
		prefix, err := utils.ParseArpaToPrefix(i)
		if err != nil {
			continue
		}
		builder.AddPrefix(prefix)
	}
	set, err := builder.IPSet()
	if err != nil {
		return false
	}

	for _, i := range body.Addresses {
		if !set.Contains(i) {
			return false
		}
	}
	return true
}
