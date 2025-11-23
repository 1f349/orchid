package servers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/1f349/orchid/logger"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/database/types"
	"github.com/gobuffalo/nulls"
	"github.com/julienschmidt/httprouter"
	"github.com/miekg/dns"
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
	if len(s.Country) != 2 {
		return fmt.Errorf("invalid country %s, expected 2 characters", s.Country)
	}
	return nil
}

const MaxBodySize = 1024 * 1024

type postCertQueries interface {
	AddCertificate(ctx context.Context, opts database.AddCertificateParams) error
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
	dec := json.NewDecoder(rawBody)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(rw, "Failed to parse body", http.StatusBadRequest)
		return
	}

	if err := body.Subject.Validate(); err != nil {
		http.Error(rw, "Failed to validate subject: "+err.Error(), http.StatusBadRequest)
		return
	}

	options := database.AddCertificateParams{
		Owner:      b.Subject,
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
		err = db.AddCertificate(req.Context(), options)
	case types.AuthorityCustom:
		// TODO: Implement Custom
		http.Error(rw, "Custom authority is currently not supported", http.StatusBadRequest)
		return
	case types.AuthorityDN42:
		// TODO: Implement DN42
		http.Error(rw, "DN42 authority is currently not supported", http.StatusBadRequest)
		return
	default:
		http.Error(rw, "Invalid authority", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(rw, "Failed to add certificate to the database", http.StatusBadRequest)
		logger.Logger.Error("Failed to add certificate to the database", "err", err)
		return
	}

	http.Error(rw, "Added certificate", http.StatusAccepted)
}
