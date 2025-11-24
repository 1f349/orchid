package servers

import (
	"context"
	"encoding/json"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/logger"
	vUtils "github.com/1f349/violet/utils"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"slices"
)

func certList(rw http.ResponseWriter, _ *http.Request, _ httprouter.Params, b AuthClaims, db *database.Queries) {
	domains := getDomainOwnershipClaims(b.Claims.Perms)
	domainMap := make(map[string]bool)
	for _, i := range domains {
		domainMap[i] = true
	}

	// query database
	rows, err := db.FindOwnedCerts(context.Background())
	if err != nil {
		logger.Logger.Info("Failed after reading certificates from database:", "err", err)
		http.Error(rw, "Database Error", http.StatusInternalServerError)
		return
	}

	// TODO(melon): rewrite this endpoint to prevent using a map then converting into a slice later
	mOther := make(map[int64]*Certificate) // other certificates
	m := make(map[int64]*Certificate)      // certificates owned by this user

	// loop over query rows
	for _, row := range rows {
		c := Certificate{
			Id:         row.ID,
			Authority:  row.Authority,
			AutoRenew:  row.AutoRenew,
			Active:     row.Active,
			Renewing:   row.Renewing,
			RenewRetry: row.RenewRetry.Time,
			NotAfter:   row.NotAfter.Time,
			UpdatedAt:  row.UpdatedAt,
		}
		d := row.Domain

		// check in owned map
		if cert, ok := m[c.Id]; ok {
			cert.Domains = append(cert.Domains, d)
			continue
		}

		// get etld+1
		topFqdn, found := vUtils.GetTopFqdn(d)
		if !found {
			logger.Logger.Info("Invalid domain found:", "domain", d)
			http.Error(rw, "Database Error", http.StatusInternalServerError)
			return
		}

		// if found in other, add domain and put in main if owned
		if cert, ok := mOther[c.Id]; ok {
			cert.Domains = append(cert.Domains, d)
			if domainMap[topFqdn] {
				m[c.Id] = cert
			}
			continue
		}

		// add to other and main if owned
		c.Domains = []string{d}
		mOther[c.Id] = &c
		if domainMap[topFqdn] {
			m[c.Id] = &c
		}
	}

	// remap into a slice
	arr := make([]*Certificate, 0, len(m))
	slices.SortFunc(arr, func(a, b *Certificate) int {
		return int(a.Id - b.Id)
	})
	for _, v := range m {
		arr = append(arr, v)
	}

	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(arr)
}
