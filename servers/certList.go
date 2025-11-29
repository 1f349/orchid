package servers

import (
	"context"
	"encoding/json"
	"github.com/1f349/orchid/database"
	"github.com/1f349/orchid/logger"
	"github.com/julienschmidt/httprouter"
	"net/http"
	"slices"
)

func certList(rw http.ResponseWriter, _ *http.Request, _ httprouter.Params, b AuthClaims, db *database.Queries) {
	// query database
	rows, err := db.FindOwnedCerts(context.Background(), b.Subject)
	if err != nil {
		logger.Logger.Info("Failed after reading certificates from database:", "err", err)
		http.Error(rw, "Database Error", http.StatusInternalServerError)
		return
	}

	m := make(map[int64]*Certificate) // certificates owned by this user

	// loop over query rows
	for _, row := range rows {
		c := Certificate{
			Id:         row.ID,
			Name:       row.Name,
			Authority:  row.Authority,
			AutoRenew:  row.AutoRenew,
			Active:     row.Active,
			Renewing:   row.Renewing,
			RenewRetry: row.RenewRetry.Time,
			NotAfter:   row.NotAfter.Time,
			UpdatedAt:  row.UpdatedAt,
			Subject: Subject{
				CommonName: row.CommonName,
				Country:    row.Country,
				Org:        row.Org,
				OrgUnit:    row.OrgUnit,
				Locality:   row.Locality,
				Province:   row.Province,
			},
		}
		d := row.Domain

		// check in owned map
		if cert, ok := m[c.Id]; ok && d.Valid {
			cert.Domains = append(cert.Domains, d.String)
			continue
		}

		// add to other and main if owned
		c.Domains = []string{}
		if d.Valid {
			c.Domains = append(c.Domains, d.String)
		}
		m[c.Id] = &c
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
