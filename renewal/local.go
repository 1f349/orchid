package renewal

// Contains local types for the renewal service
type localCertData struct {
	id         int64
	domains    []string
	commonName string
}
