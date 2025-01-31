package utils

import "fmt"

func GetCertFileName(id int64) string {
	return fmt.Sprintf("%d.cert.pem", id)
}

func GetOldCertFileName(id int64) string {
	return fmt.Sprintf("%d-old.cert.pem", id)
}

func GetKeyFileName(id int64) string {
	return fmt.Sprintf("%d.key.pem", id)
}
