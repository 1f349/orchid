package utils

import "fmt"

func GetCertFileName(id int64, commonName string) string {
	return fmt.Sprintf("%d-%s.crt", id, commonName)
}

func GetOldCertFileName(id int64, commonName string) string {
	return fmt.Sprintf("%d-%s.old.crt", id, commonName)
}

func GetKeyFileName(id int64, commonName string) string {
	return fmt.Sprintf("%d-%s.key", id, commonName)
}
