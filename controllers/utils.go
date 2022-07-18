package controllers

import (
	"os"
	"path/filepath"
)

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func GetInstanceLabels(name string) map[string]string {
	return map[string]string{
		labelsName:      name,
		labelsCreatedBy: filepath.Base(os.Args[0]),
	}
}
