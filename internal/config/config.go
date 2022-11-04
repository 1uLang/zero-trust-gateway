package config

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
)

const defaultConfigFile = "config.yaml"

// Init Read config values
func Init(cfgFile string) {
	if cfgFile != "" {
		// Use config file path provided by the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// User default config file located inside the same dir as the executable
		exePath, err := os.Executable()
		if err != nil {
			panic(err)
		}

		viper.AddConfigPath(filepath.Dir(exePath))
		viper.SetConfigFile(defaultConfigFile)
	}

	if err := viper.ReadInConfig(); err != nil {
		log.Error("failed to read config")
		log.Error(err)
		os.Exit(-1)
	}
}
