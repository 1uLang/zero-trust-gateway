package logs

import (
	"github.com/1uLang/zero-trust-gateway/utils/path"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
)

func Init() {

	if viper.GetBool("debug") {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	fp, err := os.OpenFile(path.LogFile("run.logs"), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	log.SetOutput(fp)

}
