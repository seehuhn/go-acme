package cert

import (
	"runtime/debug"
)

var packageVersion = "seehuhn.de/go/letsencrypt"

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Replace != nil {
		return
	}
	packageVersion = info.Main.Path + ", version " + info.Main.Version
}
