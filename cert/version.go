// seehuhn.de/go/acme/cert - a helper to manage TLS certificates
// Copyright (C) 2020  Jochen Voss <voss@seehuhn.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cert

import (
	"runtime/debug"
)

// PackageVersion gives the acme package name and version (updated in an init
// function).
var PackageVersion = "seehuhn.de/go/acme"

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Replace != nil {
		return
	}
	PackageVersion = info.Main.Path + ", version " + info.Main.Version
}
