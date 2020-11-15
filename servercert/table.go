// seehuhn.de/go/acme/servercert - renew and manage server certificates
// Copyright (C) 2020  Jochen Voss
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

package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type table struct {
	header []string
	rows   [][]string
}

func (T *table) SetHeader(names ...string) {
	T.header = names
}

func (T *table) AddRow(row ...string) {
	T.rows = append(T.rows, row)
}

func (T *table) Show() {
	ww := make([]int, len(T.header))
	for i, name := range T.header {
		ww[i] = utf8.RuneCountInString(name)
	}
	for _, row := range T.rows {
		for i, text := range row {
			w := utf8.RuneCountInString(text)
			if w > ww[i] {
				ww[i] = w
			}
		}
	}

	parts := make([]string, len(ww))
	for i, text := range T.header {
		parts[i] = fmt.Sprintf("%-*s", ww[i], text)
	}
	fmt.Println(strings.Join(parts, " | "))
	for i, w := range ww {
		parts[i] = strings.Repeat("-", w)
	}
	fmt.Println(strings.Join(parts, "-+-"))
	for _, row := range T.rows {
		for i, text := range row {
			parts[i] = fmt.Sprintf("%-*s", ww[i], text)
		}
		fmt.Println(strings.Join(parts, " | "))
	}
}
