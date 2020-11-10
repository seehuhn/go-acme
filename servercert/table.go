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
