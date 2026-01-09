package config

import (
	"fmt"
	"reflect"
	"sort"
)

func unknownKeys(doc map[string]any, t reflect.Type, prefix string) []string {
	fields := make(map[string]reflect.Type, t.NumField())
	for i := range t.NumField() {
		f := t.Field(i)
		fields[f.Tag.Get("zog")] = f.Type
	}
	var unknown []string
	for key, value := range doc {
		ft, ok := fields[key]
		if !ok {
			unknown = append(unknown, prefix+key)
			continue
		}
		switch {
		case ft.Kind() == reflect.Struct:
			if nested, ok := value.(map[string]any); ok {
				unknown = append(unknown, unknownKeys(nested, ft, prefix+key+".")...)
			}
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct:
			items, _ := value.([]any)
			for i, item := range items {
				if nested, ok := item.(map[string]any); ok {
					unknown = append(unknown, unknownKeys(nested, ft.Elem(), fmt.Sprintf("%s%s[%d].", prefix, key, i))...)
				}
			}
		}
	}
	sort.Strings(unknown)
	return unknown
}
