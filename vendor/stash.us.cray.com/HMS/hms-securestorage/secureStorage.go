// Copyright 2019 Cray Inc. All Rights Reserved.

package securestorage

type SecureStorage interface {
	Store(key string, value interface{}) error
	Lookup(key string, output interface{}) error
	Delete(key string) error
	LookupKeys(keyPath string) ([]string, error)
}
