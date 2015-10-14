// Copyright 2015 PLUMgrid
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iovplug

import (
	"os"
	"path/filepath"
)

func sockInit(sockPath string) error {
	if err := os.MkdirAll(filepath.Dir(sockPath), 0755); err != nil && !os.IsExist(err) {
		Error.Println(err.Error())
		return err
	}
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		Error.Println(err.Error())
		return err
	}
	return nil
}

func sockClean(sockPath string) error {
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		Error.Println(err.Error())
		return err
	}
	return nil
}
