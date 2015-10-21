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

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

var fileOpt string
var interfaceOpt string

func init() {
	const (
		fileDefault      = ""
		fileHelp         = "path to the bpf program fd to attach"
		interfaceDefault = ""
		interfaceHelp    = "interface to assign the program to"
	)
	flag.StringVar(&fileOpt, "f", fileDefault, fileHelp)
	flag.StringVar(&interfaceOpt, "i", interfaceDefault, interfaceHelp)

	flag.Usage = func() {
		fmt.Printf("Usage: %s -f /run/bcc/foo/functions/bar/fd -i eth1\n", filepath.Base(os.Args[0]))
		fmt.Printf(" -i IFC  %s (default=%s)\n", interfaceHelp, interfaceDefault)
		fmt.Printf(" -f PATH %s (default=%s)\n", fileHelp, fileDefault)
	}
}

func main() {
	flag.Parse()
}
