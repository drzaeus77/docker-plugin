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

	iov "github.com/iovisor/docker-plugin/iovplug"
)

var subnetOpt string
var socketOpt string
var interfaceOpt string
var gatewayOpt string

func init() {
	const (
		subnetDefault    = ""
		subnetHelp       = "subnet to assign the host group"
		socketDefault    = "/run/docker/plugins/iov.sock"
		socketHelp       = "docker plugin socket file"
		interfaceDefault = "eth0"
		interfaceHelp    = "interface to take ipvlans from"
		gatewayDefault   = ""
		gatewayHelp      = "default gateway ip"
	)
	flag.StringVar(&subnetOpt, "subnet", subnetDefault, subnetHelp)
	flag.StringVar(&subnetOpt, "s", subnetDefault, subnetHelp)
	flag.StringVar(&socketOpt, "socket", socketDefault, socketHelp)
	flag.StringVar(&socketOpt, "S", socketDefault, socketHelp)
	flag.StringVar(&interfaceOpt, "interface", interfaceDefault, interfaceHelp)
	flag.StringVar(&interfaceOpt, "i", interfaceDefault, interfaceHelp)
	flag.StringVar(&gatewayOpt, "gateway", gatewayDefault, gatewayHelp)
	flag.StringVar(&gatewayOpt, "g", gatewayDefault, gatewayHelp)

	flag.Usage = func() {
		fmt.Printf("Usage: %s -s 10.10.1.0/23 -i eth1\n", filepath.Base(os.Args[0]))
		fmt.Printf(" -S,--socket PATH   %s (default=%s)\n", socketHelp, socketDefault)
		fmt.Printf(" -s,--subnet NET    %s (default=%s)\n", subnetHelp, subnetDefault)
		fmt.Printf(" -i,--interface IFC %s (default=%s)\n", interfaceHelp, interfaceDefault)
		fmt.Printf(" -g,--gateway IP    %s (default=%s)\n", gatewayHelp, gatewayDefault)
	}
}

func main() {
	flag.Parse()

	config := &iov.Config{
		Subnet:    subnetOpt,
		Interface: interfaceOpt,
		Socket:    socketOpt,
		Gateway:   gatewayOpt,
	}
	iov.Run(config)
}
