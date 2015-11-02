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
	"syscall"

	"github.com/vishvananda/netlink"
)

var fileOpt string
var interfaceOpt string
var typeOpt string

func init() {
	const (
		fileDefault      = ""
		fileHelp         = "path to the bpf program fd to attach"
		interfaceDefault = ""
		interfaceHelp    = "interface to assign the program to"
		typeDefault      = "ingress"
		typeHelp         = "tc qdisc type to use"
	)
	flag.StringVar(&fileOpt, "f", fileDefault, fileHelp)
	flag.StringVar(&interfaceOpt, "i", interfaceDefault, interfaceHelp)
	flag.StringVar(&typeOpt, "t", typeDefault, typeHelp)

	flag.Usage = func() {
		fmt.Printf("Usage: %s -f /run/bcc/foo/functions/bar/fd -i eth1 -t fq_codel\n", filepath.Base(os.Args[0]))
		fmt.Printf(" -i IFC  %s (default=%s)\n", interfaceHelp, interfaceDefault)
		fmt.Printf(" -f PATH %s (default=%s)\n", fileHelp, fileDefault)
		fmt.Printf(" -t TYPE %s (default=%s)\n", typeHelp, typeDefault)
	}
}

func setIngressFd(iface netlink.Link, path string) error {
	fd, err := netlink.BpfOpen(path)
	if err != nil {
		return fmt.Errorf("failed loading bpf program %v", err)
	}
	defer syscall.Close(fd)
	ingress := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
	}
	if err := netlink.QdiscAdd(ingress); err != nil {
		return fmt.Errorf("failed setting ingress qdisc: %v", err)
	}
	u32 := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    ingress.QdiscAttrs.Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId: netlink.MakeHandle(1, 1),
		BpfFd:   fd,
	}
	if err := netlink.FilterAdd(u32); err != nil {
		return fmt.Errorf("failed adding ingress filter: %v", err)
	}
	return nil
}

func setFqCodelFd(iface netlink.Link, path string) error {
	fd, err := netlink.BpfOpen(path)
	if err != nil {
		return fmt.Errorf("failed loading bpf program %v", err)
	}
	defer syscall.Close(fd)
	fq := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		QdiscType: "fq_codel",
	}
	if err := netlink.QdiscAdd(fq); err != nil {
		return fmt.Errorf("failed setting egress qdisc: %v", err)
	}
	u32 := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    fq.QdiscAttrs.Handle,
			Protocol:  syscall.ETH_P_ALL,
			//Handle:    10,
			//Priority:  10,
		},
		ClassId: netlink.MakeHandle(1, 2),
		BpfFd:   fd,
	}
	if err := netlink.FilterAdd(u32); err != nil {
		return fmt.Errorf("failed adding egress filter: %v", err)
	}
	return nil
}

func connect(path, ifcName, qType string) error {
	link, err := netlink.LinkByName(ifcName)
	if err != nil {
		return err
	}
	switch qType {
	case "ingress":
		if err := setIngressFd(link, path); err != nil {
			return err
		}
	case "fq_codel":
		if err := setFqCodelFd(link, path); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown qdisc type %s", qType)
	}
	return nil
}

func main() {
	flag.Parse()
	if fileOpt == "" || interfaceOpt == "" || typeOpt == "" {
		flag.Usage()
		os.Exit(1)
	}
	err := connect(fileOpt, interfaceOpt, typeOpt)
	if err != nil {
		fmt.Printf("failed to add tc: %s\n", err)
		os.Exit(1)
	}
}
