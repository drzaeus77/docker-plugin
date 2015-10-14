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
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/vishvananda/netlink"
)

type driver struct {
	config     *Config
	networkID  string
	hostLink   netlink.Link
	usedIPs    map[string]string
	interfaces map[string]string
}

func NewDriver(config *Config) (*driver, error) {
	link, err := netlink.LinkByName(config.Interface)
	if err != nil {
		return nil, err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}

	// If no subnet was configured on the command line, take the first one
	// from the host interface
	if len(config.Subnet) == 0 {
		config.Subnet = addrs[0].IPNet.String()
		Debug.Printf("using interface subnet %s\n", config.Subnet)
	}

	ip, ipnet, err := net.ParseCIDR(config.Subnet)
	if err != nil {
		return nil, err
	}

	if len(config.Gateway) == 0 {
		routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			if route.Dst == nil {
				config.Gateway = route.Gw.String()
				Debug.Printf("using gateway %s\n", config.Gateway)
			}
		}
		if len(config.Gateway) == 0 {
			return nil, fmt.Errorf("cannot autoselect default gateway")
		}
	}

	d := &driver{
		config:     config,
		hostLink:   link,
		usedIPs:    make(map[string]string),
		interfaces: make(map[string]string),
	}
	d.usedIPs[ip.String()] = ""
	Debug.Printf("consuming %s\n", ip)
	d.usedIPs[ipnet.IP.String()] = ""
	Debug.Printf("consuming %s\n", ipnet.IP)
	d.usedIPs[config.Gateway] = ""
	Debug.Printf("consuming %s\n", config.Gateway)

	// Mark as provisioned the IPs owned by the host interface
	for _, addr := range addrs {
		if ipnet.Contains(addr.IP) {
			d.usedIPs[addr.IP.String()] = ""
			Debug.Printf("consuming %s\n", addr.IP)
		}
	}
	return d, nil
}

type createNetworkRequest struct {
	NetworkID string
	Options   map[string]interface{}
}

func (d *driver) createNetwork(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}

	if len(d.networkID) != 0 {
		panic(fmt.Errorf("driver already has a network defined"))
	}

	d.networkID = req.NetworkID
	Debug.Println("driver.createNetwork", req.NetworkID, req.Options)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{}`)
}

type deleteNetworkRequest struct {
	NetworkID string
}

func (d *driver) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	var req deleteNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}

	if req.NetworkID != d.networkID {
		panic(fmt.Errorf("no network with ID %s", req.NetworkID))
	}

	d.networkID = ""

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{}`)
}

type endpoint struct {
	Address     string
	AddressIPv6 string
	MacAddress  string
}

func (ifc *endpoint) String() string {
	b, _ := json.Marshal(ifc)
	return string(b)
}

type createEndpointRequest struct {
	NetworkID  string
	EndpointID string
	Interface  *endpoint
	Options    map[string]interface{}
}

func (req *createEndpointRequest) String() string {
	b, _ := json.Marshal(req)
	return string(b)
}

type endpointResponse struct {
	Interface *endpoint
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

func (d *driver) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var req createEndpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	Debug.Printf("driver.createEndoint %s\n", &req)

	if req.NetworkID != d.networkID {
		panic(fmt.Errorf("no network with ID %s", req.NetworkID))
	}

	ip, ipnet, err := net.ParseCIDR(d.config.Subnet)
	if err != nil {
		panic(err)
	}
	var newIP net.IPNet
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		if _, ok := d.usedIPs[ip.String()]; !ok {
			newIP.IP = ip
			newIP.Mask = ipnet.Mask
			break
		}
	}
	if newIP.IP == nil {
		panic(fmt.Errorf("unable to allocate IP in subnet"))
	}

	d.interfaces[req.EndpointID] = newIP.IP.String()
	d.usedIPs[newIP.IP.String()] = req.EndpointID
	Info.Printf("new IP %s\n", newIP.IP)

	resp := &endpointResponse{
		Interface: &endpoint{
			Address: newIP.String(),
		},
	}
	Info.Printf("return Address: %s\n", newIP.String())

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		panic(err)
	}
}

type endpointRequest struct {
	NetworkID  string
	EndpointID string
}

func (req *endpointRequest) String() string {
	b, _ := json.Marshal(req)
	return string(b)
}

func (d *driver) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var req endpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}

	ip, ok := d.interfaces[req.EndpointID]
	if !ok {
		panic(fmt.Errorf("cannot find endpoint %s", req.EndpointID))
	}

	defer delete(d.interfaces, req.EndpointID)
	defer delete(d.usedIPs, ip)

	Debug.Printf("driver.deleteEndpoint %s\n", &req)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{}`)
}

func (d *driver) endpointOperInfo(w http.ResponseWriter, r *http.Request) {
	var req endpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}

	if _, ok := d.interfaces[req.EndpointID]; !ok {
		panic(fmt.Errorf("cannot find endpoint %s", req.EndpointID))
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"Value": {}}`)
}

type joinRequest struct {
	NetworkID  string
	EndpointID string
	SandboxKey string
	Options    map[string]interface{}
}

type staticRoute struct {
	Destination string
	RouteType   int
	NextHop     string
}

type interfaceName struct {
	SrcName   string
	DstName   string
	DstPrefix string
}

type joinResponse struct {
	Gateway       string
	InterfaceName *interfaceName
	StaticRoutes  []*staticRoute
}

func (d *driver) join(w http.ResponseWriter, r *http.Request) {
	var req joinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(err)
	}
	if _, ok := d.interfaces[req.EndpointID]; !ok {
		panic(fmt.Errorf("cannot find endpoint %s", req.EndpointID))
	}

	newLink := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        req.EndpointID[:5],
			ParentIndex: d.hostLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}
	if err := netlink.LinkAdd(newLink); err != nil {
		panic(err)
	}
	if err := netlink.LinkSetUp(newLink); err != nil {
		panic(err)
	}
	resp := &joinResponse{
		InterfaceName: &interfaceName{
			SrcName:   newLink.Name,
			DstPrefix: "eth",
		},
		Gateway: d.config.Gateway,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		panic(err)
	}
}

func (d *driver) leave(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{}`)
}

func (d *driver) activate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"Implements": ["NetworkDriver"]}`)
}

func (d *driver) capabilities(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"Scope": "local"}`)
}
