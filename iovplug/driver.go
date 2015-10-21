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
	"io/ioutil"
	"net"
	"net/http"
	"strconv"

	"github.com/vishvananda/netlink"
)

type driver struct {
	config     *Config
	networkID  string
	hostLink   netlink.Link
	ip         net.IP
	ipnet      *net.IPNet
	interfaces map[string][]net.IP
	iom        *ioModuleClient
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
	}

	ip, ipnet, err := net.ParseCIDR(config.Subnet)
	if err != nil {
		return nil, err
	}

	d := &driver{
		config:     config,
		ip:         ip,
		ipnet:      ipnet,
		hostLink:   link,
		interfaces: make(map[string][]net.IP),
	}

	//d.iom = &ioModuleClient{
	//	client:  &http.Client{},
	//	baseUrl: "http://localhost:5000",
	//}
	//if err := d.iom.discover(); err != nil {
	//	return nil, err
	//}

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

	route := &netlink.Route{
		LinkIndex: d.hostLink.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       d.ipnet,
	}
	if err := netlink.RouteAdd(route); err != nil {
		panic(err)
	}

	//d.iom.createIOModule(&req)

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

	route := &netlink.Route{
		LinkIndex: d.hostLink.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       d.ipnet,
	}
	if err := netlink.RouteDel(route); err != nil {
		Warn.Printf("RouteDel failed: %s\n", err.Error())
	}

	d.networkID = ""
	//d.iom.deleteIOModule(&req)

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

func endpointToLink(endpointID string) string {
	return endpointID[:5]
}

func tagFromEndpointOptions(options map[string]interface{}) string {
	obj, ok := options["com.docker.network.endpoint.exposedports"]
	if !ok {
		return ""
	}

	exposedPorts, ok := obj.([]interface{})
	if !ok {
		return ""
	}

	Debug.Printf("parsing exposedports list %v\n", exposedPorts)
	for _, obj := range exposedPorts {
		exposedPort, ok := obj.(map[string]interface{})
		if !ok {
			continue
		}
		port, ok := exposedPort["Port"]
		if !ok {
			continue
		}
		if val, ok := port.(float64); ok {
			return strconv.Itoa(int(val))
		}
	}
	return ""
}

func ipsFromEndpointRequest(req *createEndpointRequest) (ip4 net.IP, ip6 net.IP) {
	if req.Interface.Address != "" {
		ip, _, err := net.ParseCIDR(req.Interface.Address)
		if err != nil {
			panic(err)
		}
		if ip.To4() == nil {
			panic(fmt.Errorf("expected v4 address"))
		}
		ip4 = ip.To4()
	}
	if req.Interface.AddressIPv6 != "" {
		ip, _, err := net.ParseCIDR(req.Interface.AddressIPv6)
		if err != nil {
			panic(err)
		}
		if ip.To16() == nil {
			panic(fmt.Errorf("expected v6 address"))
		}
		ip6 = ip.To16()
	}
	return
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

	ip4, ip6 := ipsFromEndpointRequest(&req)

	if tag := tagFromEndpointOptions(req.Options); tag != "" {
		Debug.Printf("set ip2grp %s -> %d\n", req.Interface.Address, tag)
		file := fmt.Sprintf("/run/bcc/foo/maps/ip2grp/{ 0x%02x%02x%02x%02x 0x0  }",
			ip4[0], ip4[1], ip4[2], ip4[3])
		if err := ioutil.WriteFile(file, []byte(tag), 0644); err != nil {
			panic(err)
		}
	}

	ips := []net.IP{ip4, ip6}
	d.interfaces[req.EndpointID] = ips

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"Value": {}}`)
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
	Debug.Printf("driver.deleteEndpoint %s\n", &req)

	_, ok := d.interfaces[req.EndpointID]
	if !ok {
		panic(fmt.Errorf("cannot find endpoint %s", req.EndpointID))
	}

	linkName := endpointToLink(req.EndpointID)

	defer delete(d.interfaces, req.EndpointID)

	if link, err := netlink.LinkByName(linkName); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			Warn.Printf("unable to cleanup link %s while deleting endpoint", linkName)
		}
	} else {
		Warn.Printf("unable to find link %s while deleting endpoint", linkName)
	}

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

type moduleData struct {
	modType     string `json:"module_type"`
	displayName string `json:"display_name"`
	config      string `json:"config"`
}

// Called when the container actually needs the endpoint, create the virtual
// device now
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
			Name:        endpointToLink(req.EndpointID),
			ParentIndex: d.hostLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L3,
	}
	if err := netlink.LinkAdd(newLink); err != nil {
		panic(err)
	}
	Debug.Printf("link added, index %d\n", newLink.Index)

	if err := netlink.LinkSetUp(newLink); err != nil {
		panic(err)
	}

	//d.iom.connectLink(d.networkID, newLink.Name)

	resp := &joinResponse{
		InterfaceName: &interfaceName{
			SrcName:   newLink.Name,
			DstPrefix: "eth",
		},
		// uncomment for L3 mode
		StaticRoutes: []*staticRoute{
			&staticRoute{
				Destination: "0.0.0.0/0",
				RouteType:   1,
				NextHop:     "",
			},
		},
	}
	if len(d.config.Gateway) > 0 {
		resp.Gateway = d.config.Gateway
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
