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
	"net"
	"net/http"
	"runtime"
)

func init() {
	logInit()
}

func makeHandler(fn http.HandlerFunc, methods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Info.Printf("%s %s\n", r.Method, r.URL)
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(runtime.Error); ok {
					panic(r)
				}
				err := r.(error)
				Error.Println(err.Error())
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
		}()

		for _, method := range methods {
			if r.Method == method {
				fn(w, r)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
}

func Run(config *Config) error {
	d, err := NewDriver(config)
	if err != nil {
		Error.Fatalf(err.Error())
	}

	sockInit(config.Socket)
	defer sockClean(config.Socket)

	Info.Println("IOVisor Docker Plugin starting...")
	http.HandleFunc("/Plugin.Activate", makeHandler(d.activate, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.GetCapabilities", makeHandler(d.capabilities, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.CreateNetwork", makeHandler(d.createNetwork, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.DeleteNetwork", makeHandler(d.deleteNetwork, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.CreateEndpoint", makeHandler(d.createEndpoint, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.DeleteEndpoint", makeHandler(d.deleteEndpoint, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.EndpointOperInfo", makeHandler(d.endpointOperInfo, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.Join", makeHandler(d.join, []string{"POST"}))
	http.HandleFunc("/NetworkDriver.Leave", makeHandler(d.leave, []string{"POST"}))

	var listener net.Listener
	if listener, err = net.Listen("unix", d.config.Socket); err != nil {
		Error.Fatalf("%s", err.Error())
	}

	return http.Serve(listener, nil)
}
