// Copyright 2020 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// sensorfetcher application
// For documentation on how to setup and run the application see:
// https://github.com/netsec-ethz/scion-apps/blob/master/README.md
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func main() {
	serverAddrStr := flag.String("s", "", "Server address (<ISD-AS,[IP]:port> or <hostname:port>)")
	interactive := flag.Bool("i", false, "Interactive path selection, prompt to choose path")
	sequence := flag.String("sequence", "", "Sequence of space separated hop predicates to specify path")
	preference := flag.String("preference", "", "Preference sorting order for paths. "+
		"Comma-separated list of available sorting options: "+
		strings.Join(pan.AvailablePreferencePolicies, "|"))

	flag.Parse()

	if len(*serverAddrStr) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	policy, err := pan.PolicyFromCommandline(*sequence, *preference, *interactive)
	check(err)
	serverAddr, err := pan.ResolveUDPAddr(context.TODO(), *serverAddrStr)
	check(err)
	conn, err := pan.DialUDP(context.Background(), netip.AddrPort{}, serverAddr, pan.WithPolicy(policy))
	check(err)

	receivePacketBuffer := make([]byte, 2500)
	sendPacketBuffer := make([]byte, 0)

	_, err = conn.Write(sendPacketBuffer)
	check(err)

	n, err := conn.Read(receivePacketBuffer)
	check(err)

	fmt.Print(string(receivePacketBuffer[:n]))
}
