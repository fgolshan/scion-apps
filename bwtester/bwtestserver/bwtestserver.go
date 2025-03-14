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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/netsec-ethz/scion-apps/bwtester/bwtest"
	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

const (
	resultExpiry          = time.Minute
	SelectorLossThreshold = 10.0
)

func main() {
	var listen pan.IPPortValue
	kingpin.Flag("listen", "Address to listen on").Default(":40002").SetValue(&listen)
	kingpin.Parse()

	err := runServer(listen.Get())
	bwtest.Check(err)
}

func runServer(listen netip.AddrPort) error {
	receivePacketBuffer := make([]byte, 2500)

	var currentBwtest string
	var currentBwtestFinish time.Time
	// currentLossMetrics holds the active test's LossMetrics instance.
	var currentLossMetrics *bwtest.LossMetrics
	// currentLossUpdatesStopChan is used to stop loss update sending.
	var currentLossUpdatesStopChan chan struct{}

	currentResult := make(chan bwtest.Result)
	results := make(resultsMap)

	ctx := context.Background()
	ccSelector := pan.NewDefaultReplySelector()
	ccConn, err := pan.ListenUDP(context.Background(), listen, pan.WithReplySelector(ccSelector))
	if err != nil {
		return err
	}
	serverCCAddr := ccConn.LocalAddr().(pan.UDPAddr)

	for {
		// Check if a result from a background bwtest is available.
		select {
		case res := <-currentResult:
			// Before inserting the result, stop sending loss updates.
			if currentLossUpdatesStopChan != nil {
				close(currentLossUpdatesStopChan)
				currentLossUpdatesStopChan = nil
			}
			results.insert(currentBwtest, res)
			// Reset the current test state.
			currentBwtest = ""
			currentBwtestFinish = time.Time{}
			currentLossMetrics = nil
		default:
		}

		n, clientCCAddr, err := ccConn.ReadFrom(receivePacketBuffer)
		if err != nil {
			return err
		}
		if n < 1 {
			continue
		}
		request := receivePacketBuffer[:n]
		clientCCAddrStr := clientCCAddr.String()
		fmt.Println("Received request:", string(request[0]), clientCCAddrStr)

		switch request[0] {
		case 'L':
			// Process a loss metrics update message.
			if clientCCAddrStr == currentBwtest && currentLossMetrics != nil {
				if ctr, err := currentLossMetrics.ProcessRemoteUpdate(request); err != nil {
					fmt.Printf("Error processing loss update from %s: %v\n", clientCCAddrStr, err)
				} else {
					fmt.Printf("Processed loss update (counter: %d) from %s\n", ctr, clientCCAddrStr)
				}
			} else {
				fmt.Printf("Received loss update from %s, but no active test found.\n", clientCCAddrStr)
			}
			continue

		case 'N':
			// New bwtest request.
			if currentBwtest != "" {
				fmt.Println("A bwtest is already ongoing", currentBwtest)
				if clientCCAddrStr == currentBwtest {
					// Same client: re-send success response.
					fmt.Println("clientCCAddrStr == currentBwtest")
					writeResponseN(ccConn, clientCCAddr, 0)
				} else {
					// Another client: send remaining duration.
					writeResponseN(ccConn, clientCCAddr, retryWaitTime(currentBwtestFinish))
				}
				continue
			}

			// Decode the parameters.
			clientBwp, serverBwp, err := decodeRequestN(request)
			if err != nil {
				continue
			}
			// Obtain the path from the selector.
			path := ccSelector.Path(ctx, clientCCAddr.(pan.UDPAddr))
			// Start the bwtest in background, which returns finishTime and the LossMetrics instance.
			finishTime, lossMet, err := startBwtestBackground(serverCCAddr, clientCCAddr.(pan.UDPAddr), path,
				clientBwp, serverBwp, currentResult)
			if err != nil {
				// Ask the client to try again in 1 second.
				writeResponseN(ccConn, clientCCAddr, 1)
				continue
			}
			// Save current state.
			currentBwtest = clientCCAddrStr
			currentBwtestFinish = finishTime
			currentLossMetrics = lossMet

			// Start sending loss update messages.
			currentLossUpdatesStopChan = make(chan struct{})
			measurementInterval := bwtest.LossMetricsMeasurementInterval
			expectedRate := float64(clientBwp.NumPackets) / clientBwp.BwtestDuration.Seconds()
			expectedPerInterval := expectedRate * measurementInterval.Seconds()

			sendFunc := func(msg []byte) error {
				_, err := ccConn.WriteTo(msg, clientCCAddr)
				return err
			}

			// When using a LossAwareSelector for the server as well, can use its wouldSwitch method.
			wouldSwitch := func(lossWindow []float32) bool {
				if len(lossWindow) == 0 {
					return false
				}
				var sum float64
				for _, loss := range lossWindow {
					sum += float64(loss)
				}
				avgLoss := sum / float64(len(lossWindow))
				return avgLoss > SelectorLossThreshold
			}
			currentLossMetrics.StartSendingUpdates(bwtest.LossMetricsUpdateInterval, expectedPerInterval, wouldSwitch, sendFunc, currentLossUpdatesStopChan)

			writeResponseN(ccConn, clientCCAddr, 0)

		case 'R':
			// Request for results.
			if clientCCAddrStr == currentBwtest {
				// Test still ongoing; reply with remaining time.
				writeResponseR(ccConn, clientCCAddr, retryWaitTime(currentBwtestFinish), nil)
				continue
			}
			v, ok := results[clientCCAddrStr]
			if !ok || !bytes.Equal(v.PrgKey, request[1:]) {
				writeResponseR(ccConn, clientCCAddr, 127, nil)
				continue
			}
			writeResponseR(ccConn, clientCCAddr, 0, &v.Result)

		default:
			continue
		}
	}
}

// startBwtestBackground starts a bandwidth test, in the background.
// Returns the expected finish time of the test, or any error during the setup.
func startBwtestBackground(serverCCAddr pan.UDPAddr, clientCCAddr pan.UDPAddr,
	path *pan.Path, clientBwp, serverBwp bwtest.Parameters, res chan<- bwtest.Result) (time.Time, *bwtest.LossMetrics, error) {

	// Data Connection addresses:
	clientDCAddr := clientCCAddr
	clientDCAddr.Port = clientBwp.Port
	serverDCAddr := netip.AddrPortFrom(serverCCAddr.IP, serverBwp.Port)

	// Open Data Connection
	dcSelector := initializedReplySelector(clientDCAddr, path)
	dcConn, err := listenConnected(serverDCAddr, clientDCAddr, dcSelector)
	if err != nil {
		return time.Time{}, nil, err
	}

	now := time.Now()
	finishTimeSend := now.Add(serverBwp.BwtestDuration + bwtest.GracePeriodSend)
	finishTimeReceive := now.Add(clientBwp.BwtestDuration + bwtest.StragglerWaitPeriod)
	finishTime := finishTimeReceive
	if finishTime.Before(finishTimeSend) {
		finishTime = finishTimeSend
	}
	if err := dcConn.SetReadDeadline(finishTimeReceive); err != nil {
		dcConn.Close()
		return time.Time{}, nil, err
	}
	if err := dcConn.SetWriteDeadline(finishTimeSend); err != nil {
		dcConn.Close()
		return time.Time{}, nil, err
	}

	// --- Set up loss metrics for incoming packets (client -> server) ---
	lossMetrics := bwtest.NewLossMetrics(bwtest.LossMetricsWindowSize)
	measurementInterval := bwtest.LossMetricsMeasurementInterval
	expectedRate := float64(clientBwp.NumPackets) / clientBwp.BwtestDuration.Seconds()
	expectedPerInterval := expectedRate * measurementInterval.Seconds()
	stopChan := make(chan struct{})
	lossMetrics.StartMonitoring(measurementInterval, expectedPerInterval, stopChan)

	sendDone := make(chan struct{})
	go func() {
		_ = bwtest.HandleDCConnSend(serverBwp, dcConn)
		close(sendDone)
	}()
	go func() {
		// Pass lossMetrics to HandleDCConnReceive so that each correctly received packet is counted.
		r := bwtest.HandleDCConnReceive(clientBwp, dcConn, lossMetrics)
		<-sendDone
		dcConn.Close()
		// Stop the loss monitoring.
		close(stopChan)
		res <- r
	}()
	return finishTime, lossMetrics, nil
}

// writeResponseN writes the response to an 'N' (new bandwidth test) request.
// The waitTime field is
//   - 0:   Ok, the test starts immediately
//   - N>0: please try again in N seconds
func writeResponseN(ccConn net.PacketConn, addr net.Addr, waitTime byte) {
	var response [2]byte
	response[0] = 'N'
	response[1] = waitTime
	_, _ = ccConn.WriteTo(response[:], addr)
}

// writeResponseN writes the response to an 'R' (fetch results) request.
// The code field is
//   - 0:   Ok, the rest of the response is the encoded result
//   - N>0: please try again in N seconds
//   - 127: error, go away (why 127? I guess we have 7-bit bytes or something...)
func writeResponseR(ccConn net.PacketConn, addr net.Addr, code byte, res *bwtest.Result) {
	response := make([]byte, 2000)
	response[0] = 'R'
	response[1] = code
	n := 0
	if res != nil {
		n, _ = bwtest.EncodeResult(*res, response[2:])
	}
	_, _ = ccConn.WriteTo(response[:2+n], addr)
}

// retryWaitTime gives back the "encoded" number of seconds for a client to wait until t.
// Clips to at least 1 second wait time, even if t is closer or in the past.
func retryWaitTime(t time.Time) byte {
	remTime := time.Until(t)
	// Ensure non-negative; should already have finished, but apparently hasn't.
	if remTime < 0 {
		remTime = 0
	}
	return byte(remTime/time.Second) + 1
}

// decodeRequestN decodes and checks the bandwidth test parameters contained in
// an 'N' (new bandwidth test) request.
func decodeRequestN(request []byte) (clientBwp, serverBwp bwtest.Parameters, err error) {
	clientBwp, n1, err := bwtest.DecodeParameters(request[1:])
	if err != nil {
		err = fmt.Errorf("decoding client->server parameters: %w", err)
		return
	}
	if err = validateBwtestParameters(clientBwp); err != nil {
		err = fmt.Errorf("invalid client->server parameters: %w", err)
		return
	}
	serverBwp, n2, err := bwtest.DecodeParameters(request[n1+1:])
	if err != nil {
		err = fmt.Errorf("decoding server->client parameters: %w", err)
		return
	}
	if err = validateBwtestParameters(serverBwp); err != nil {
		err = fmt.Errorf("invalid server->client parameters: %w", err)
		return
	}
	if len(request) != 1+n1+n2 {
		err = errors.New("packet size incorrect")
	}
	return
}

func validateBwtestParameters(bwp bwtest.Parameters) error {
	if bwp.BwtestDuration > bwtest.MaxDuration {
		return fmt.Errorf("duration exceeds max: %s > %s", bwp.BwtestDuration, bwtest.MaxDuration)
	}
	if bwp.PacketSize < bwtest.MinPacketSize {
		return fmt.Errorf("packet size too small: %d < %d", bwp.PacketSize, bwtest.MinPacketSize)
	}
	if bwp.PacketSize > bwtest.MaxPacketSize {
		return fmt.Errorf("packet size exceeds max: %d > %d", bwp.PacketSize, bwtest.MaxPacketSize)
	}
	if bwp.Port < bwtest.MinPort {
		return fmt.Errorf("invalid port: %d", bwp.Port)
	}
	if len(bwp.PrgKey) != 16 {
		return fmt.Errorf("invalid key size: %d != 16", len(bwp.PrgKey))
	}
	return nil
}

type bwtestResultWithExpiry struct {
	bwtest.Result
	Expiry time.Time
}

type resultsMap map[string]bwtestResultWithExpiry

func (r resultsMap) insert(client string, res bwtest.Result) {
	r.purgeExpired()
	r[client] = bwtestResultWithExpiry{
		Result: res,
		Expiry: time.Now().Add(resultExpiry),
	}
}

func (r resultsMap) purgeExpired() {
	now := time.Now()
	for k, v := range r {
		if v.Expiry.Before(now) {
			delete(r, k)
		}
	}
}

func listenConnected(local netip.AddrPort, remote pan.UDPAddr, selector pan.ReplySelector) (net.Conn, error) {
	conn, err := pan.ListenUDP(context.Background(), local, pan.WithReplySelector(selector))
	return connectedPacketConn{
		ListenConn: conn,
		remote:     remote,
	}, err
}

// connectedPacketConn connects a net.PacketConn to a fixed remote address,
// i.e. it uses the fixed remote address to wrap the ReadFrom/WriteTo of a
// net.PacketConn into Read/Write of a net.Conn.
type connectedPacketConn struct {
	pan.ListenConn
	remote pan.UDPAddr
}

func (c connectedPacketConn) Read(buf []byte) (int, error) {
	for {
		n, addr, err := c.ListenConn.ReadFrom(buf)
		if err != nil {
			return n, err
		}
		if c.remote != addr.(pan.UDPAddr) {
			continue
		}
		return n, err
	}
}

func (c connectedPacketConn) Write(buf []byte) (int, error) {
	return c.ListenConn.WriteTo(buf, c.remote)
}

func (c connectedPacketConn) RemoteAddr() net.Addr {
	return c.remote
}

// initializedReplySelector creates a pan.DefaultReplySelector, initialized with path for dst.
func initializedReplySelector(remote pan.UDPAddr, path *pan.Path) pan.ReplySelector {
	if path != nil && path.Destination != remote.IA {
		panic("path destination should match address")
	}
	selector := pan.NewDefaultReplySelector()
	selector.Record(remote, path)
	return selector
}
