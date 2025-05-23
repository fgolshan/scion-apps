// Copyright 2021 ETH Zurich
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

package pan

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"

	"github.com/netsec-ethz/scion-apps/pkg/pan/internal/ping"

	"github.com/netsec-ethz/scion-apps/bwtester/bwtest"
)

// Selector controls the path used by a single **dialed** socket. Stateful.
type Selector interface {
	// Path selects the path for the next packet.
	// Invoked for each packet sent with Write.
	Path(ctx context.Context) *Path
	// Initialize the selector for a connection with the initial list of paths,
	// filtered/ordered by the Policy.
	// Invoked once during the creation of a Conn.
	Initialize(local, remote UDPAddr, paths []*Path)
	// Refresh updates the paths. This is called whenever the Policy is changed or
	// when paths were about to expire and are refreshed from the SCION daemon.
	// The set and order of paths may differ from previous invocations.
	Refresh([]*Path)
	// PathDown is called whenever an SCMP down notification is received on any
	// connection so that the selector can adapt its path choice. The down
	// notification may be for unrelated paths not used by this selector.
	PathDown(PathFingerprint, PathInterface)
	Close() error
}

// DefaultSelector is a Selector for a single dialed socket.
// This will keep using the current path, starting with the first path chosen
// by the policy, as long possible.
// Faults are detected passively via SCMP down notifications; whenever such
// a down notification affects the current path, the DefaultSelector will
// switch to the first path (in the order defined by the policy) that is not
// affected by down notifications.
type DefaultSelector struct {
	mutex   sync.Mutex
	paths   []*Path
	current int
}

func NewDefaultSelector() *DefaultSelector {
	return &DefaultSelector{}
}

func (s *DefaultSelector) Path(_ context.Context) *Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.paths) == 0 {
		return nil
	}
	return s.paths[s.current]
}

func (s *DefaultSelector) Initialize(local, remote UDPAddr, paths []*Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.paths = paths
	s.current = 0
}

func (s *DefaultSelector) Refresh(paths []*Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	newcurrent := 0
	if len(s.paths) > 0 {
		currentFingerprint := s.paths[s.current].Fingerprint
		for i, p := range paths {
			if p.Fingerprint == currentFingerprint {
				newcurrent = i
				break
			}
		}
	}
	s.paths = paths
	s.current = newcurrent
}

func (s *DefaultSelector) PathDown(pf PathFingerprint, pi PathInterface) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if current := s.paths[s.current]; isInterfaceOnPath(current, pi) || pf == current.Fingerprint {
		fmt.Println("down:", s.current, len(s.paths))
		better := stats.FirstMoreAlive(current, s.paths)
		if better >= 0 {
			// Try next path. Note that this will keep cycling if we get down notifications
			s.current = better
			fmt.Println("failover:", s.current, len(s.paths))
		}
	}
}

func (s *DefaultSelector) Close() error {
	return nil
}

type PingingSelector struct {
	// Interval for pinging. Must be positive.
	Interval time.Duration
	// Timeout for the individual pings. Must be positive and less than Interval.
	Timeout time.Duration

	mutex   sync.Mutex
	paths   []*Path
	current int
	local   scionAddr
	remote  scionAddr

	numActive    int64
	pingerCtx    context.Context
	pingerCancel context.CancelFunc
	pinger       *ping.Pinger
}

// SetActive enables active pinging on at most numActive paths.
func (s *PingingSelector) SetActive(numActive int) {
	s.ensureRunning()
	atomic.SwapInt64(&s.numActive, int64(numActive))
}

func (s *PingingSelector) Path(_ context.Context) *Path {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.paths) == 0 {
		return nil
	}
	return s.paths[s.current]
}

func (s *PingingSelector) Initialize(local, remote UDPAddr, paths []*Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.local = local.scionAddr()
	s.remote = remote.scionAddr()
	s.paths = paths
	s.current = stats.LowestLatency(s.remote, s.paths)
}

func (s *PingingSelector) Refresh(paths []*Path) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.paths = paths
	s.current = stats.LowestLatency(s.remote, s.paths)
}

func (s *PingingSelector) PathDown(pf PathFingerprint, pi PathInterface) {
	s.reselectPath()
}

func (s *PingingSelector) reselectPath() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.current = stats.LowestLatency(s.remote, s.paths)
}

func (s *PingingSelector) ensureRunning() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	host, err := getHost()
	if err != nil {
		return
	}
	if s.local.IA == s.remote.IA {
		return
	}
	if s.pinger != nil {
		return
	}
	s.pingerCtx, s.pingerCancel = context.WithCancel(context.Background())
	local := s.local.snetUDPAddr()
	pinger, err := ping.NewPinger(s.pingerCtx, host.sciond, local)
	if err != nil {
		return
	}
	s.pinger = pinger
	go s.pinger.Drain(s.pingerCtx)
	go s.run()
}

func (s *PingingSelector) run() {
	pingTicker := time.NewTicker(s.Interval)
	pingTimeout := time.NewTimer(0)
	if !pingTimeout.Stop() {
		<-pingTimeout.C // drain initial timer event
	}

	var sequenceNo uint16
	replyPending := make(map[PathFingerprint]struct{})

	for {
		select {
		case <-s.pingerCtx.Done():
			return
		case <-pingTicker.C:
			numActive := int(atomic.LoadInt64(&s.numActive))
			if numActive > len(s.paths) {
				numActive = len(s.paths)
			}
			if numActive == 0 {
				continue
			}

			activePaths := s.paths[:numActive]
			for _, p := range activePaths {
				replyPending[p.Fingerprint] = struct{}{}
			}
			sequenceNo++
			s.sendPings(activePaths, sequenceNo)
			resetTimer(pingTimeout, s.Timeout)
		case r := <-s.pinger.Replies:
			s.handlePingReply(r, replyPending, sequenceNo)
			if len(replyPending) == 0 {
				pingTimeout.Stop()
				s.reselectPath()
			}
		case <-pingTimeout.C:
			if len(replyPending) == 0 {
				continue // already handled above
			}
			for pf := range replyPending {
				stats.RecordLatency(s.remote, pf, s.Timeout)
				delete(replyPending, pf)
			}
			s.reselectPath()
		}
	}
}

func (s *PingingSelector) sendPings(paths []*Path, sequenceNo uint16) {
	for _, p := range paths {
		remote := s.remote.snetUDPAddr()
		remote.Path = p.ForwardingPath.dataplanePath
		remote.NextHop = net.UDPAddrFromAddrPort(p.ForwardingPath.underlay)
		err := s.pinger.Send(s.pingerCtx, remote, sequenceNo, 16)
		if err != nil {
			panic(err)
		}
	}
}

func (s *PingingSelector) handlePingReply(reply ping.Reply,
	expectedReplies map[PathFingerprint]struct{},
	expectedSequenceNo uint16) {
	if reply.Error != nil {
		// handle NotifyPathDown.
		// The Pinger is not using the normal scmp handler in raw.go, so we have to
		// reimplement this here.
		pf, err := reversePathFingerprint(reply.Path)
		if err != nil {
			return
		}
		switch e := reply.Error.(type) { //nolint:errorlint
		case ping.InternalConnectivityDownError:
			pi := PathInterface{
				IA:   IA(e.IA),
				IfID: IfID(e.Egress),
			}
			stats.NotifyPathDown(pf, pi)
		case ping.ExternalInterfaceDownError:
			pi := PathInterface{
				IA:   IA(e.IA),
				IfID: IfID(e.Interface),
			}
			stats.NotifyPathDown(pf, pi)
		}
		return
	}

	if reply.Source.Host.Type() != addr.HostTypeIP {
		return // ignore replies from non-IP addresses
	}
	src := scionAddr{
		IA: IA(reply.Source.IA),
		IP: reply.Source.Host.IP(),
	}
	if src != s.remote || reply.Reply.SeqNumber != expectedSequenceNo {
		return
	}
	pf, err := reversePathFingerprint(reply.Path)
	if err != nil {
		return
	}
	if _, expected := expectedReplies[pf]; !expected {
		return
	}
	stats.RecordLatency(s.remote, pf, reply.RTT())
	delete(expectedReplies, pf)
}

func (s *PingingSelector) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.pinger == nil {
		return nil
	}
	s.pingerCancel()
	return s.pinger.Close()
}

// LossAwareSelector implements the Selector interface and makes simple path selection decisions
// based on remote loss metrics. It wraps an underlying DefaultSelector.
type LossAwareSelector struct {
	defaultSel                  *DefaultSelector    // underlying default selector (we have access to its internals)
	lossMetrics                 *bwtest.LossMetrics // pointer to our loss metrics instance
	inertia                     time.Duration       // minimum duration between path switches, e.g., 8 seconds
	lossThreshold               float64             // loss percentage threshold, e.g., 10.0 for 10%
	cacheMutex                  sync.Mutex          // protects access to lastSwitch and cache fields
	lastSwitch                  time.Time           // time when the last switch occurred
	cacheDuration               time.Duration       // duration for which the loss average is cached
	lastCacheUpdate             time.Time           // last time the cache was updated
	lastSeenRemoteUpdateCounter uint32              // counter of the last remote update used for switching
}

// NewLossAwareSelector creates a new LossAwareSelector.
// cacheDur specifies the duration to cache the loss value (e.g., 500ms).
func NewLossAwareSelector(lossMetrics *bwtest.LossMetrics, inertia time.Duration, lossThreshold float64, cacheDur time.Duration) *LossAwareSelector {
	return &LossAwareSelector{
		defaultSel:                  NewDefaultSelector(),
		lossMetrics:                 lossMetrics,
		inertia:                     inertia,
		lossThreshold:               lossThreshold,
		lastSwitch:                  time.Now(),
		cacheDuration:               cacheDur,
		lastCacheUpdate:             time.Now().Add(-cacheDur),
		lastSeenRemoteUpdateCounter: 0,
	}
}

// WouldSwitch returns true if the average loss over the provided lossWindow exceeds the threshold.
func (s *LossAwareSelector) WouldSwitch(lossWindow []float32) bool {
	if len(lossWindow) == 0 {
		return false
	}
	var sum float64
	for _, loss := range lossWindow {
		sum += float64(loss)
	}
	avgLoss := sum / float64(len(lossWindow))
	return avgLoss > s.lossThreshold
}

// Path selects the path for the next packet. It accepts a context and delegates
// to the underlying default selector's Path method, updating the cached remote loss.
func (s *LossAwareSelector) Path(ctx context.Context) *Path {
	ds := s.defaultSel
	currentPath := ds.Path(ctx)
	if currentPath == nil {
		return nil
	}

	// TODO: The caching mechanism can be removed, since we now use atomic loads to receive the update counter.
	// If we are still in the caching period, do not fetch remote update and do not switch.
	s.cacheMutex.Lock()
	defer s.cacheMutex.Unlock()
	now := time.Now()
	if now.Sub(s.lastCacheUpdate) < s.cacheDuration {
		return ds.Path(ctx)
	}

	// Check if there is a new remote update and update last seen update counter.
	newRemoteUpdateCounter := s.lossMetrics.GetLastRemoteUpdateCounter()
	seenNewUpdate := newRemoteUpdateCounter > s.lastSeenRemoteUpdateCounter
	s.lastCacheUpdate = now
	if seenNewUpdate {
		s.lastSeenRemoteUpdateCounter = newRemoteUpdateCounter
	}

	// Switch only if sufficient time has passed since the last switch and new updates are still incoming
	// Switch to an arbitrary path uniformly at random, including the current path.
	if seenNewUpdate && now.Sub(s.lastSwitch) >= s.inertia {
		numPaths := len(ds.paths)
		if numPaths > 0 {
			newIndex := rand.Intn(numPaths)
			ds.mutex.Lock()
			ds.current = newIndex
			ds.mutex.Unlock()
			s.lastSwitch = now
			fmt.Printf("LossAwareSelector: switching path to index %d due to new remote update (counter: %d)\n", newIndex, newRemoteUpdateCounter)
		}
	}

	return ds.Path(ctx)
}

// Initialize delegates initialization to the underlying default selector.
func (s *LossAwareSelector) Initialize(local, remote UDPAddr, paths []*Path) {
	s.defaultSel.Initialize(local, remote, paths)
	s.cacheMutex.Lock()
	s.lastSwitch = time.Now()
	s.lastCacheUpdate = time.Now().Add(-s.cacheDuration)
	s.lastSeenRemoteUpdateCounter = s.lossMetrics.GetLastRemoteUpdateCounter()
	s.cacheMutex.Unlock()
}

// Refresh delegates to the underlying default selector.
func (s *LossAwareSelector) Refresh(paths []*Path) {
	s.defaultSel.Refresh(paths)
}

// Currently not implemented, must avoid double switch from Path() method
func (s *LossAwareSelector) PathDown(pf PathFingerprint, pi PathInterface) {
	//s.defaultSel.PathDown(pf, pi)
}

// Close delegates to the underlying default selector.
func (s *LossAwareSelector) Close() error {
	return s.defaultSel.Close()
}

// The following code implements a LossAndPingAwareSelector. Just as the LossAwareSelector, it
// makes path selection decisions based on remote loss metrics. However, it previouly computes
// a candidate set of paths based on Pinging metrics.

// Define the state constants for the LossAndPingAwareSelector.
const (
	stateNormal  = iota // 0: Normal operation.
	stateInertia        // 1: In inertia period after a switch decision (or a decision not to switch).
	stateWaiting        // 2: Random waiting period scheduled for switching.
	stateReady          // 3: Ready-to-switch state (waiting for a new update to trigger immediate switch).
)

type LossAndPingAwareSelector struct {
	pingSel     *PingingSelector    // underlying ping selector (must be running and updating latencies)
	lossMetrics *bwtest.LossMetrics // provides remote loss update information

	cutoffAbs     float64       // cutoffAbs is the multiplicative factor for absolute latency; e.g., 1.2 means select all paths with latency ≤ 1.2× best.
	cutoffDiff    float64       // cutoffDiff is the multiplicative factor for the latency difference; e.g., 1.2 means select all paths with latency difference from min ≤ 1.2× best.
	inertia       time.Duration // minimum time between switches
	lossThreshold float64       // loss percentage threshold for switching

	mutex                       sync.Mutex // protects cachedPath and switching fields
	switchState                 int        // current state of the selector
	cachedPath                  *Path      // currently selected path
	lastSwitch                  time.Time  // time when the last switch was triggered
	lastSeenRemoteUpdateCounter uint32     // last remote update counter that triggered a switch
	scheduledSwitchTime         time.Time  // scheduledSwitchTime is set in state 2: the time at which we become ready (state 3).
	readyExpirationTime         time.Time  // readyExpirationTime is set in state 3: if no new update arrives before this time, cancel ready state.
}

// NewLossAndPingAwareSelector creates a new LossAndPingAwareSelector.
// The parameters are:
//   - cutoff: e.g. 1.2 for 20% above the best latency,
//   - inertia: minimum time between switches,
//   - pingInterval and pingTimeout: parameters for the underlying ping selector,
//   - lossMetrics: pointer to the LossMetrics instance.
func NewLossAndPingAwareSelector(cutoffAbs, cutoffDiff, lossThreshold float64, inertia, pingInterval, pingTimeout time.Duration, lossMetrics *bwtest.LossMetrics) *LossAndPingAwareSelector {
	// Instantiate the underlying ping selector.
	ps := &PingingSelector{
		Interval: pingInterval,
		Timeout:  pingTimeout,
		// Other fields will be set in Initialize.
	}
	// Do not call ensureRunning() here; it will be called in Initialize via SetActive.
	return &LossAndPingAwareSelector{
		pingSel:                     ps,
		lossMetrics:                 lossMetrics,
		cutoffAbs:                   cutoffAbs,
		cutoffDiff:                  cutoffDiff,
		inertia:                     inertia,
		lossThreshold:               lossThreshold,
		switchState:                 stateNormal,
		lastSeenRemoteUpdateCounter: 0,
	}
}

// WouldSwitch returns true if the average loss over the provided lossWindow exceeds the threshold
// and the most recent loss is above the threshold.
func (s *LossAndPingAwareSelector) WouldSwitch(lossWindow []float32) bool {
	if len(lossWindow) == 0 {
		return false
	}
	var sum float64
	for _, loss := range lossWindow {
		sum += float64(loss)
	}
	avgLoss := sum / float64(len(lossWindow))
	return avgLoss > s.lossThreshold && lossWindow[len(lossWindow)-1] > float32(s.lossThreshold)
}

// getLatestLatency returns the most recent latency for path p toward destination dst.
// It looks up the destination's latency samples in the global stats database.
// If no valid latency is recorded for p, or if the path was notified down after the sample was taken,
// it returns a very high duration (maxDuration).
func getLatestLatency(dst scionAddr, p *Path) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)

	stats.mutex.RLock()
	defer stats.mutex.RUnlock()

	dstStats, ok := stats.destinations[dst]
	if !ok {
		return maxDuration
	}
	samples, ok := dstStats.Latency[p.Fingerprint]
	if !ok || len(samples) == 0 {
		return maxDuration
	}
	latestSample := samples[0] // assume samples[0] is the most recent sample

	// Check if the path was notified down after the latency sample was taken.
	downTime := stats.newestDownNotification(p)
	if downTime.After(latestSample.Time) {
		return maxDuration
	}

	return latestSample.Value
}

// CandidatePaths returns a subset of paths that have a valid latency measurement and whose latency
// is within cutoff times the minimum measured latency among all paths.
// If no valid latency measurement is found (i.e. all paths are effectively down), it returns all paths.
func CandidatePaths(dst scionAddr, paths []*Path, cutoff float64) []*Path {
	const maxDuration = time.Duration(1<<63 - 1)

	var valid []struct {
		p   *Path
		lat time.Duration
	}
	minLatency := maxDuration
	for _, p := range paths {
		lat := getLatestLatency(dst, p)
		// Consider a latency valid if it is less than maxDuration.
		if lat < maxDuration {
			valid = append(valid, struct {
				p   *Path
				lat time.Duration
			}{p, lat})
			if lat < minLatency {
				minLatency = lat
			}
		}
	}
	// If no valid measurements exist, return all paths.
	if len(valid) == 0 {
		return paths
	}

	// Print latenccy information for analysis. TODO: Remove after analysis.
	fmt.Println("Printing latency information for all paths:")
	for _, v := range valid {
		fmt.Printf("Path %s: latency %v\n", v.p.Fingerprint, v.lat)
	}
	fmt.Println("Latency information printed.")

	// Define cutoff duration.
	cutoffDuration := time.Duration(float64(minLatency) * cutoff)
	var candidates []*Path
	for _, v := range valid {
		if v.lat <= cutoffDuration {
			candidates = append(candidates, v.p)
		}
	}
	// Fallback: if candidate subset is empty (should not happen if one path responded), return all paths.
	if len(candidates) == 0 {
		return paths
	}
	return candidates
}

// getRobustCurrentRTT returns the median of the last three RTT measurements for path p toward dst.
// If fewer than three samples are available, it uses all available samples.
// If the newest down notification for p is later than the timestamp of the least recent sample, returns maxDuration.
func getRobustCurrentRTT(dst scionAddr, p *Path) time.Duration {
	numberOfMeasurements := 3

	stats.mutex.RLock()
	defer stats.mutex.RUnlock()

	dstStats, ok := stats.destinations[dst]
	if !ok {
		return maxDuration
	}
	samples, ok := dstStats.Latency[p.Fingerprint]
	if !ok || len(samples) == 0 {
		return maxDuration
	}

	// Use up to the last three samples.
	n := len(samples)
	count := numberOfMeasurements
	if n < numberOfMeasurements {
		count = n
	}
	window := make([]time.Duration, count)
	for i := 0; i < count; i++ {
		window[i] = samples[i].Value
	}

	// Check down notification: if newest down notification for p is after the timestamp of the least recent sample, consider it down.
	newestDown := stats.newestDownNotification(p)
	if newestDown.After(samples[count-1].Time) {
		return maxDuration
	}

	// Sort the window to compute the median.
	sort.Slice(window, func(i, j int) bool { return window[i] < window[j] })
	medianRTT := window[count/2]

	return medianRTT
}

// getMinRTT returns the minimum RTT measured for path p toward dst by iterating over all samples.
// This is of course highly ineffecient and must be replaced by some caching mechanism for anything beyond prototyping.
func getMinRTT(dst scionAddr, p *Path) time.Duration {
	stats.mutex.RLock()
	defer stats.mutex.RUnlock()

	dstStats, ok := stats.destinations[dst]
	if !ok {
		return maxDuration
	}
	samples, ok := dstStats.Latency[p.Fingerprint]
	if !ok || len(samples) == 0 {
		return maxDuration
	}

	minRTT := maxDuration
	for _, sample := range samples {
		if sample.Value < minRTT {
			minRTT = sample.Value
		}
	}
	return minRTT
}

// CandidatePathsDual returns a candidate set of paths based on two criteria:
// 1) Absolute RTT: The robust current RTT (median of last three samples) is within cutoffAbs times the best robust RTT among all paths.
// 2) RTT difference: The difference (robust current RTT - min RTT) is within cutoffDiff times the smallest such difference among the absolute candidates.
// If the intersection is empty, fall back to the absolute candidate set. If that too is empty, return all paths.
func CandidatePathsDual(dst scionAddr, paths []*Path, cutoffAbs, cutoffDiff float64) []*Path {
	// Step 1: Build the absolute candidate set.
	type pathMetrics struct {
		p    *Path
		rtt  time.Duration // robust current RTT
		diff time.Duration // current RTT - min RTT
	}
	var absCandidates []pathMetrics
	bestRTT := maxDuration
	for _, p := range paths {
		rtt := getRobustCurrentRTT(dst, p)
		if rtt < maxDuration {
			if rtt < bestRTT {
				bestRTT = rtt
			}
			// Compute RTT difference.
			minRTT := getMinRTT(dst, p)
			var diff time.Duration
			if minRTT < maxDuration && rtt >= minRTT {
				diff = rtt - minRTT
			} else {
				diff = maxDuration
			}
			absCandidates = append(absCandidates, pathMetrics{p: p, rtt: rtt, diff: diff})
		}
	}
	// If no valid candidates, return all paths.
	if len(absCandidates) == 0 {
		return paths
	}

	absCutoffDuration := time.Duration(float64(bestRTT) * cutoffAbs)
	var absSet []pathMetrics
	now := time.Now()
	fmt.Printf("[%v] Selector: Computing initial candidate set\n", now)
	for _, pm := range absCandidates {
		if pm.rtt <= absCutoffDuration {
			absSet = append(absSet, pm)
			fmt.Printf("[%v] Selector: Adding path %s to initial candidate set (lat: %v, lat diff: %v)\n",
				now, pm.p.Fingerprint, pm.rtt, pm.diff)
		}
	}
	// If absSet is empty (should not happen if at least one path is valid), fallback.
	if len(absSet) == 0 {
		absSet = absCandidates
	}

	// Step 2: Build the narrower candidate set based on RTT difference.
	fmt.Printf("[%v] Selector: Computing the narrower candidate set\n", now)
	bestDiff := maxDuration
	for _, pm := range absSet {
		if pm.diff < bestDiff {
			bestDiff = pm.diff
		}
	}
	diffCutoff := time.Duration(float64(bestDiff) * cutoffDiff)
	var finalCandidates []*Path
	for _, pm := range absSet {
		if pm.diff <= diffCutoff {
			finalCandidates = append(finalCandidates, pm.p)
			fmt.Printf("[%v] Selector: Adding path %s to narrower candidate set (lat: %v, lat diff: %v)\n",
				now, pm.p.Fingerprint, pm.rtt, pm.diff)
		}
	}

	// Fallback: if final candidate set is empty, use the absolute candidate set.
	// Actually, this should not ever happen with the relative difference cutoff.
	if len(finalCandidates) == 0 {
		finalCandidates = make([]*Path, len(absSet))
		for i, pm := range absSet {
			finalCandidates[i] = pm.p
		}
	}
	return finalCandidates
}

// Initialize delegates initialization to the underlying ping selector,
// then sets NumActive to ensure that all paths are actively probed,
// and initializes our cached path.
func (s *LossAndPingAwareSelector) Initialize(local, remote UDPAddr, paths []*Path) {
	s.pingSel.Initialize(local, remote, paths)
	s.pingSel.SetActive(len(paths))
	if s.cachedPath == nil {
		s.mutex.Lock()
		// Lock the underlying ping selector to safely copy its paths and remote.
		s.pingSel.mutex.Lock()
		if len(s.pingSel.paths) == 0 {
			s.cachedPath = nil
		} else {
			s.cachedPath = s.pingSel.paths[0]
		}
		s.pingSel.mutex.Unlock()
		s.lastSeenRemoteUpdateCounter = s.lossMetrics.GetLastRemoteUpdateCounter()
		fmt.Printf("[%v] Selector: Initialized selector with path %s\n",
			time.Now(), s.cachedPath.Fingerprint)
		s.mutex.Unlock()
	}
}

// Refresh delegates to the underlying ping selector.
// TODO: Currently this has no direct effect on path selection
func (s *LossAndPingAwareSelector) Refresh(paths []*Path) {
	s.pingSel.Refresh(paths)
}

// PathDown delegates to the underlying ping selector.
// TODO: Currently not implemented, avoid interference with Path() method
func (s *LossAndPingAwareSelector) PathDown(pf PathFingerprint, pi PathInterface) {
	// s.pingSel.PathDown(pf, pi)
}

// Close delegates to the underlying ping selector.
func (s *LossAndPingAwareSelector) Close() error {
	return s.pingSel.Close()
}

func (s *LossAndPingAwareSelector) Path(ctx context.Context) *Path {
	now := time.Now()

	// Lock our selector state.
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Obtain the latest remote update counter.
	remoteUpdateCounter := s.lossMetrics.GetLastRemoteUpdateCounter()
	hasNewUpdate := remoteUpdateCounter > s.lastSeenRemoteUpdateCounter
	if hasNewUpdate {
		// If a new update is available, we always update the counter.
		s.lastSeenRemoteUpdateCounter = remoteUpdateCounter
	}

	// State machine transitions:
	switch s.switchState {
	case stateNormal:
		// In normal state, check if a new update is available.
		if hasNewUpdate {
			remoteUpdate := s.lossMetrics.GetLastRemoteUpdate()
			// In case we have just fetched an even newer update, update the conter as well.
			currentRemoteUpdateCounter := remoteUpdate.UpdateCounter.Load()
			if currentRemoteUpdateCounter > s.lastSeenRemoteUpdateCounter {
				s.lastSeenRemoteUpdateCounter = currentRemoteUpdateCounter
			}
			// Currently, we don't use the probabilistic switching decision. To print loss, use: loss=%.2f%%
			/*
				// Compute remote average loss.
				var remoteAvgLoss float64
				if len(remoteUpdate.SlidingWindow) > 0 {
					var sum float64
					for _, loss := range remoteUpdate.SlidingWindow {
						sum += float64(loss)
					}
					remoteAvgLoss = sum / float64(len(remoteUpdate.SlidingWindow))
				} else {
					remoteAvgLoss = 0
				}
				// Decide probabilistically whether to switch.
				p := remoteAvgLoss / 100.0 // if loss is 100%, p = 1.
			*/
			// For a small number of flows, simply use p = 1
			p := 1.0
			if rand.Float64() < p {
				// Schedule a random switch time within inertia leaving 2s to refresh latency measurements.
				randomDelay := 2*time.Second + time.Duration(rand.Int63n(int64(s.inertia-2*time.Second)))
				s.scheduledSwitchTime = now.Add(randomDelay)
				// Transition to waiting state.
				s.switchState = stateWaiting
				fmt.Printf("[%v] Selector: new update (counter %d) - scheduling switch at %v\n",
					now, remoteUpdateCounter, s.scheduledSwitchTime)
			} else {
				// Otherwise, do not switch and enter inertia state.
				s.lastSwitch = now
				s.switchState = stateInertia
				fmt.Printf("[%v] Selector: new update (counter %d) - remaining on current path, entering inertia\n",
					now, remoteUpdateCounter)
			}
		}
	case stateInertia:
		// In inertia state, do nothing until inertia expires.
		if now.Sub(s.lastSwitch) >= s.inertia/4 {
			// Inertia period is over; return to normal.
			s.switchState = stateNormal
		} else {
			// Still in inertia: return current cached path.
			return s.cachedPath
		}
	case stateWaiting:
		// In waiting state, if the scheduled switch time has not yet arrived, remain in waiting.
		if now.Before(s.scheduledSwitchTime) {
			return s.cachedPath
		}
		// Otherwise, transition to ready state.
		s.readyExpirationTime = now.Add(s.inertia) // ready period lasts for inertia duration.
		s.switchState = stateReady
		fmt.Printf("[%v] Selector: transitioning to ready-to-switch state; ready until %v\n", now, s.readyExpirationTime)
	case stateReady:
		// In ready-to-switch state: if a new update arrives (i.e. remote update counter increases), switch immediately.
		if hasNewUpdate {
			// Ensure underlying pingSel has candidate paths.
			s.pingSel.mutex.Lock()
			if len(s.pingSel.paths) == 0 {
				s.pingSel.mutex.Unlock()
				return nil
			}
			// Obtain candidate paths from the underlying ping selector.
			pathsCopy := make([]*Path, len(s.pingSel.paths))
			copy(pathsCopy, s.pingSel.paths)
			dst := s.pingSel.remote
			s.pingSel.mutex.Unlock()
			// Perform the switch now.
			// candidates := CandidatePaths(dst, pathsCopy, s.cutoff)
			candidates := CandidatePathsDual(dst, pathsCopy, s.cutoffAbs, s.cutoffDiff)
			if len(candidates) > 0 {
				newPath := candidates[rand.Intn(len(candidates))]
				s.cachedPath = newPath
				s.lastSwitch = now
				s.switchState = stateInertia // after switching, enter inertia state.
				fmt.Printf("[%v] Selector: switching path in ready state due to new remote update (counter %d); selected path %s with latency %v from %d/%d candidate paths\n",
					now, remoteUpdateCounter, newPath.Fingerprint, getLatestLatency(dst, newPath), len(candidates), len(pathsCopy))
			}
		} else if now.After(s.readyExpirationTime) {
			// Ready period expired without new update; cancel switching and return to normal.
			s.switchState = stateNormal
			fmt.Printf("[%v] Selector: ready-to-switch period expired; staying on current path\n", now)
		} else {
			// Still in ready-to-switch period and no new update; continue using cached path.
			return s.cachedPath
		}
	}

	// In stateNormal (or after transitioning out of inertia/waiting/ready), return the cached path.
	return s.cachedPath
}
