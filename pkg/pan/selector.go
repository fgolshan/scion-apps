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

// LossAwareSelector implements the Selector interface and makes path decisions
// based on remote loss metrics. It wraps an underlying DefaultSelector.
type LossAwareSelector struct {
	defaultSel                  *DefaultSelector    // underlying default selector (we have access to its internals)
	lossMetrics                 *bwtest.LossMetrics // pointer to our loss metrics instance
	inertia                     time.Duration       // minimum duration between path switches, e.g., 8 seconds
	lossThreshold               float64             // loss percentage threshold, e.g., 10.0 for 10%
	lastSwitch                  time.Time           // time when the last switch occurred
	switchMutex                 sync.Mutex          // protects access to lastSwitch and cache fields
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
// This method is used by both the update sender and the Path method.
// The decision criterion is simply: average loss > threshold.
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

	// If we are still in the caching period, do not fetch remote update and do not switch.
	s.switchMutex.Lock()
	defer s.switchMutex.Unlock()
	now := time.Now()
	if now.Sub(s.lastCacheUpdate) < s.cacheDuration {
		return ds.Path(ctx)
	}

	// Check if there is a new remote update and update last seen update counter.
	newRemoteUpdateCounter := s.lossMetrics.GetLastRemoteUpdate().UpdateCounter
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
	s.switchMutex.Lock()
	s.lastSwitch = time.Now()
	s.lastCacheUpdate = time.Now().Add(-s.cacheDuration)
	s.lastSeenRemoteUpdateCounter = 0
	s.switchMutex.Unlock()
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
