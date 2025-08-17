package pan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/topology/underlay"
	"github.com/x448/float16"
)

const TargetMissFactor = 0.98 // How much we can miss the target send rate without switching, e.g. 0.98 (98% of target)

type ProbeState struct {
	RequestTime   time.Time // when we sent the P-probe that last updated the path state
	lastReplyTime time.Time // when we received the last P-probe reply
	lastEstimate  uint64    // most recent bps estimate from P-probe reply
}

type PolarisCore struct {
	mu         sync.Mutex
	paths      []*Path               // available paths
	activePath *atomic.Pointer[Path] // currently active path

	sendRateBps       atomic.Uint64 // the estimated send rate on the current path, e.g. 1000000 (1 Mbps)
	byteCounter       atomic.Uint64 // bytes sent on the current path in the current second
	targetSendRateBps atomic.Uint64 // the target send rate on the current path, e.g. 1000000 (1 Mbps)
	targetMissFactor  float64       // How much we can miss the target send rate without switching, e.g. 0.98 (98% of target)

	alpha          float64       // margin factor to avoid unnecessary path switches, e.g. 1.5
	stableTime     time.Duration // amount of time a path needs to be a potential candidate, e.g. 5s
	switchInterval time.Duration // minimum wait time after a path switch before allowing to switch again, e.g. 10s
	lastSwitch     time.Time     // time of the last path switch, used to enforce switchInterval
	probeValidity  time.Duration // how long a P-probe reply is valid, e.g. 2*probeInterval to allow for one but not two missed replies
	RTTUpperBound  time.Duration // used to avoid potentially stale bandwidth shares after a path switch, e.g. 0.5s

	stopCh     chan struct{} // closed to stop probing, switching and bandwidth updating routines
	once       sync.Once
	logEnabled bool // whether to log path switch events and rate changes for traffic analysis

	prober         *Prober                // prober instance for sending P-probes and receiving replies
	probeState     map[string]*ProbeState // results from P-probes and P-CA alerts for each path
	potentialSince map[string]time.Time   // when a path first became potential candidate
	congested      map[string]struct{}    // paths that are currently congested (received P-CA alert)
	down           map[string]struct{}    // paths that are currently down (received SCMP path down alert)
}

// NewPolarisCore creates and initializes a Core for the given paths.
func NewPolarisCore(alpha float64,
	probeInterval,
	stableTime,
	switchInterval time.Duration,
	logEnabled bool,
	targetSendRate uint64,
) *PolarisCore {
	core := &PolarisCore{
		activePath:     &atomic.Pointer[Path]{},
		alpha:          alpha,
		stableTime:     stableTime,
		switchInterval: switchInterval,
		lastSwitch:     time.Now(),
		probeValidity:  2 * probeInterval,
		RTTUpperBound:  500 * time.Millisecond,
		stopCh:         make(chan struct{}),
		logEnabled:     logEnabled,
	}

	core.probeState = make(map[string]*ProbeState)
	core.potentialSince = make(map[string]time.Time)
	core.congested = make(map[string]struct{})
	core.down = make(map[string]struct{})

	core.prober = NewProber(core, probeInterval)

	core.targetSendRateBps.Store(targetSendRate)
	core.targetMissFactor = TargetMissFactor

	return core
}

func (c *PolarisCore) Initialize(local, remote UDPAddr, paths []*Path) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.paths = paths
	// pick the first path as our starting point
	if len(paths) > 0 {
		c.activePath.Store(paths[0])
		// try random initialization
		// c.activePath.Store(paths[rand.Intn(len(paths))])
	} else {
		return
	}

	newPath := c.ActivePath()
	evt := map[string]interface{}{
		"ts":           float64(time.Now().UnixNano()) / 1e9,
		"event":        "path_switch",
		"trigger":      "initialization",
		"new":          string(newPath.Fingerprint),
		"current_rate": c.CurrentSendRate(),
	}
	c.logEvent(evt)

	availablePaths := make([]*Path, len(paths))
	copy(availablePaths, paths) // fine for small topologies
	err := c.prober.Initialize(local, remote, availablePaths)
	if err != nil {
		fmt.Printf("Failed to initialize Polaris prober: %v\n", err)
		return
	}
	c.StartSwitchLoop()
	c.StartCurrentBandwidthTracker()
}

// HandleProbeReply updates the Polaris state for a path when a P-probe response is received.
// It clears any stale alerts for the path, records the new reply, and updates the potential candidates.
func (c *PolarisCore) HandleProbeReply(
	pathFP string,
	estimatedBps uint64,
	requestTime time.Time,
	replyTime time.Time,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1) clear stale alerts
	delete(c.down, pathFP)
	delete(c.congested, pathFP)

	// 2) record the new reply
	ps := &ProbeState{
		RequestTime:   requestTime,
		lastReplyTime: replyTime,
		lastEstimate:  estimatedBps,
	}
	c.probeState[pathFP] = ps

	// 3) immediately refresh this path’s potential status
	c.updateSinglePathPotential(pathFP)
}

// Helper to perform a path switch, assumes c.mu is held.
func (c *PolarisCore) switchToPath(path *Path) {
	if path == nil || path.Fingerprint == c.ActivePath().Fingerprint {
		return
	}
	c.activePath.Store(path)
	c.lastSwitch = time.Now()
	c.potentialSince = make(map[string]time.Time) // reset potential candidates since we switched
}

// HandlePCA marks a path as congested when a P-CA alert is received, and removes it from potential candidates.
// If the P-CA alert is for the currently active path, it may trigger a switch to another path, if there is a candidate available.
func (c *PolarisCore) HandlePCA(pathFP string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.congested[pathFP] = struct{}{}
	delete(c.potentialSince, pathFP)
	if pathFP == string(c.ActivePath().Fingerprint) {
		alts := c.finalCandidates()
		if len(alts) > 0 {
			newPath := alts[rand.Intn(len(alts))]
			// log the path switch event for traffic analysis
			oldPath := c.ActivePath()
			var estimatedShare interface{} = nil
			if ps, ok := c.probeState[string(newPath.Fingerprint)]; ok {
				estimatedShare = ps.lastEstimate
			}
			evt := map[string]interface{}{
				"ts":              float64(time.Now().UnixNano()) / 1e9,
				"event":           "path_switch",
				"trigger":         "P-CA",
				"old":             string(oldPath.Fingerprint),
				"new":             string(newPath.Fingerprint),
				"candidates":      len(alts),
				"estimated_share": estimatedShare,
				"current_rate":    c.CurrentSendRate(),
			}
			c.logEvent(evt)

			c.switchToPath(newPath)
		}
	}
}

// HandlePathDown marks a path as down when a SCMP path down alert is received.
// If the down path is the currently active path, it will switch to another path, if available.
func (c *PolarisCore) HandlePathDown(pathFP string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.down[pathFP] = struct{}{}
	delete(c.potentialSince, pathFP)
	if pathFP == string(c.ActivePath().Fingerprint) {
		alts := c.finalCandidates()
		if len(alts) == 0 {
			alts = c.potentialCandidates()
		}
		if len(alts) == 0 {
			alts = c.nonCongestedPaths()
		}
		if len(alts) == 0 {
			alts = c.upPaths()
		}
		if len(alts) > 0 {
			newPath := alts[rand.Intn(len(alts))]
			// log the path switch event for traffic analysis
			oldPath := c.ActivePath()
			var estimatedShare interface{} = nil
			if ps, ok := c.probeState[string(newPath.Fingerprint)]; ok {
				estimatedShare = ps.lastEstimate
			}
			evt := map[string]interface{}{
				"ts":              float64(time.Now().UnixNano()) / 1e9,
				"event":           "path_switch",
				"trigger":         "SCMP_path_down",
				"old":             string(oldPath.Fingerprint),
				"new":             string(newPath.Fingerprint),
				"candidates":      len(alts),
				"estimated_share": estimatedShare,
				"current_rate":    c.CurrentSendRate(),
			}
			c.logEvent(evt)

			c.switchToPath(newPath)
		}
	}
}

// Launches a routine for periodic path switch considerations.
func (c *PolarisCore) StartSwitchLoop() {
	go func() {
		ticker := time.NewTicker(c.switchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.maybeSwitch()
			case <-c.stopCh:
				return
			}
		}
	}()
}

// Launches a routine for periodic bandwidth tracking and potential candidate recomputation.
func (c *PolarisCore) StartCurrentBandwidthTracker() {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				raw := c.byteCounter.Load()
				c.byteCounter.Store(0)
				newRateBps := raw * 8
				c.sendRateBps.Swap(newRateBps) // could get old value here to compare

				// log the current send rate for traffic analysis
				evt := map[string]interface{}{
					"ts":    float64(time.Now().UnixNano()) / 1e9,
					"event": "send_rate",
					"rate":  newRateBps,
				}
				c.logEvent(evt)

				// re-evaluate potential candidates even if the rate has not changed
				// this keeps the potential candidates fresh (deals with missing probe replies)
				c.mu.Lock()
				c.recomputePotentialCandidates()
				c.mu.Unlock()
			case <-c.stopCh:
				return
			}
		}
	}()
}

// Computes final candidate paths and may switch to one of them.
// Switching occurs if sufficient time since the last switch has passed and there are final candidates available.
func (c *PolarisCore) maybeSwitch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.lastSwitch) < c.switchInterval {
		return
	}

	if float64(c.CurrentSendRate()) >= c.targetMissFactor*float64(c.GetTargetSendRate()) {
		// If we are already at or above the target send rate reduced by a small margin, we can skip switching.
		return
	}

	finals := c.finalCandidates()
	// Filter finals according to adaptive alpha criterium
	n_paths_unfiltered := len(finals)
	var maxEstimate uint64
	finals, maxEstimate = c.filter_stable_switch(finals)
	/*n_valids := 0
	for _, ps := range c.probeState {
		if time.Now().Sub(ps.lastReplyTime) <= c.probeValidity {
			n_valids++
		}
	}*/

	curFP := string(c.ActivePath().Fingerprint)
	// Improved stability check:
	// Do not switch if current path reports bw share just as good
	// even if current sending rate is currently low
	// In this case, the network is likely congested and we should not switch.
	if ps, ok := c.probeState[string(curFP)]; ok {
		if ps.lastEstimate >= maxEstimate {
			return
		}
	}

	// add current path as a candiate unless down or congested
	_, congested := c.congested[curFP]
	_, down := c.down[curFP]
	if !congested && !down {
		// it should not be in finals yet, but just to be safe
		found := false
		for _, p := range finals {
			if string(p.Fingerprint) == curFP {
				found = true
				break
			}
		}
		if !found {
			finals = append(finals, c.ActivePath())
			n_paths_unfiltered++
		}
	}
	if len(finals) > 0 {
		newPath := finals[rand.Intn(len(finals))]
		// log the path switch event for traffic analysis
		oldPath := c.ActivePath()
		if oldPath.Fingerprint != newPath.Fingerprint {
			var estimatedShare interface{} = nil
			if ps, ok := c.probeState[string(newPath.Fingerprint)]; ok {
				estimatedShare = ps.lastEstimate
			}
			evt := map[string]interface{}{
				"ts":                    float64(time.Now().UnixNano()) / 1e9,
				"event":                 "path_switch",
				"trigger":               "scheduled",
				"old":                   string(oldPath.Fingerprint),
				"new":                   string(newPath.Fingerprint),
				"candidates":            len(finals),
				"candidates_unfiltered": n_paths_unfiltered,
				"estimated_share":       estimatedShare,
				"max_estimated_share":   maxEstimate,
				"current_rate":          c.CurrentSendRate(),
			}
			c.logEvent(evt)
		}

		c.switchToPath(newPath)
	}
}

// filterFinalsByAlpha returns (filteredFinals, maxLastEstimate).
// A path p is kept iff  float64(ps.lastEstimate) * c.alpha / r  >  float64(maxLastEstimate),
// where maxLastEstimate is the maximum lastEstimate over all finals that have probe state.
// We only keep paths that would not cause a switch again.
func (c *PolarisCore) filter_stable_switch(finals []*Path) ([]*Path, uint64) {
	// 1) Find max lastEstimate among finals
	var maxLast uint64
	for _, p := range finals {
		key := string(p.Fingerprint)
		if ps, ok := c.probeState[key]; ok {
			if ps.lastEstimate > maxLast {
				maxLast = ps.lastEstimate
			}
		}
	}

	// 2) Keep only those with lastEstimate * alpha / r > maxLast (strict)
	filtered := make([]*Path, 0, len(finals))
	r := 1.1 // stability factor
	for _, p := range finals {
		key := string(p.Fingerprint)
		if ps, ok := c.probeState[key]; ok {
			if float64(ps.lastEstimate)*c.alpha/r > float64(maxLast) {
				filtered = append(filtered, p)
			}
		}
	}
	return filtered, maxLast
}

// Returns paths that have been potential candidates for at least stableTime
// Only call with c.mu held.
func (c *PolarisCore) finalCandidates() []*Path {
	now := time.Now()
	var out []*Path
	for _, p := range c.potentialCandidates() {
		fp := string(p.Fingerprint)
		since, ok := c.potentialSince[fp]
		if !ok {
			continue
		}
		_, congested := c.congested[fp]
		_, down := c.down[fp]
		if now.Sub(since) >= c.stableTime && !congested && !down {
			out = append(out, p)
		}
	}
	return out
}

// Returns paths that are potential candidates, i.e., have a fresh P-probe reply.
// Only call with c.mu held.
func (c *PolarisCore) potentialCandidates() []*Path {
	var out []*Path
	now := time.Now()
	for _, p := range c.paths {
		fp := string(p.Fingerprint)
		if _, exists := c.potentialSince[fp]; exists {
			_, congested := c.congested[fp]
			_, down := c.down[fp]
			if ps, ok := c.probeState[fp]; ok &&
				now.Sub(ps.lastReplyTime) <= c.probeValidity &&
				c.lastSwitch.Add(c.RTTUpperBound).Before(ps.RequestTime) &&
				!congested && !down {
				out = append(out, p)
			}
		}
	}
	return out
}

// Returns paths that are not congested and not down.
// Only call with c.mu held.
func (c *PolarisCore) nonCongestedPaths() []*Path {
	var out []*Path
	for _, p := range c.paths {
		fp := string(p.Fingerprint)
		_, congested := c.congested[fp]
		_, down := c.down[fp]
		if !congested && !down {
			out = append(out, p)
		}
	}
	return out
}

// Returns paths that are up, i.e., not down.
// Only call with c.mu held.
func (c *PolarisCore) upPaths() []*Path {
	var out []*Path
	for _, p := range c.paths {
		fp := string(p.Fingerprint)
		_, down := c.down[fp]
		if !down {
			out = append(out, p)
		}
	}
	return out
}

// Checks all paths and updates the potential candidates.
// A path is a potential candidate if it has a fresh P-probe reply,
// meets the α×rate condition, and is not congested or down.
// Only call with c.mu held.
func (c *PolarisCore) recomputePotentialCandidates() {
	now := time.Now()
	rate := c.CurrentSendRate()

	for _, p := range c.paths {
		fp := string(p.Fingerprint)
		ps, exists := c.probeState[fp]
		if !exists {
			delete(c.potentialSince, fp)
			continue
		}
		// Reply must be fresh:
		if now.Sub(ps.lastReplyTime) > c.probeValidity ||
			c.lastSwitch.Add(c.RTTUpperBound).After(ps.RequestTime) {
			delete(c.potentialSince, fp)
			continue
		}
		// Must meet α⋅rate and not be congested or down:
		_, congested := c.congested[fp]
		_, down := c.down[fp]
		if float64(ps.lastEstimate) >= float64(rate)*c.alpha &&
			!congested && !down {
			if _, was := c.potentialSince[fp]; !was {
				c.potentialSince[fp] = now
			}
		} else {
			delete(c.potentialSince, fp)
		}
	}
}

// Checks if a path is a potential candidate based on its probe state.
// The same conditions as in recomputePotentialCandidates are applied.
func (c *PolarisCore) updateSinglePathPotential(fp string) {
	now := time.Now()
	rate := c.CurrentSendRate()
	ps := c.probeState[fp]

	// “fresh” reply?
	if now.Sub(ps.lastReplyTime) > c.probeValidity ||
		c.lastSwitch.Add(c.RTTUpperBound).After(ps.RequestTime) {
		delete(c.potentialSince, fp)
		return
	}

	// α×rate check + down/congested
	_, congested := c.congested[fp]
	_, down := c.down[fp]
	if float64(ps.lastEstimate) >= float64(rate)*c.alpha &&
		!congested && !down {
		if _, ok := c.potentialSince[fp]; !ok {
			c.potentialSince[fp] = now
		}
	} else {
		delete(c.potentialSince, fp)
	}
}

// SetTargetSendRate updates the Polaris core on the target send rate.
// This avoids unnecessary path switches, if we are already sending at the target rate.
func (c *PolarisCore) SetTargetSendRate(rateBps uint64) {
	c.targetSendRateBps.Store(rateBps)
}

// GetTargetSendRate returns the target send rate in bits per second.
func (c *PolarisCore) GetTargetSendRate() uint64 {
	return c.targetSendRateBps.Load()
}

// RecordSent must be called after each successful packet send.
// It tracks bytes in a 1-second window to estimate the real send rate.
func (c *PolarisCore) RecordSent(nBytes int) {
	c.byteCounter.Add(uint64(nBytes))
}

// returns the current send rate in bits per second
func (c *PolarisCore) CurrentSendRate() uint64 {
	return c.sendRateBps.Load()
}

// ActivePath returns the currently active path.
func (c *PolarisCore) ActivePath() *Path {
	return c.activePath.Load()
}

// Helper for logging events in Polaris if enabled.
func (c *PolarisCore) logEvent(evt map[string]interface{}) {
	if !c.logEnabled {
		return
	}
	blob, _ := json.Marshal(evt)
	log.Printf("POLARIS_LOG %s", blob)
}

func (c *PolarisCore) Close() {
	c.once.Do(func() {
		c.prober.Stop()
		close(c.stopCh)
	})
}

// Prober opens its own raw SCION socket to send P-probe SCMPs,
// and to receive probe replies, P-CA alerts and SCMP path down alerts.
type Prober struct {
	core  *PolarisCore
	paths []*Path // available paths for probing

	conn         snet.PacketConn // raw SCION conn (cooked to handle SCMP)
	local        *snet.UDPAddr
	remote       scionAddr
	proberCtx    context.Context
	proberCancel context.CancelFunc

	replies    <-chan Reply // SCMP handler pushes here
	errHandler func(error)

	lastReqTime   map[PathFingerprint]time.Time // reqID → time we sent this round's P-probe
	seq           uint16                        // global round number (wraps at 65535)
	id            uint16                        // SCMP request ID, has to be scr port of connection
	probeInterval time.Duration                 // how often to send P-probes, e.g. 1s

	stopCh chan struct{}
	once   sync.Once
}

func NewProber(core *PolarisCore,
	probeInterval time.Duration,
) *Prober {
	return &Prober{
		core:          core,
		probeInterval: probeInterval,
		errHandler:    nil,
		stopCh:        make(chan struct{}),
	}
}

func (p *Prober) Initialize(local, remote UDPAddr, paths []*Path) error {
	p.paths = paths
	p.lastReqTime = make(map[PathFingerprint]time.Time, len(paths))
	// DEBUG
	fmt.Printf("Polaris prober initialized with %d paths\n", len(paths))

	// Open a raw SCION socket to send P-probes and receive replies
	host, err := getHost()
	if err != nil {
		return err
	}
	if local.IA == remote.IA {
		return nil
	}
	replies := make(chan Reply, 2*len(p.paths))
	p.replies = replies
	handler := &PolarisSCMPHandler{replies: replies}
	sn := &snet.SCIONNetwork{
		Topology:    host.topology,
		SCMPHandler: handler,
	}
	localUDP := local.scionAddr().snetUDPAddr().Copy()
	p.proberCtx, p.proberCancel = context.WithCancel(context.Background())
	conn, err := sn.OpenRaw(p.proberCtx, localUDP.Host)
	if err != nil {
		return fmt.Errorf("polaris prober: OpenRaw: %w", err)
	}
	p.conn = conn
	localUDP.Host = conn.LocalAddr().(*net.UDPAddr)
	p.id = uint16(localUDP.Host.Port) // use the UDP port as SCMP request ID
	p.local = localUDP
	p.remote = remote.scionAddr()
	// DEBUG
	fmt.Printf("Polaris prober initialized with local %s and remote %s\n", p.local, p.remote)

	// Run the prober
	go p.drainLoop()
	go p.run()

	return nil
}

// sendProbe builds and sends a SCMP P-probe request for one path.
// HINT: check sendPings() in ping.go and Pprobe() in PolarisProbe.go for similar logic.
func (p *Prober) sendProbe(pt *Path) {
	// record send time
	now := time.Now()
	p.lastReqTime[pt.Fingerprint] = now

	// build payload
	pl := snet.SCMPPProbeRequest{
		NextHdr:           uint8(slayers.L4SCMP),
		ExtLen:            0,
		RequestIdentifier: p.id,
		SequenceNumber:    p.seq,
		CumQueuingDelay:   float16.Float16(0),
		ASIdentifier:      0,
		InterfaceID:       0,
		BottleneckShare:   float16.Inf(0),
	}

	remote := p.remote.snetUDPAddr()
	remote.Path = pt.ForwardingPath.dataplanePath
	remote.NextHop = net.UDPAddrFromAddrPort(pt.ForwardingPath.underlay)

	local := p.local
	pkt, err := packPolarisProbe(local, remote, pl)
	if err != nil {
		fmt.Printf("Failed to pack P-probe for path %s: %v\n", pt.Fingerprint, err)
		return
	}
	nextHop := remote.NextHop
	if nextHop == nil && local.IA.Equal(remote.IA) {
		// DEBUG
		fmt.Println("NextHop is nil and remote IA equals local IA")
		nextHop = &net.UDPAddr{
			IP:   remote.Host.IP,
			Port: underlay.EndhostPort,
			Zone: remote.Host.Zone,
		}
	}
	if err := p.conn.WriteTo(pkt, nextHop); err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			// fmt.Println("Prober connection closed, stopping.")
			p.Stop()
		} else {
			fmt.Printf("Failed to send P-probe for path %s: %v\n", pt.Fingerprint, err)
			return
		}
	}
	// DEBUG
	// fmt.Printf("Sent P-probe for path %s, reqID %d, seq %d\n", pt.Fingerprint, p.id, p.seq)
}

func (p *Prober) handleReply(pkt *snet.Packet, path snet.RawPath, received time.Time) {
	// DEBUG
	// fmt.Println("Received SCMP reply")
	pf, err := reversePathFingerprint(path)
	if err != nil {
		// DEBUG
		fmt.Printf("Failed to reverse path fingerprint: %v\n", err)
		return
	}
	switch s := pkt.Payload.(type) {
	case snet.SCMPEchoReply:
		// DEBUG
		// fmt.Println("Received SCMP echo reply")
		// Only accept replies from current or previous round of P-probes.
		if s.SeqNumber > p.seq || s.SeqNumber < p.seq-1 {
			// DEBUG
			fmt.Printf("Received SCMP echo reply with unexpected seq %d, expected %d or %d\n",
				s.SeqNumber, p.seq, p.seq-1)
			return
		}
		sent, ok := p.lastReqTime[pf]
		if !ok {
			// DEBUG
			fmt.Printf("No last request time found for path %s\n", pf)
			return
		}
		var scmpPp slayers.SCMPPProbeRequest
		if err := scmpPp.DecodeFromBytes(s.Payload, gopacket.NilDecodeFeedback); err != nil {
			// DEBUG
			fmt.Printf("Failed to decode SCMP P-probe reply: %v\n", err)
			return
		}
		estimatedBps := uint64(float64(scmpPp.BottleneckShare.Float32()) * 1000) // convert from kbps to bps
		p.core.HandleProbeReply(string(pf), estimatedBps, sent, received)
		// DEBUG
		// fmt.Printf("Received P-probe reply for path %s, reqID %d, seq %d, estimated share %d bps\n",
		// 	string(pf), s.Identifier, s.SeqNumber, estimatedBps)
	case snet.SCMPPCongestionAlert:
		// DEBUG
		if s.SequenceNumber > p.seq || s.SequenceNumber < p.seq-1 {
			// DEBUG
			fmt.Printf("Received P-CA alert with unexpected seq %d, expected %d or %d\n",
				s.SequenceNumber, p.seq, p.seq-1)
			return
		}
		p.core.HandlePCA(string(pf))
		// DEBUG
		fmt.Printf("Received P-CA alert for path %s, reqID %d, seq %d\n",
			string(pf), s.RequestIdentifier, s.SequenceNumber)
	case snet.SCMPExternalInterfaceDown:
		p.core.HandlePathDown(string(pf))
		// DEBUG
		fmt.Printf("Received SCMP external interface down for path %s\n", pf)
	case snet.SCMPInternalConnectivityDown:
		p.core.HandlePathDown(string(pf))
		// DEBUG
		fmt.Printf("Received SCMP internal connectivity down for path %s\n", pf)
	}
}

func (p *Prober) run() {
	ticker := time.NewTicker(p.probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.seq++
			for _, pt := range p.paths {
				p.sendProbe(pt)
			}
			// DEBUG
			// fmt.Printf("Sent P-probes for all %d paths at seq %d\n", len(p.paths), p.seq)
		case reply := <-p.replies:
			if reply.Error != nil {
				continue
			}
			p.handleReply(reply.Packet, reply.Path, reply.Received)
		}
	}
}

// Might not be needed but won't hurt (modeled after the Pinger)
func (p *Prober) drainLoop() {
	var last time.Time
	for {
		select {
		case <-p.stopCh:
			return
		default:
			var pkt snet.Packet
			var ov net.UDPAddr
			if err := p.conn.ReadFrom(&pkt, &ov); err != nil && p.errHandler != nil {
				// DEBUG
				fmt.Printf("Drain Loop read error: %v\n", err)
				// Rate limit the error reports.
				if now := time.Now(); now.Sub(last) > 500*time.Millisecond {
					p.errHandler(serrors.Wrap("reading packet", err))
					last = now
				}
			} else {
				// DEBUG
				fmt.Println("Drain Loop received packet")
				if pkt.Payload != nil {
					// DEBUG
					fmt.Println("Drain Loop received non-nil payload")
				}
			}
		}
	}
}

func (p *Prober) Stop() {
	p.once.Do(func() {
		p.proberCancel()
		close(p.stopCh)
		p.conn.Close()
	})
}

type Reply struct {
	Received time.Time
	Packet   *snet.Packet
	Path     snet.RawPath
	Error    error
}

type PolarisSCMPHandler struct {
	replies chan<- Reply
}

func (h *PolarisSCMPHandler) Handle(pkt *snet.Packet) error {
	// DEBUG
	// fmt.Println("PolarisSCMPHandler received packet")
	err := h.handle(pkt)
	h.replies <- Reply{
		Received: time.Now(),
		Packet:   pkt,
		Path:     pkt.Path.(snet.RawPath),
		Error:    err,
	}
	return nil
}

func (h *PolarisSCMPHandler) handle(pkt *snet.Packet) error {
	if pkt.Payload == nil {
		return serrors.New("no v2 payload found")
	}
	return nil
}

func packPolarisProbe(local, remote *snet.UDPAddr, req snet.SCMPPProbeRequest) (*snet.Packet, error) {
	if _, ok := remote.Path.(path.Empty); (remote.Path == nil || ok) && !local.IA.Equal(remote.IA) {
		return nil, serrors.New("no path for remote ISD-AS", "local", local.IA, "remote", remote.IA)
	}
	localIP, ok := netip.AddrFromSlice(local.Host.IP)
	if !ok {
		return nil, serrors.New("invalid local IP", "local", local.Host.IP)
	}
	remoteIP, ok := netip.AddrFromSlice(remote.Host.IP)
	if !ok {
		return nil, serrors.New("invalid remote IP", "remote", remote.Host.IP)
	}

	// DEBUG
	// fmt.Printf("Packing P-probe from %s to %s\n", localIP, remoteIP)

	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA:   remote.IA,
				Host: addr.HostIP(remoteIP),
			},
			Source: snet.SCIONAddress{
				IA:   local.IA,
				Host: addr.HostIP(localIP),
			},
			Path:    remote.Path,
			Payload: req,
		},
	}
	return pkt, nil
}
