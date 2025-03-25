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

// package bwtest contains the definitions shared between bwtestserver and
// bwtestclient.
package bwtest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Maximum duration of a bandwidth test
	MaxDuration time.Duration = time.Minute * 5
	// Maximum amount of time to wait for straggler packets
	StragglerWaitPeriod time.Duration = time.Second
	// Allow sending beyond the finish time by this amount
	GracePeriodSend time.Duration = time.Millisecond * 10
	// Min packet size is 4 bytes, so that 32-bit integer fits in
	// Ideally packet size > 4 bytes, so that part of the PRG is also in packet
	MinPacketSize int64 = 4
	// Max packet size to avoid allocation of too large a buffer, make it large enough for jumbo frames++
	MaxPacketSize int64 = 66000
	// Make sure the port number is a port the server application can connect to
	MinPort uint16 = 1024
	// The number of intervals for which loss metrics are kept
	LossMetricsWindowSize = 3
	// Interval for counting received packets to comput loss
	LossMetricsMeasurementInterval = time.Second / 4
	// Interval for sending loss updates
	LossMetricsUpdateInterval = LossMetricsMeasurementInterval / 2
)

type Parameters struct {
	BwtestDuration time.Duration
	PacketSize     int64
	NumPackets     int64
	PrgKey         []byte
	Port           uint16
}

type Result struct {
	NumPacketsReceived int64
	CorrectlyReceived  int64
	IPAvar             int64
	IPAmin             int64
	IPAavg             int64
	IPAmax             int64
	// Contains the client's sending PRG key, so that the result can be uniquely identified
	// Only requests that contain the correct key can obtain the result
	PrgKey []byte
}

func Check(e error) {
	if e != nil {
		fmt.Fprintln(os.Stderr, "Fatal:", e)
		os.Exit(1)
	}
}

type prgFiller struct {
	aes cipher.Block
	buf []byte
}

func newPrgFiller(key []byte) *prgFiller {
	aesCipher, err := aes.NewCipher(key)
	Check(err)
	return &prgFiller{
		aes: aesCipher,
		buf: make([]byte, aes.BlockSize),
	}
}

// Fill the buffer with AES PRG in counter mode
// The value of the ith 16-byte block is simply an encryption of i under the key
func (f *prgFiller) Fill(iv int, data []byte) {
	memzero(f.buf)
	i := uint32(iv)
	j := 0
	for j <= len(data)-aes.BlockSize {
		binary.LittleEndian.PutUint32(f.buf, i)
		f.aes.Encrypt(data, f.buf) // BUG(matzf): this should be data[j:]! data is mostly left zero.
		j = j + aes.BlockSize
		i = i + uint32(aes.BlockSize)
	}
	// Check if fewer than BlockSize bytes are required for the final block
	if j < len(data) {
		binary.LittleEndian.PutUint32(f.buf, i)
		f.aes.Encrypt(f.buf, f.buf)
		copy(data[j:], f.buf[:len(data)-j])
	}
}

func memzero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// Encode Result into a sufficiently large byte buffer that is passed in, return the number of bytes written
func EncodeResult(res Result, buf []byte) (int, error) {
	var bb bytes.Buffer
	enc := gob.NewEncoder(&bb)
	err := enc.Encode(res)
	copy(buf, bb.Bytes())
	return bb.Len(), err
}

// Decode Result from byte buffer that is passed in, returns Result structure and number of bytes consumed
func DecodeResult(buf []byte) (Result, int, error) {
	bb := bytes.NewBuffer(buf)
	is := bb.Len()
	dec := gob.NewDecoder(bb)
	var v Result
	err := dec.Decode(&v)
	return v, is - bb.Len(), err
}

// Encode Parameters into a sufficiently large byte buffer that is passed in, return the number of bytes written
func EncodeParameters(bwtp Parameters, buf []byte) (int, error) {
	var bb bytes.Buffer
	enc := gob.NewEncoder(&bb)
	err := enc.Encode(bwtp)
	copy(buf, bb.Bytes())
	return bb.Len(), err
}

// Decode Parameters from byte buffer that is passed in, returns BwtestParameters structure and number of bytes consumed
func DecodeParameters(buf []byte) (Parameters, int, error) {
	bb := bytes.NewBuffer(buf)
	is := bb.Len()
	dec := gob.NewDecoder(bb)
	var v Parameters
	err := dec.Decode(&v)
	return v, is - bb.Len(), err
}

func HandleDCConnSend(bwp Parameters, udpConnection io.Writer) error {
	sb := make([]byte, bwp.PacketSize)
	t0 := time.Now()
	interPktInterval := bwp.BwtestDuration
	if bwp.NumPackets > 1 {
		interPktInterval = bwp.BwtestDuration / time.Duration(bwp.NumPackets-1)
	}
	prgFiller := newPrgFiller(bwp.PrgKey)
	for i := int64(0); i < bwp.NumPackets; i++ {
		time.Sleep(time.Until(t0.Add(interPktInterval * time.Duration(i))))
		// Send packet now
		prgFiller.Fill(int(i*bwp.PacketSize), sb)
		// Place packet number at the beginning of the packet, overwriting some PRG data
		binary.LittleEndian.PutUint32(sb, uint32(i*bwp.PacketSize))
		_, err := udpConnection.Write(sb)
		if err != nil {
			return err
		}
	}
	return nil
}

func HandleDCConnReceive(bwp Parameters, udpConnection io.Reader, lossMetrics *LossMetrics) Result {
	var numPacketsReceived int64
	var correctlyReceived int64
	interPacketArrivalTime := make(map[int]int64, bwp.NumPackets)
	recBuf := make([]byte, bwp.PacketSize+1)
	cmpBuf := make([]byte, bwp.PacketSize)
	prgFiller := newPrgFiller(bwp.PrgKey)
	for correctlyReceived < bwp.NumPackets {
		n, err := udpConnection.Read(recBuf)
		if err != nil {
			break
		}
		numPacketsReceived++
		if int64(n) != bwp.PacketSize {
			continue
		}
		iv := int64(binary.LittleEndian.Uint32(recBuf))
		seqNo := int(iv / bwp.PacketSize)
		interPacketArrivalTime[seqNo] = time.Now().UnixNano()
		prgFiller.Fill(int(iv), cmpBuf)
		binary.LittleEndian.PutUint32(cmpBuf, uint32(iv))
		if bytes.Equal(recBuf[:bwp.PacketSize], cmpBuf) {
			correctlyReceived++
			// Increment our loss metric counter for a correctly received packet.
			if lossMetrics != nil {
				lossMetrics.Increment()
			}
		}
	}
	res := Result{
		NumPacketsReceived: numPacketsReceived,
		CorrectlyReceived:  correctlyReceived,
		PrgKey:             bwp.PrgKey,
	}
	res.IPAvar, res.IPAmin, res.IPAavg, res.IPAmax = aggrInterArrivalTime(interPacketArrivalTime)
	return res
}

func aggrInterArrivalTime(bwr map[int]int64) (IPAvar, IPAmin, IPAavg, IPAmax int64) {
	// reverse map, mapping timestamps to sequence numbers
	revMap := make(map[int64]int, len(bwr))
	keys := make([]int64, 0, len(bwr)) // keys are the timestamps of the received packets
	// fill the reverse map and the keep track of the timestamps
	for k, v := range bwr {
		revMap[v] = k
		keys = append(keys, v)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] }) // sorted timestamps of the received packets

	// We keep only the interarrival times of successive packets with no drops
	var iat []int64
	i := 1
	for i < len(keys) {
		if revMap[keys[i-1]]+1 == revMap[keys[i]] { // valid measurement without reordering, include
			iat = append(iat, keys[i]-keys[i-1]) // resulting interarrival time
		}
		i += 1
	}

	// Compute variance and average
	var average float64 = 0
	IPAmin = -1
	for _, v := range iat {
		if v > IPAmax {
			IPAmax = v
		}
		if v < IPAmin || IPAmin == -1 {
			IPAmin = v
		}
		average += float64(v) / float64(len(iat))
	}
	IPAvar = IPAmax - int64(average)
	IPAavg = int64(average)
	return
}

// The following code implements the loss metrics data structure and functions.

// RemoteLossUpdate stores the most recent loss update received from the remote side.
type RemoteLossUpdate struct {
	UpdateCounter atomic.Uint32
	SlidingWindow []float32 // loss percentages for each interval
	ReceivedAt    time.Time
}

// LossMetrics tracks the number of correctly received packets in the current interval
// and maintains a sliding window of raw measurements from the last N intervals.
type LossMetrics struct {
	current      int64   // current interval's counter (number of correctly received packets)
	measurements []int64 // raw measurements (number of correctly received packets per interval)
	windowSize   int
	mu           sync.Mutex

	updateCounter    uint32           // counter for outgoing updates
	lastRemoteUpdate RemoteLossUpdate // most recent remote update
	muRemote         sync.Mutex       // mutex for remote updates
}

// NewLossMetrics initializes a new LossMetrics with the desired sliding window size.
func NewLossMetrics(windowSize int) *LossMetrics {
	return &LossMetrics{
		windowSize:    windowSize,
		measurements:  make([]int64, 0, windowSize),
		updateCounter: 0,
	}
}

// Increment increases the current counter by one.
// Call this in the packet verification section when a packet is correctly received.
func (lm *LossMetrics) Increment() {
	atomic.AddInt64(&lm.current, 1)
}

// FinishInterval finalizes the current interval by appending the current count
// to the sliding window and then resetting the counter.
func (lm *LossMetrics) FinishInterval() int64 {
	current := atomic.SwapInt64(&lm.current, 0)
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.measurements = append(lm.measurements, current)
	if len(lm.measurements) > lm.windowSize {
		lm.measurements = lm.measurements[1:]
	}
	lm.updateCounter++
	return current
}

// GetMeasurements returns a copy of the sliding window measurements.
func (lm *LossMetrics) GetMeasurements() []int64 {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	cpy := make([]int64, len(lm.measurements))
	copy(cpy, lm.measurements)
	return cpy
}

// ResetWindow clears the sliding window
func (lm *LossMetrics) ResetWindow() {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.measurements = lm.measurements[:0]
}

// Helper function to compute the loss percentage based on the expected number of packets per interval.
func computeLossPercentage(count int64, expectedPerInterval float64) float32 {
	lossPercent := 0.0
	if expectedPerInterval > 0 {
		loss := (expectedPerInterval - float64(count)) * 100.0 / expectedPerInterval
		if loss < 0 {
			loss = 0
		}
		lossPercent = loss
	}
	return float32(lossPercent)
}

// StartMonitoring starts a ticker that every measurementInterval finalizes the current interval,
// computes the loss percentage based on expectedPerInterval, and prints it for debugging.
// It runs until stopChan is closed.
func (lm *LossMetrics) StartMonitoring(measurementInterval time.Duration, expectedPerInterval float64, stopChan <-chan struct{}) {
	ticker := time.NewTicker(measurementInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				intervalCount := lm.FinishInterval()
				lossPercent := computeLossPercentage(intervalCount, expectedPerInterval)
				fmt.Printf("LossMetrics - Interval measured: %d packets, expected %.2f packets, loss: %.2f%%\n",
					intervalCount, expectedPerInterval, lossPercent)
			case <-stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

// GenerateUpdate encodes the current sliding window into a loss update message.
// Each raw measurement is converted to a loss percentage using:
//
//	loss% = max(0, (expected - measurement)/expected * 100)
//
// Message format:
//
//	Byte 0: 'L' (loss update identifier)
//	Bytes 1-4: update counter (uint32, big endian)
//	Bytes 5-8: window length (uint32, big endian)
//	Then for each measurement: 4 bytes (float32, big endian) representing loss percentage.
func (lm *LossMetrics) GenerateUpdate(expectedPerInterval float64) ([]byte, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	buf := new(bytes.Buffer)
	// Write message type.
	if err := buf.WriteByte('L'); err != nil {
		return nil, err
	}
	// Write update counter.
	if err := binary.Write(buf, binary.BigEndian, lm.updateCounter); err != nil {
		return nil, err
	}
	// Write window length.
	windowLen := uint32(len(lm.measurements))
	if err := binary.Write(buf, binary.BigEndian, windowLen); err != nil {
		return nil, err
	}
	// Write each measurement as a float32 loss percentage.
	for _, count := range lm.measurements {
		var lossPercent float32 = computeLossPercentage(count, expectedPerInterval)
		if err := binary.Write(buf, binary.BigEndian, lossPercent); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// DecodeLossUpdate decodes a loss update message and returns a RemoteLossUpdate.
// It expects the format defined in GenerateUpdate.
func DecodeLossUpdate(data []byte) (*RemoteLossUpdate, error) {
	r := bytes.NewReader(data)
	// Check message type.
	msgType, err := r.ReadByte()
	if err != nil {
		return &RemoteLossUpdate{}, err
	}
	if msgType != 'L' {
		return &RemoteLossUpdate{}, fmt.Errorf("invalid loss update message type: %c", msgType)
	}
	var counter uint32
	if err := binary.Read(r, binary.BigEndian, &counter); err != nil {
		return &RemoteLossUpdate{}, err
	}
	var windowLen uint32
	if err := binary.Read(r, binary.BigEndian, &windowLen); err != nil {
		return &RemoteLossUpdate{}, err
	}
	slidingWindow := make([]float32, windowLen)
	for i := uint32(0); i < windowLen; i++ {
		var lossPercent float32
		if err := binary.Read(r, binary.BigEndian, &lossPercent); err != nil {
			return &RemoteLossUpdate{}, err
		}
		slidingWindow[i] = lossPercent
	}
	remoteLossUpdate := RemoteLossUpdate{
		SlidingWindow: slidingWindow,
		ReceivedAt:    time.Now(),
	}
	remoteLossUpdate.UpdateCounter.Store(counter)
	return &remoteLossUpdate, nil
}

// ProcessRemoteUpdate decodes an incoming loss update message and stores it
// if it is more recent than the currently stored update.
func (lm *LossMetrics) ProcessRemoteUpdate(data []byte) (uint32, error) {
	update, err := DecodeLossUpdate(data)
	if err != nil {
		return 0, err
	}
	lm.muRemote.Lock()
	defer lm.muRemote.Unlock()
	// Only update if the new counter is greater than the stored one.
	lastRemoteUpdateCounter := lm.lastRemoteUpdate.UpdateCounter.Load()
	updateCounter := update.UpdateCounter.Load()
	if updateCounter > lastRemoteUpdateCounter {
		lm.lastRemoteUpdate.SlidingWindow = update.SlidingWindow
		lm.lastRemoteUpdate.ReceivedAt = update.ReceivedAt
		lm.lastRemoteUpdate.UpdateCounter.Store(updateCounter)
	} else {
		// Optionally log that an older or duplicate update was ignored.
		fmt.Printf("Ignored remote loss update with counter %d (current: %d)\n",
			updateCounter, lastRemoteUpdateCounter)
	}
	return updateCounter, nil
}

// GetLastRemoteUpdate returns a copy of the last remote loss update received.
func (lm *LossMetrics) GetLastRemoteUpdate() *RemoteLossUpdate {
	lm.muRemote.Lock()
	defer lm.muRemote.Unlock()
	cpy := make([]float32, len(lm.lastRemoteUpdate.SlidingWindow))
	copy(cpy, lm.lastRemoteUpdate.SlidingWindow)
	remoteLossUpdate := RemoteLossUpdate{
		SlidingWindow: cpy,
		ReceivedAt:    lm.lastRemoteUpdate.ReceivedAt,
	}
	remoteLossUpdate.UpdateCounter.Store(lm.lastRemoteUpdate.UpdateCounter.Load())
	return &remoteLossUpdate
}

// For better performance, if only the update counter is needed
func (lm *LossMetrics) GetLastRemoteUpdateCounter() uint32 {
	return lm.lastRemoteUpdate.UpdateCounter.Load()
}

// StartSendingUpdates starts a goroutine that, every updateInterval,
// generates a loss update message (using the current sliding window) and sends it via sendFunc.
// It continues until stopChan is closed.
func (lm *LossMetrics) StartSendingUpdates(updateInterval time.Duration, expectedPerInterval float64, wouldSwitch func([]float32) bool, sendFunc func([]byte) error, stopChan <-chan struct{}) {
	ticker := time.NewTicker(updateInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				// First check if we should send an update.
				measurements := lm.GetMeasurements()
				losses := make([]float32, len(measurements))
				for i, count := range measurements {
					losses[i] = computeLossPercentage(count, expectedPerInterval)
				}
				if !wouldSwitch(losses) {
					continue
				}
				// Generate the update message.
				msg, err := lm.GenerateUpdate(expectedPerInterval)
				if err != nil {
					fmt.Printf("Error generating loss update: %v\n", err)
					continue
				}
				// Send the update using the provided callback.
				if err := sendFunc(msg); err != nil {
					fmt.Printf("Error sending loss update: %v\n", err)
				} else {
					fmt.Printf("Sent loss update (counter: %d)\n", lm.updateCounter)
				}
			case <-stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}
