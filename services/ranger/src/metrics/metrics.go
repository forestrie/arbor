// Package metrics provides Prometheus metrics for the ranger service.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metric handles for the ranger service.
type Metrics struct {
	// Counters
	PollsTotal                   *prometheus.CounterVec
	EntriesProcessedTotal        prometheus.Counter
	AcksTotal                    *prometheus.CounterVec
	SealHintsPublishedTotal      prometheus.Counter
	SealHintPublishFailuresTotal prometheus.Counter

	// Histograms
	EntriesPerPoll prometheus.Histogram
	PollDuration   prometheus.Histogram
	CommitDuration prometheus.Histogram

	// Gauges
	BatchFullnessRatio prometheus.Gauge
	ShardCount         prometheus.Gauge
}

// NewMetrics creates and registers all metrics with the provided registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		PollsTotal:                   newPollsTotal(),
		EntriesProcessedTotal:        newEntriesProcessedTotal(),
		AcksTotal:                    newAcksTotal(),
		SealHintsPublishedTotal:      newSealHintsPublishedTotal(),
		SealHintPublishFailuresTotal: newSealHintPublishFailuresTotal(),
		EntriesPerPoll:               newEntriesPerPoll(),
		PollDuration:                 newPollDuration(),
		CommitDuration:               newCommitDuration(),
		BatchFullnessRatio:           newBatchFullnessRatio(),
		ShardCount:                   newShardCount(),
	}

	reg.MustRegister(
		m.PollsTotal,
		m.EntriesProcessedTotal,
		m.AcksTotal,
		m.SealHintsPublishedTotal,
		m.SealHintPublishFailuresTotal,
		m.EntriesPerPoll,
		m.PollDuration,
		m.CommitDuration,
		m.BatchFullnessRatio,
		m.ShardCount,
	)

	return m
}

// RecordPoll increments the polls counter with the given result label.
// Result should be one of: "empty", "partial", "full".
func (m *Metrics) RecordPoll(result string) {
	m.PollsTotal.WithLabelValues(result).Inc()
}

// AddEntriesProcessed increments the entries processed counter by n.
func (m *Metrics) AddEntriesProcessed(n int) {
	m.EntriesProcessedTotal.Add(float64(n))
}

// RecordAck increments the acks counter with success or failure status.
func (m *Metrics) RecordAck(success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	m.AcksTotal.WithLabelValues(status).Inc()
}

// ObserveEntriesPerPoll records the number of entries returned in a poll.
func (m *Metrics) ObserveEntriesPerPoll(n int) {
	m.EntriesPerPoll.Observe(float64(n))
}

// ObservePollDuration records the duration of a poll cycle in seconds.
func (m *Metrics) ObservePollDuration(seconds float64) {
	m.PollDuration.Observe(seconds)
}

// ObserveCommitDuration records the duration of a commit operation in seconds.
func (m *Metrics) ObserveCommitDuration(seconds float64) {
	m.CommitDuration.Observe(seconds)
}

// SetBatchFullness sets the batch fullness ratio (0.0 to 1.0).
func (m *Metrics) SetBatchFullness(ratio float64) {
	m.BatchFullnessRatio.Set(ratio)
}

// SetShardCount sets the current number of shards being polled.
func (m *Metrics) SetShardCount(n int) {
	m.ShardCount.Set(float64(n))
}

// RecordSealHintPublish increments the seal hint published/failed counters
// (ADR-0007 phase 1).
func (m *Metrics) RecordSealHintPublish(success bool) {
	if success {
		m.SealHintsPublishedTotal.Inc()
		return
	}
	m.SealHintPublishFailuresTotal.Inc()
}
