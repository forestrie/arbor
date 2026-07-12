// Package metrics provides Prometheus metrics for the sealer service.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metric handles for the sealer service.
type Metrics struct {
	// Counters
	PollsTotal                *prometheus.CounterVec
	LogsCheckpointedTotal     prometheus.Counter
	MessagesProcessedTotal    prometheus.Counter
	MessagesAcknowledgedTotal *prometheus.CounterVec
	SealTriggerTotal          *prometheus.CounterVec

	// Histograms
	MessagesPerPoll    prometheus.Histogram
	PollDuration       prometheus.Histogram
	CheckpointDuration prometheus.Histogram
	CheckpointLag      prometheus.Histogram

	// Gauges
	DelegationLeaseExpiry prometheus.Gauge
}

// NewMetrics creates and registers all metrics with the provided registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		PollsTotal:                newPollsTotal(),
		LogsCheckpointedTotal:     newLogsCheckpointedTotal(),
		MessagesProcessedTotal:    newMessagesProcessedTotal(),
		MessagesAcknowledgedTotal: newMessagesAcknowledgedTotal(),
		SealTriggerTotal:          newSealTriggerTotal(),
		MessagesPerPoll:           newMessagesPerPoll(),
		PollDuration:              newPollDuration(),
		CheckpointDuration:        newCheckpointDuration(),
		CheckpointLag:             newCheckpointLag(),
		DelegationLeaseExpiry:     newDelegationLeaseExpiry(),
	}

	reg.MustRegister(
		m.PollsTotal,
		m.LogsCheckpointedTotal,
		m.MessagesProcessedTotal,
		m.MessagesAcknowledgedTotal,
		m.SealTriggerTotal,
		m.MessagesPerPoll,
		m.PollDuration,
		m.CheckpointDuration,
		m.CheckpointLag,
		m.DelegationLeaseExpiry,
	)

	return m
}

// RecordPoll increments the polls counter with the given result label.
// Result should be one of: "empty", "success", "failure".
func (m *Metrics) RecordPoll(result string) {
	m.PollsTotal.WithLabelValues(result).Inc()
}

// IncLogsCheckpointed increments the logs checkpointed counter.
func (m *Metrics) IncLogsCheckpointed() {
	m.LogsCheckpointedTotal.Inc()
}

// AddMessagesProcessed increments the messages processed counter by n.
func (m *Metrics) AddMessagesProcessed(n int) {
	m.MessagesProcessedTotal.Add(float64(n))
}

// RecordAck increments the messages acknowledged counter with success or failure status.
func (m *Metrics) RecordAck(success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	m.MessagesAcknowledgedTotal.WithLabelValues(status).Inc()
}

// ObserveMessagesPerPoll records the number of messages returned in a poll.
func (m *Metrics) ObserveMessagesPerPoll(n int) {
	m.MessagesPerPoll.Observe(float64(n))
}

// ObservePollDuration records the duration of a poll cycle in seconds.
func (m *Metrics) ObservePollDuration(seconds float64) {
	m.PollDuration.Observe(seconds)
}

// ObserveCheckpointDuration records the duration of a checkpoint operation in seconds.
func (m *Metrics) ObserveCheckpointDuration(seconds float64) {
	m.CheckpointDuration.Observe(seconds)
}

// SetDelegationLeaseExpiry sets the delegation lease expiry timestamp.
func (m *Metrics) SetDelegationLeaseExpiry(unixSeconds float64) {
	m.DelegationLeaseExpiry.Set(unixSeconds)
}

// RecordSealTrigger increments the seal trigger counter for the given wake
// source. Source must be one of the SealTriggerSource* constants; anything
// else is recorded as "unknown" to keep label cardinality bounded.
func (m *Metrics) RecordSealTrigger(source string) {
	switch source {
	case SealTriggerSourceR2Event, SealTriggerSourceRangerHint,
		SealTriggerSourceLongPoll, SealTriggerSourceSweep:
	default:
		source = SealTriggerSourceUnknown
	}
	m.SealTriggerTotal.WithLabelValues(source).Inc()
}

// ObserveCheckpointLag records the seconds from the massif's last entry
// idtimestamp to the checkpoint write (ADR-0007 trigger latency).
func (m *Metrics) ObserveCheckpointLag(seconds float64) {
	m.CheckpointLag.Observe(seconds)
}
