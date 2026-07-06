// Package metrics provides Prometheus metrics for the publisher service.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metric handles for the publisher service.
type Metrics struct {
	// Queue counters/histograms
	PollsTotal                *prometheus.CounterVec
	MessagesProcessedTotal    prometheus.Counter
	MessagesAcknowledgedTotal *prometheus.CounterVec
	MessagesPerPoll           prometheus.Histogram
	PollDuration              prometheus.Histogram

	// Publish outcomes
	PublishTotal    *prometheus.CounterVec // label: status
	RevertsTotal    *prometheus.CounterVec // label: reason
	PublishDuration prometheus.Histogram

	// Per-chain gauges
	AnchorLag *prometheus.GaugeVec // labels: chain_id, contract — seals ahead of chain
	KeyBalWei *prometheus.GaugeVec // label: chain_id — publisher EOA balance
}

// NewMetrics creates and registers all metrics with the provided registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		PollsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "publisher_polls_total",
			Help: "Queue polls by result (empty, partial, full, failure).",
		}, []string{"result"}),
		MessagesProcessedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "publisher_messages_processed_total",
			Help: "Checkpoint notifications processed.",
		}),
		MessagesAcknowledgedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "publisher_messages_acknowledged_total",
			Help: "Queue acknowledgements by status (success, failure).",
		}, []string{"status"}),
		MessagesPerPoll: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "publisher_messages_per_poll",
			Help:    "Messages returned per queue poll.",
			Buckets: prometheus.LinearBuckets(0, 4, 9),
		}),
		PollDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "publisher_poll_duration_seconds",
			Help:    "Queue poll round-trip duration.",
			Buckets: prometheus.DefBuckets,
		}),
		PublishTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "publisher_publish_total",
			Help: "Publish attempts by terminal status (published, already_anchored, owner_not_anchored, chain_not_configured, reverted).",
		}, []string{"status"}),
		RevertsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "publisher_reverts_total",
			Help: "Reverted submissions by decoded reason.",
		}, []string{"reason"}),
		PublishDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "publisher_publish_duration_seconds",
			Help:    "One-shot publish (resolve+assemble+submit) duration.",
			Buckets: prometheus.DefBuckets,
		}),
		AnchorLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "publisher_anchor_lag_size",
			Help: "Sealed mmr size minus on-chain size at last attempt, per chain/contract.",
		}, []string{"chain_id", "contract"}),
		KeyBalWei: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "publisher_key_balance_wei",
			Help: "Publisher EOA balance per chain (wei).",
		}, []string{"chain_id"}),
	}

	reg.MustRegister(
		m.PollsTotal, m.MessagesProcessedTotal, m.MessagesAcknowledgedTotal,
		m.MessagesPerPoll, m.PollDuration,
		m.PublishTotal, m.RevertsTotal, m.PublishDuration,
		m.AnchorLag, m.KeyBalWei,
	)
	return m
}

func (m *Metrics) RecordPoll(result string) { m.PollsTotal.WithLabelValues(result).Inc() }

func (m *Metrics) AddMessagesProcessed(n int) { m.MessagesProcessedTotal.Add(float64(n)) }

func (m *Metrics) RecordAck(success bool) {
	status := "failure"
	if success {
		status = "success"
	}
	m.MessagesAcknowledgedTotal.WithLabelValues(status).Inc()
}

func (m *Metrics) ObserveMessagesPerPoll(n int) { m.MessagesPerPoll.Observe(float64(n)) }

func (m *Metrics) ObservePollDuration(s float64) { m.PollDuration.Observe(s) }

// RecordPublish counts a terminal publish outcome (and the reason when reverted).
func (m *Metrics) RecordPublish(status, reason string) {
	if m == nil {
		return
	}
	m.PublishTotal.WithLabelValues(status).Inc()
	if reason != "" {
		m.RevertsTotal.WithLabelValues(reason).Inc()
	}
}

func (m *Metrics) ObservePublishDuration(s float64) {
	if m != nil {
		m.PublishDuration.Observe(s)
	}
}

// SetAnchorLag records how many seals the sealed state is ahead of the chain.
func (m *Metrics) SetAnchorLag(chainID, contract string, lag float64) {
	if m != nil {
		m.AnchorLag.WithLabelValues(chainID, contract).Set(lag)
	}
}

// SetKeyBalance records the publisher EOA balance on a chain.
func (m *Metrics) SetKeyBalance(chainID string, wei float64) {
	if m != nil {
		m.KeyBalWei.WithLabelValues(chainID).Set(wei)
	}
}

// Handler returns an http.Handler that serves Prometheus metrics.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
}
