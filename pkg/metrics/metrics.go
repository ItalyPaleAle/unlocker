package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type UnlockerMetrics struct {
	requests *prometheus.CounterVec
	results  *prometheus.CounterVec
	latency  *prometheus.SummaryVec
}

func (m *UnlockerMetrics) Init() {
	m.requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "unlocker_requests_total",
		Help: "The total number of requests per operation per key",
	}, []string{"operation", "key"})

	m.results = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "unlocker_results_total",
		Help: "The total number of results per status",
	}, []string{"status"})

	m.latency = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name: "unlocker_keyvault_latency_ms",
		Help: "The latency of requests to Azure Key Vault",
	}, []string{"vault"})
}

func (m UnlockerMetrics) RecordRequest(operation string, key string) {
	m.requests.
		WithLabelValues(operation, key).
		Inc()
}

func (m UnlockerMetrics) RecordResult(status string) {
	m.results.
		WithLabelValues(status).
		Inc()
}

func (m UnlockerMetrics) RecordLatency(vault string, latency time.Duration) {
	m.latency.
		WithLabelValues(vault).
		Observe(float64(latency.Microseconds()) / 1000)
}
