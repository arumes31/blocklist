package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	MetricBlocksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Namespace: "blocklist", Name: "blocks_total", Help: "Number of IP blocks"},
		[]string{"source"},
	)
	MetricUnblocksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Namespace: "blocklist", Name: "unblocks_total", Help: "Number of IP unblocks"},
		[]string{"source"},
	)
	MetricHttpDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "blocklist",
			Name:      "http_duration_seconds",
			Help:      "Latency of HTTP requests in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"path", "method", "status"},
	)
	MetricRedisDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "blocklist",
			Name:      "redis_op_duration_seconds",
			Help:      "Latency of Redis operations in seconds",
			Buckets:   []float64{.001, .002, .005, .01, .02, .05, .1},
		},
		[]string{"operation"},
	)
)

func init() {
	prometheus.MustRegister(MetricBlocksTotal)
	prometheus.MustRegister(MetricUnblocksTotal)
	prometheus.MustRegister(MetricHttpDuration)
	prometheus.MustRegister(MetricRedisDuration)
}
