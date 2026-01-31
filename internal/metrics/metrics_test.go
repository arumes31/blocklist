package metrics

import (
	"testing"
)

func TestMetricsInitialized(t *testing.T) {
	if MetricBlocksTotal == nil { t.Error("MetricBlocksTotal is nil") }
	if MetricUnblocksTotal == nil { t.Error("MetricUnblocksTotal is nil") }
	if MetricHttpDuration == nil { t.Error("MetricHttpDuration is nil") }
	if MetricRedisDuration == nil { t.Error("MetricRedisDuration is nil") }
}
