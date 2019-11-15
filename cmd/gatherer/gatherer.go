package main

import (
	"bytes"
	"fmt"
	"github.com/intel/cri-resource-manager/pkg/metrics"
	_ "github.com/intel/cri-resource-manager/pkg/metrics/register"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"os"
)

func main() {

	metricFamilies := make(chan *dto.MetricFamily)

	metricCollector, err := metrics.NewMetric(metricFamilies, metrics.GetDefaultConfig())
	if err != nil {
		fmt.Printf("Unable to create Metrics Collector: %+v\n", err)
		os.Exit(1)
	}
	defer metricCollector.Close()

	for mf := range metricFamilies {
		out := &bytes.Buffer{}
		if _, err = expfmt.MetricFamilyToText(out, mf); err != nil {
			panic(err)
		}
		fmt.Print(out)
	}
}
