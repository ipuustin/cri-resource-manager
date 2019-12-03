// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resmgr

import (
	"bytes"
	"strings"

	model "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"

	"github.com/intel/cri-resource-manager/pkg/avx"
	"github.com/intel/cri-resource-manager/pkg/cri/resource-manager/cache"
	"github.com/intel/cri-resource-manager/pkg/metrics"

	// pull in all metrics collectors
	_ "github.com/intel/cri-resource-manager/pkg/metrics/register"
)

// metrics cgroup prefix
var cgroups = ""

// nil is our special event to stop metrics collection
var stopMetricsEvent *model.MetricFamily

// avx512Event indicates a change in a containers usage of AVX512 instructions.
type avx512Event struct {
	container cache.Container
	active    bool
}

// activateMetricsCollection activates metrics data collection and processing.
func (m *resmgr) activateMetricsCollection() error {
	defaults := metrics.GetDefaultConfig()
	defaults.Cache = &m.cache
	cgroups = defaults.CgroupPath

	m.metrics = make(chan *model.MetricFamily, 8)
	collector, err := metrics.NewMetric(m.metrics, defaults)
	if err != nil {
		return resmgrError("failed to create metrics collector: %v", err)
	}
	m.collector = collector

	go func() {
		elog.Info("started metrics processing loop")
		for {
			metric := <-m.metrics
			stop := m.processMetricsEvent(metric)

			if stop {
				break
			}
		}
		elog.Info("stopping metrics processing")
		close(m.metrics)
		m.metrics = nil
	}()

	return nil
}

// stopMetricsCollection deactivates metrics data collection and processing.
func (m *resmgr) stopMetricsCollection() {
	if m.metrics != nil {
		m.collector.Close()
		m.metrics <- stopMetricsEvent
	}
}

// processMetricsEvent processes the given metrics event.
func (m *resmgr) processMetricsEvent(event *model.MetricFamily) bool {
	if event == stopMetricsEvent {
		return true
	}

	elog.Debug("got metrics event %s...", *event.Name)

	if elog.DebugEnabled() {
		buf := &bytes.Buffer{}
		if _, err := expfmt.MetricFamilyToText(buf, event); err == nil {
			elog.DebugBlock("  <metric event> ", "%s", strings.TrimSpace(buf.String()))
		}
	}

	switch *event.Name {
	case avx.AVXSwitchCountName:
		if *event.Type != model.MetricType_GAUGE {
			elog.Warn("unexpected %s type: %v, expected %v",
				avx.AVXSwitchCountName, *event.Type, model.MetricType_GAUGE)
			return false
		}
		for _, metric := range event.Metric {
			if len(metric.Label) < 1 {
				continue
			}
			if metric.Label[0].GetName() != "cgroup" {
				elog.Warn("expected cgroup gauge label not found")
				continue
			}
			cgroup := strings.TrimPrefix(metric.Label[0].GetValue(), cgroups)
			value := metric.Gauge.GetValue()

			elog.Info("%s %s: %f", *event.Name, cgroup, value)
			if c, ok := m.cache.LookupContainerByCgroup(cgroup); ok {
				elog.Info("  => container %s...", c.PrettyName())
				m.SendEvent(&avx512Event{container: c, active: true})
			}
		}

	case avx.AllSwitchCountName:
		elog.Debug("got metric event %s (%v)", *event.Name, event)

	case avx.LastCPUName:
		elog.Debug("got metric event %s (%v)", *event.Name, event)

	default:
		elog.Warn("ignoring metric event %s (%v)", *event.Name, event)
	}

	return false
}
