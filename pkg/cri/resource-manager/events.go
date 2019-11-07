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
	logger "github.com/intel/cri-resource-manager/pkg/log"
)

// stopEvent is the event used to shut down event processing.
type stopEvent struct{}

// Our event logging instance
var elog = logger.NewLogger("event")

// SendEvent injects the given event to the resource managers event processing loop.
func (m *resmgr) SendEvent(event interface{}) error {
	if m.events == nil {
		return resmgrError("can't send event, event processor not running")
	}

	m.events <- event
	return nil
}

// activateEventprocessing prepares resource manager for making policy decisions for events.
func (m *resmgr) activateEventProcessing() error {
	if err := m.activateMetricsCollection(); err != nil {
		return err
	}

	m.events = make(chan interface{}, 32)

	go func() {
		elog.Info("started event processing loop")
		for {
			event := <-m.events
			stop := m.processEvent(event)

			if stop {
				break
			}
		}
		elog.Info("stopped event processing loop")
		close(m.events)
		m.events = nil
	}()

	return nil
}

// stopEventProcessing stops the resource manager event processing loop.
func (m *resmgr) stopEventProcessing() {
	m.stopMetricsCollection()
	if m.events != nil {
		m.events <- stopEvent{}
	}
}

// processEvent processes a single resource manager event.
func (m *resmgr) processEvent(event interface{}) bool {
	m.Lock()
	defer m.Unlock()

	switch event.(type) {
	case stopEvent:
		elog.Info("received stop-request event")
		return true

	case string:
		elog.Debug("received string event '%s'...", event.(string))

	case *avx512Event:
		e := event.(*avx512Event)
		state := map[bool]string{false: "false", true: "true"}
		e.container.SetTag("AVX512", state[e.active])

	default:
		elog.Warn("received unknown event %T (%v)", event, event)
	}

	return false
}
