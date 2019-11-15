package metrics

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"sync"
	"time"
)

type Metric struct {
	sync.Mutex

	period  time.Duration
	events  chan<- *dto.MetricFamily
	closing bool

	gatherer prometheus.Gatherers
}

var builtInCollectors map[string]InitCollector

type CollectorConfig struct {
	CgroupPath    string
	CgroupFormat  string
	BpfInstallDir string
	Period        time.Duration
}

func init() {
	builtInCollectors = make(map[string]InitCollector)
}

// TODO: set pkg/config?
func GetDefaultConfig() *CollectorConfig {
	return &CollectorConfig{
		CgroupPath:    "/sys/fs/cgroup/unified",
		CgroupFormat:  "systemd",
		BpfInstallDir: "/usr/libexec/bpf",
		Period:        5 * time.Second,
	}
}

type InitCollector func(config *CollectorConfig) (prometheus.Collector, error)

func RegisterCollector(name string, init InitCollector) error {
	if _, fn := builtInCollectors[name]; fn {
		return fmt.Errorf("Collector %s already registered", name)
	}

	builtInCollectors[name] = init

	return nil
}

var registeredCollectors = []prometheus.Collector{}

func NewMetric(events chan<- *dto.MetricFamily, config *CollectorConfig) (*Metric, error) {

	reg := prometheus.NewRegistry()

	for _, cb := range builtInCollectors {
		c, err := cb(config)
		if err != nil {
			return nil, err
		}
		registeredCollectors = append(registeredCollectors, c)
	}

	reg.MustRegister(registeredCollectors[:]...)

	m := &Metric{
		period: config.Period,
		events: events,
		gatherer: prometheus.Gatherers{
			reg,
		},
	}
	go m.run()

	return m, nil
}

func (m *Metric) Close() {
	m.Lock()
	defer m.Unlock()

	// TODO: bpfModule.Close()

	m.closing = true
}

func (m *Metric) isClosing() bool {
	m.Lock()
	defer m.Unlock()

	if m.closing {
		return true
	}
	return false
}

func (m *Metric) run() {
	for {
		time.Sleep(m.period)

		if m.isClosing() {
			close(m.events)
			return
		}

		g, err := m.gatherer.Gather()
		if err != nil {
			fmt.Println(err)
		}

		for _, mf := range g {
			m.events <- mf
		}
	}
}
