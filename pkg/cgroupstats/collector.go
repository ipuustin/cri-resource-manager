package cgroupstats

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/intel/cri-resource-manager/pkg/cgroups"
	"github.com/intel/cri-resource-manager/pkg/cri/resource-manager/cache"
	"github.com/intel/cri-resource-manager/pkg/log"
	"github.com/intel/cri-resource-manager/pkg/metrics"
	"github.com/intel/cri-resource-manager/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	lastCPUDesc = prometheus.NewDesc(
		"last_cpu_avx_task_switches",
		"Number of task switches on the CPU where AVX512 instructions were used.",
		[]string{
			"cpu_id",
		}, nil,
	)

	avxSwitchCountDesc = prometheus.NewDesc(
		"avx_switch_count_per_cgroup",
		"Number of task switches where AVX512 instructions were used in a particular cgroup.",
		[]string{
			"cgroup",
			"cgroup_id",
		}, nil,
	)

	allSwitchCountDesc = prometheus.NewDesc(
		"all_switch_count_per_cgroup",
		"Total number of task switches in a particular cgroup.",
		[]string{
			"cgroup",
		}, nil,
	)
)

var numaStatsDesc = prometheus.NewDesc(
	"cgroup_numa_stats",
	"NUMA statistics for a given container and pod.",
	[]string{
		// Pod ID
		"pod_id",
		// Container ID
		"container_id",
		// NUMA node ID
		"numa_node_id",
		// NUMA memory type
		"type",
	}, nil,
)

var (
	memoryUsageDesc = prometheus.NewDesc(
		"cgroup_memory_usage",
		"Memory usage statistics for a given container and pod.",
		[]string{
			// Pod ID
			"pod_id",
			// Container ID
			"container_id",
			"type",
		}, nil,
	)

	memoryMigrateDesc = prometheus.NewDesc(
		"cgroup_memory_migrate",
		"Memory migrate status for a given container and pod.",
		[]string{
			// Pod ID
			"pod_id",
			// Container ID
			"container_id",
		}, nil,
	)

	cpuAcctUsageDesc = prometheus.NewDesc(
		"cgroup_cpu_acct",
		"CPU accounting for a given container and pod.",
		[]string{
			// Pod ID
			"pod_id",
			// Container ID
			"container_id",
			// CPU ID
			"cpu",
			"type",
		}, nil,
	)

	hugeTlbUsageDesc = prometheus.NewDesc(
		"cgroup_hugetlb_usage",
		"Hugepages usage for a given container and pod.",
		[]string{
			// Pod ID
			"pod_id",
			// Container ID
			"container_id",
			"size",
			"type",
		}, nil,
	)

	blkioDeviceUsageDesc = prometheus.NewDesc(
		"cgroup_blkio_device_usage",
		"Blkio Device bytes usage for a given container and pod.",
		[]string{
			// Pod ID
			"pod_id",
			// Container ID
			"container_id",
			"major",
			"minor",
			"operation",
		}, nil,
	)
)

type collector struct {
	config *metrics.CollectorConfig
}

// NewCollector creates new Prometheus collector
func NewCollector(config *metrics.CollectorConfig) (prometheus.Collector, error) {
	return &collector{
		config: config,
	}, nil
}

// Describe implements prometheus.Collector interface
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func updateCPUAcctUsageMetric(ch chan<- prometheus.Metric, pod cache.Pod, container cache.Container, metric []cgroups.CPUAcctUsage) {
	for i, acct := range metric {
		ch <- prometheus.MustNewConstMetric(
			cpuAcctUsageDesc,
			prometheus.CounterValue,
			float64(acct.CPU),
			pod.GetID(), container.GetID(), strconv.FormatInt(int64(i), 10), "CPU",
		)
		ch <- prometheus.MustNewConstMetric(
			cpuAcctUsageDesc,
			prometheus.CounterValue,
			float64(acct.User),
			pod.GetID(), container.GetID(), strconv.FormatInt(int64(i), 10), "User",
		)
		ch <- prometheus.MustNewConstMetric(
			cpuAcctUsageDesc,
			prometheus.CounterValue,
			float64(acct.System),
			pod.GetID(), container.GetID(), strconv.FormatInt(int64(i), 10), "System",
		)
	}
}

func updateMemoryMigrateMetric(ch chan<- prometheus.Metric, pod cache.Pod, container cache.Container, migrate bool) {
	migrateValue := 0
	if migrate {
		migrateValue = 1
	}
	ch <- prometheus.MustNewConstMetric(
		memoryMigrateDesc,
		prometheus.GaugeValue,
		float64(migrateValue),
		pod.GetID(), container.GetID(),
	)
}

func updateMemoryUsageMetric(ch chan<- prometheus.Metric, pod cache.Pod, container cache.Container, metric cgroups.MemoryUsage) {
	ch <- prometheus.MustNewConstMetric(
		memoryUsageDesc,
		prometheus.GaugeValue,
		float64(metric.Bytes),
		pod.GetID(), container.GetID(), "Bytes",
	)
	ch <- prometheus.MustNewConstMetric(
		memoryUsageDesc,
		prometheus.GaugeValue,
		float64(metric.MaxBytes),
		pod.GetID(), container.GetID(), "MaxBytes",
	)
}

func updateNumaStatMetric(ch chan<- prometheus.Metric, pod cache.Pod, container cache.Container, metric cgroups.NumaStat) {
	// TODO: use "reflect" to iterate through the struct fields of NumaStat?

	for key, value := range metric.Total.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "Total",
		)
	}
	for key, value := range metric.File.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "File",
		)
	}
	for key, value := range metric.Anon.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "Anon",
		)
	}
	for key, value := range metric.Unevictable.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "Unevictable",
		)
	}
	for key, value := range metric.HierarchicalTotal.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "HierarchicalTotal",
		)
	}
	for key, value := range metric.HierarchicalFile.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "HierarchicalFile",
		)
	}
	for key, value := range metric.HierarchicalAnon.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "HierarchicalAnon",
		)
	}
	for key, value := range metric.HierarchicalUnevictable.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			pod.GetID(), container.GetID(), key, "HierarchicalUnevictable",
		)
	}
}

func updateHugeTlbUsageMetric(ch chan<- prometheus.Metric, pod cache.Pod, container cache.Container, metric []cgroups.HugetlbUsage) {
	// One HugeTlbUsage for each size.
	for _, hugeTlbUsage := range metric {
		ch <- prometheus.MustNewConstMetric(
			hugeTlbUsageDesc,
			prometheus.GaugeValue,
			float64(hugeTlbUsage.Bytes),
			pod.GetID(), container.GetID(), hugeTlbUsage.Size, "Bytes",
		)
		ch <- prometheus.MustNewConstMetric(
			hugeTlbUsageDesc,
			prometheus.GaugeValue,
			float64(hugeTlbUsage.MaxBytes),
			pod.GetID(), container.GetID(), hugeTlbUsage.Size, "MaxBytes",
		)
	}
}

func updateBlkioDeviceUsageMetric(ch chan<- prometheus.Metric, pod cache.Pod, container cache.Container, metric cgroups.BlkioThrottleBytes) {
	for _, deviceBytes := range metric.DeviceBytes {
		for operation, val := range deviceBytes.Operations {
			ch <- prometheus.MustNewConstMetric(
				blkioDeviceUsageDesc,
				prometheus.CounterValue,
				float64(val),
				pod.GetID(), container.GetID(), strconv.FormatInt(int64(deviceBytes.Major), 10),
				strconv.FormatInt(int64(deviceBytes.Minor), 10), operation,
			)
		}
	}
}

// Collect implements prometheus.Collector interface
func (c collector) Collect(ch chan<- prometheus.Metric) {
	var wg sync.WaitGroup

	// We don't bail out on errors because those can happen if there is a race condition between
	// the destruction of a container and us getting to read the cgroup data. We just don't report
	// the values we don't get.

	cch := c.config.Cache
	(*cch).GetConfig()

	pods := (*cch).GetPods()
	for _, pod := range pods {
		containers := pod.GetContainers()
		for _, container := range containers {

			// TODO: func GetContainerCgroupDirs(containerId string) map[string]os.Path
			cgroupPathMemory := utils.GetContainerCgroupDir("memory", container.GetID())
			cgroupPathCpuset := utils.GetContainerCgroupDir("cpuset", container.GetID())
			cgroupPathCPU := utils.GetContainerCgroupDir("cpu", container.GetID())
			cgroupPathHugetlb := utils.GetContainerCgroupDir("hugetlb", container.GetID())
			cgroupPathBlkio := utils.GetContainerCgroupDir("blkio", container.GetID())

			wg.Add(6)
			go func(pod_ cache.Pod, container_ cache.Container, containerPath_ string) {
				defer wg.Done()
				numa, err := cgroups.GetNumaStats(containerPath_)
				if err == nil {
					updateNumaStatMetric(ch, pod_, container_, numa)
				} else {
					fmt.Println(err.Error())
				}
			}(pod, container, cgroupPathMemory)
			go func(pod_ cache.Pod, container_ cache.Container, containerPath_ string) {
				defer wg.Done()
				memory, err := cgroups.GetMemoryUsage(containerPath_)
				if err == nil {
					updateMemoryUsageMetric(ch, pod_, container_, memory)
				} else {
					fmt.Println(err.Error())
				}
			}(pod, container, cgroupPathMemory)
			go func(pod_ cache.Pod, container_ cache.Container, containerPath_ string) {
				defer wg.Done()
				migrate, err := cgroups.GetCPUSetMemoryMigrate(containerPath_)
				if err == nil {
					updateMemoryMigrateMetric(ch, pod_, container_, migrate)
				} else {
					fmt.Println(err.Error())
				}
			}(pod, container, cgroupPathCpuset)
			go func(pod_ cache.Pod, container_ cache.Container, containerPath_ string) {
				defer wg.Done()
				cpuAcctUsage, err := cgroups.GetCPUAcctStats(containerPath_)
				if err == nil {
					updateCPUAcctUsageMetric(ch, pod_, container_, cpuAcctUsage)
				} else {
					fmt.Println(err.Error())
				}
			}(pod, container, cgroupPathCPU)
			go func(pod_ cache.Pod, container_ cache.Container, containerPath_ string) {
				defer wg.Done()
				hugeTlbUsage, err := cgroups.GetHugetlbUsage(containerPath_)
				if err == nil {
					updateHugeTlbUsageMetric(ch, pod_, container_, hugeTlbUsage)
				} else {
					fmt.Println(err.Error())
				}
			}(pod, container, cgroupPathHugetlb)
			go func(pod_ cache.Pod, container_ cache.Container, containerPath_ string) {
				defer wg.Done()
				blkioDeviceUsage, err := cgroups.GetBlkioThrottleBytes(containerPath_)
				if err == nil {
					updateBlkioDeviceUsageMetric(ch, pod_, container_, blkioDeviceUsage)
				} else {
					fmt.Println(err.Error())
				}
			}(pod, container, cgroupPathBlkio)
		}
	}

	// We need to wait so that the response channel doesn't get closed.
	wg.Wait()
}

func init() {
	err := metrics.RegisterCollector("cgroupstats", NewCollector)
	if err != nil {
		log.Error("Failed to register cgroupstats collector: %v", err)
		return
	}
}
