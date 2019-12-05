package cgroupstats

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"github.com/intel/cri-resource-manager/pkg/cgroups"
	"github.com/intel/cri-resource-manager/pkg/log"
	"github.com/intel/cri-resource-manager/pkg/metrics"
	"github.com/intel/cri-resource-manager/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
)

// CgroupDriver determines file sys<tem layout for cgroups.
type CgroupDriver int

const (
	// Systemd uses systemd-style cgroup fileystem loyout.
	Systemd CgroupDriver = iota
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

type container struct {
	ID string
}

func (c container) GetID() string {
	return c.ID
}

type pod struct {
	ID         string
	Qos        string
	Containers []container
}

func (p pod) GetID() string {
	return p.ID
}

func (p pod) GetContainers() []container {
	return p.Containers
}

type collector struct {
	prefix string
	config *metrics.CollectorConfig
}

// NewCollector creates new Prometheus collector
func NewCollector(config *metrics.CollectorConfig) (prometheus.Collector, error) {
	return &collector{
		config: config,
		prefix: "/sys/fs/cgroup",
	}, nil
}

// Describe implements prometheus.Collector interface
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

func createSystemdWalkFunction(root string, cgroup string, prefix string, pods *map[string]pod, otherContainers *map[string]container) (filepath.WalkFunc, error) {

	kubeCpusetRoot := path.Join(root, cgroup, prefix)
	dockerCpusetRoot := path.Join(root, cgroup, "system.slice")

	// /sys/fs/cgroup/cpuset/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podb29b2823_f3d3_4d54_8771_d2c37af2316a.slice/docker-58fb4364741ab62114355b866e0fb8b0a520fdb7c3d9fe094f0ed5c6c428e5d1.scope/cpuset.memory_migrate
	//
	// Groups:
	// 1 besteffort
	// 2 b29b2823_f3d3_4d54_8771_d2c37af2316a
	// 3 docker-58fb4364741ab62114355b866e0fb8b0a520fdb7c3d9fe094f0ed5c6c428e5d1
	// 4 cpuset.memory_migrate

	podContainerDirRe, err := regexp.Compile(`^` + kubeCpusetRoot + `/kubepods-([\w]+).slice/[-\.\w]+pod(.+)\.slice/([-\.\w]+).scope/([-\.\w]+)$`)
	if err != nil {
		return nil, err
	}

	guaranteedPodContainerDirRe, err := regexp.Compile(`^` + kubeCpusetRoot + `/[-\.\w]*pod(.+)\.slice/([-\.\w]+).scope/([-\.\w]+)$`)
	if err != nil {
		return nil, err
	}
	// /sys/fs/cgroup/cpuset/system.slice/docker-84c92d71304317dfbc95437844af1d6e88f0fc722b4c4c6255ad3c22f720db57.scope/cpuset.memory_migrate
	// 1 docker-84c92d71304317dfbc95437844af1d6e88f0fc722b4c4c6255ad3c22f720db5
	// 2 cpuset.memory_migrate

	dockerContainerDirRe, err := regexp.Compile(`^` + dockerCpusetRoot + `/([-\w]+).scope/([-\.\w]+)$`)
	if err != nil {
		return nil, err
	}

	return func(path string, info os.FileInfo, err error) error {
		tokens := podContainerDirRe.FindStringSubmatch(path)
		if len(tokens) == 5 {
			if p, found := (*pods)[tokens[2]]; found {
				for _, c := range p.Containers {
					if c.ID == tokens[3] {
						// Already have the container.
						return nil
					}
				}
				p.Containers = append(p.Containers, container{ID: tokens[3]})
			} else {
				p := pod{ID: tokens[2], Qos: tokens[1], Containers: make([]container, 1)}
				p.Containers[0] = container{ID: tokens[3]}
				(*pods)[tokens[2]] = p
			}
		} else {
			// Pods in "Guaranteed" QoS class have a different cgroup structure,
			// match for them too.
			tokens = guaranteedPodContainerDirRe.FindStringSubmatch(path)
			if len(tokens) == 4 {
				if p, found := (*pods)[tokens[1]]; found {
					for _, container := range p.Containers {
						if container.ID == tokens[2] {
							return nil
						}
					}
					p.Containers = append(p.Containers, container{ID: tokens[2]})
				} else {
					p := pod{ID: tokens[1], Qos: "guaranteed", Containers: make([]container, 1)}
					p.Containers[0] = container{ID: tokens[2]}
					(*pods)[tokens[1]] = p
				}
			} else {
				// Find basic docker containers too.
				tokens = dockerContainerDirRe.FindStringSubmatch(path)
				if len(tokens) == 3 {
					if _, found := (*otherContainers)[tokens[1]]; !found {
						(*otherContainers)[tokens[1]] = container{ID: tokens[1]}
					}
				}
			}
		}
		return nil
	}, nil
}

// getPodCgroups returns a list of container cgroups under the root path
func getPodCgroups(cgroupdriver CgroupDriver, root string) ([]pod, error) {

	// Trivial first version: Go through the tree depth-first and try to find
	// pod and container IDs. Assume systemd cgroup driver and Kubernetes.

	pods := make(map[string]pod, 0)
	otherContainers := make(map[string]container, 0)

	var walkFunc filepath.WalkFunc
	var err error

	if cgroupdriver == Systemd {
		walkFunc, err = createSystemdWalkFunction(root, "cpuset", "kubepods.slice", &pods, &otherContainers)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Unknown cgroup layout")
	}

	err = filepath.Walk(path.Join(root, "cpuset"), walkFunc)
	if err != nil {
		return nil, err
	}

	// Prepare array for returning.
	podArray := make([]pod, len(pods)+len(otherContainers))
	i := 0
	for _, pod := range pods {
		podArray[i] = pod
		i++
	}

	// Create fake pods for the other Containers.
	for _, c := range otherContainers {
		p := pod{ID: "", Qos: "", Containers: make([]container, 1)}
		p.Containers[0] = c

		podArray[i] = p
		i++
	}

	return podArray, nil
}

func updateCPUAcctUsageMetric(ch chan<- prometheus.Metric, p pod, c container, metric []cgroups.CPUAcctUsage) {
	for i, acct := range metric {
		ch <- prometheus.MustNewConstMetric(
			cpuAcctUsageDesc,
			prometheus.CounterValue,
			float64(acct.CPU),
			p.GetID(), c.GetID(), strconv.FormatInt(int64(i), 10), "CPU",
		)
		ch <- prometheus.MustNewConstMetric(
			cpuAcctUsageDesc,
			prometheus.CounterValue,
			float64(acct.User),
			p.GetID(), c.GetID(), strconv.FormatInt(int64(i), 10), "User",
		)
		ch <- prometheus.MustNewConstMetric(
			cpuAcctUsageDesc,
			prometheus.CounterValue,
			float64(acct.System),
			p.GetID(), c.GetID(), strconv.FormatInt(int64(i), 10), "System",
		)
	}
}

func updateMemoryMigrateMetric(ch chan<- prometheus.Metric, p pod, c container, migrate bool) {
	migrateValue := 0
	if migrate {
		migrateValue = 1
	}
	ch <- prometheus.MustNewConstMetric(
		memoryMigrateDesc,
		prometheus.GaugeValue,
		float64(migrateValue),
		p.GetID(), c.GetID(),
	)
}

func updateMemoryUsageMetric(ch chan<- prometheus.Metric, p pod, c container, metric cgroups.MemoryUsage) {
	ch <- prometheus.MustNewConstMetric(
		memoryUsageDesc,
		prometheus.GaugeValue,
		float64(metric.Bytes),
		p.GetID(), c.GetID(), "Bytes",
	)
	ch <- prometheus.MustNewConstMetric(
		memoryUsageDesc,
		prometheus.GaugeValue,
		float64(metric.MaxBytes),
		p.GetID(), c.GetID(), "MaxBytes",
	)
}

func updateNumaStatMetric(ch chan<- prometheus.Metric, p pod, c container, metric cgroups.NumaStat) {
	// TODO: use "reflect" to iterate through the struct fields of NumaStat?

	for key, value := range metric.Total.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "Total",
		)
	}
	for key, value := range metric.File.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "File",
		)
	}
	for key, value := range metric.Anon.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "Anon",
		)
	}
	for key, value := range metric.Unevictable.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "Unevictable",
		)
	}
	for key, value := range metric.HierarchicalTotal.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "HierarchicalTotal",
		)
	}
	for key, value := range metric.HierarchicalFile.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "HierarchicalFile",
		)
	}
	for key, value := range metric.HierarchicalAnon.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "HierarchicalAnon",
		)
	}
	for key, value := range metric.HierarchicalUnevictable.Nodes {
		ch <- prometheus.MustNewConstMetric(
			numaStatsDesc,
			prometheus.GaugeValue,
			float64(value),
			p.GetID(), c.GetID(), key, "HierarchicalUnevictable",
		)
	}
}

func updateHugeTlbUsageMetric(ch chan<- prometheus.Metric, p pod, c container, metric []cgroups.HugetlbUsage) {
	// One HugeTlbUsage for each size.
	for _, hugeTlbUsage := range metric {
		ch <- prometheus.MustNewConstMetric(
			hugeTlbUsageDesc,
			prometheus.GaugeValue,
			float64(hugeTlbUsage.Bytes),
			p.GetID(), c.GetID(), hugeTlbUsage.Size, "Bytes",
		)
		ch <- prometheus.MustNewConstMetric(
			hugeTlbUsageDesc,
			prometheus.GaugeValue,
			float64(hugeTlbUsage.MaxBytes),
			p.GetID(), c.GetID(), hugeTlbUsage.Size, "MaxBytes",
		)
	}
}

func updateBlkioDeviceUsageMetric(ch chan<- prometheus.Metric, p pod, c container, metric cgroups.BlkioThrottleBytes) {
	for _, deviceBytes := range metric.DeviceBytes {
		for operation, val := range deviceBytes.Operations {
			ch <- prometheus.MustNewConstMetric(
				blkioDeviceUsageDesc,
				prometheus.CounterValue,
				float64(val),
				p.GetID(), c.GetID(), strconv.FormatInt(int64(deviceBytes.Major), 10),
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

	pods, err := getPodCgroups(Systemd, c.prefix)
	if err != nil {
		return
	}

	for _, p := range pods {
		containers := p.GetContainers()
		for _, c := range containers {

			// TODO: func GetContainerCgroupDirs(containerId string) map[string]os.Path
			cgroupPathMemory := utils.GetContainerCgroupDir("memory", c.GetID())
			cgroupPathCpuset := utils.GetContainerCgroupDir("cpuset", c.GetID())
			cgroupPathCPU := utils.GetContainerCgroupDir("cpu", c.GetID())
			cgroupPathHugetlb := utils.GetContainerCgroupDir("hugetlb", c.GetID())
			cgroupPathBlkio := utils.GetContainerCgroupDir("blkio", c.GetID())

			// Six deferred wg.Done() calls.
			wg.Add(6)

			go func(pod_ pod, container_ container, containerPath_ string) {
				defer wg.Done()
				numa, err := cgroups.GetNumaStats(containerPath_)
				if err == nil {
					updateNumaStatMetric(ch, pod_, container_, numa)
				} else {
					fmt.Println(err.Error())
				}
			}(p, c, cgroupPathMemory)
			go func(pod_ pod, container_ container, containerPath_ string) {
				defer wg.Done()
				memory, err := cgroups.GetMemoryUsage(containerPath_)
				if err == nil {
					updateMemoryUsageMetric(ch, pod_, container_, memory)
				} else {
					fmt.Println(err.Error())
				}
			}(p, c, cgroupPathMemory)
			go func(pod_ pod, container_ container, containerPath_ string) {
				defer wg.Done()
				migrate, err := cgroups.GetCPUSetMemoryMigrate(containerPath_)
				if err == nil {
					updateMemoryMigrateMetric(ch, pod_, container_, migrate)
				} else {
					fmt.Println(err.Error())
				}
			}(p, c, cgroupPathCpuset)
			go func(pod_ pod, container_ container, containerPath_ string) {
				defer wg.Done()
				cpuAcctUsage, err := cgroups.GetCPUAcctStats(containerPath_)
				if err == nil {
					updateCPUAcctUsageMetric(ch, pod_, container_, cpuAcctUsage)
				} else {
					fmt.Println(err.Error())
				}
			}(p, c, cgroupPathCPU)
			go func(pod_ pod, container_ container, containerPath_ string) {
				defer wg.Done()
				hugeTlbUsage, err := cgroups.GetHugetlbUsage(containerPath_)
				if err == nil {
					updateHugeTlbUsageMetric(ch, pod_, container_, hugeTlbUsage)
				} else {
					fmt.Println(err.Error())
				}
			}(p, c, cgroupPathHugetlb)
			go func(pod_ pod, container_ container, containerPath_ string) {
				defer wg.Done()
				blkioDeviceUsage, err := cgroups.GetBlkioThrottleBytes(containerPath_)
				if err == nil {
					updateBlkioDeviceUsageMetric(ch, pod_, container_, blkioDeviceUsage)
				} else {
					fmt.Println(err.Error())
				}
			}(p, c, cgroupPathBlkio)
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
