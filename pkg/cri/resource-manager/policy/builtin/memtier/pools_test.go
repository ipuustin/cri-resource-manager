// Copyright 2020 Intel Corporation. All Rights Reserved.
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

package memtier

import (
	"archive/tar"
	"compress/bzip2"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"testing"

	system "github.com/intel/cri-resource-manager/pkg/sysfs"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

func findNodeWithID(id int, nodes []Node) *Node {
	for _, node := range nodes {
		if node.NodeID() == id {
			return &node
		}
	}
	panic("No node found")
}

func setLinks(nodes []Node, tree map[int][]int) {
	for parent, children := range tree {
		parentNode := findNodeWithID(parent, nodes)
		for _, child := range children {
			childNode := findNodeWithID(child, nodes)
			(*childNode).LinkParent(*parentNode)
		}
	}
}

func uncompress(file *os.File, dir string) error {
	data := bzip2.NewReader(file)
	tr := tar.NewReader(data)
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if header.Typeflag == tar.TypeDir {
			// Create a directory.
			err = os.MkdirAll(path.Join(dir, header.Name), 0755)
			if err != nil {
				return err
			}
		} else if header.Typeflag == tar.TypeReg {
			// Create a regular file.
			targetFile, err := os.Create(path.Join(dir, header.Name))
			if err != nil {
				return err
			}
			_, err = io.Copy(targetFile, tr)
			if err != nil {
				return err
			}
		} else if header.Typeflag == tar.TypeSymlink {
			// Create a symlink. Ignore error. FIXME: find out why symlinks aren't created.
			os.Create(path.Join(dir, header.Name))
			//_ = os.Symlink(header.Name, header.Linkname)
		}
	}
}

func TestMemoryLimitFiltering(t *testing.T) {

	// Test the scoring algorithm with synthetic data. The assumptions are:

	// 1. The first node in "nodes" is the root of the tree.

	tcases := []struct {
		name                   string
		nodes                  []Node
		numaNodes              []system.Node
		req                    Request
		affinities             map[int]int32
		tree                   map[int][]int
		expectedRemainingNodes []int
	}{
		{
			name: "single node memory limit (fits)",
			nodes: []Node{
				&numanode{
					node: node{
						id:      100,
						name:    "testnode0",
						kind:    UnknownNode,
						noderes: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
						freeres: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
					},
					id: 0, // system node id
				},
			},
			numaNodes: []system.Node{
				&mockSystemNode{id: 0, memFree: 10001},
			},
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   defaultMemoryType,
				container: &mockContainer{},
			},
			expectedRemainingNodes: []int{100},
			tree:                   map[int][]int{100: {}},
		},
		{
			name: "single node memory limit (doesn't fit)",
			nodes: []Node{
				&numanode{
					node: node{
						id:      100,
						name:    "testnode0",
						kind:    UnknownNode,
						noderes: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
						freeres: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
					},
					id: 0, // system node id
				},
			},
			numaNodes: []system.Node{
				&mockSystemNode{id: 0, memFree: 9999},
			},
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   defaultMemoryType,
				container: &mockContainer{},
			},
			expectedRemainingNodes: []int{},
			tree:                   map[int][]int{100: {}},
		},
		{
			name: "two node memory limit (fits to leaf)",
			nodes: []Node{
				&virtualnode{
					node: node{
						id:      100,
						name:    "testnode0",
						kind:    UnknownNode,
						noderes: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
						freeres: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
					},
				},
				&numanode{
					node: node{
						id:      101,
						name:    "testnode1",
						kind:    UnknownNode,
						noderes: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
						freeres: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
					},
					id: 0, // system node id
				},
			},
			numaNodes: []system.Node{
				&mockSystemNode{id: 0, memFree: 10001},
			},
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   defaultMemoryType,
				container: &mockContainer{},
			},
			expectedRemainingNodes: []int{100, 101},
			tree:                   map[int][]int{100: {101}, 101: {}},
		},
		{
			name: "three node memory limit (fits to root)",
			nodes: []Node{
				&virtualnode{
					node: node{
						id:      100,
						name:    "testnode0",
						kind:    UnknownNode,
						noderes: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
						freeres: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
					},
				},
				&numanode{
					node: node{
						id:      101,
						name:    "testnode1",
						kind:    UnknownNode,
						noderes: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
						freeres: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
					},
					id: 0, // system node id
				},
				&numanode{
					node: node{
						id:      102,
						name:    "testnode2",
						kind:    UnknownNode,
						noderes: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
						freeres: newSupply(&node{}, cpuset.NewCPUSet(), cpuset.NewCPUSet(), 0),
					},
					id: 1, // system node id
				},
			},
			numaNodes: []system.Node{
				&mockSystemNode{id: 0, memFree: 6000},
				&mockSystemNode{id: 1, memFree: 6000},
			},
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   defaultMemoryType,
				container: &mockContainer{},
			},
			expectedRemainingNodes: []int{100},
			tree:                   map[int][]int{100: {101, 102}, 101: {}, 102: {}},
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			setLinks(tc.nodes, tc.tree)
			policy := &policy{
				sys: &mockSystem{
					nodes: tc.numaNodes,
				},
				pools:       tc.nodes,
				cache:       &mockCache{},
				root:        tc.nodes[0],
				nodeCnt:     len(tc.nodes),
				allocations: allocations{},
			}
			// back pointers
			for _, node := range tc.nodes {
				switch node.(type) {
				case *numanode:
					numaNode := node.(*numanode)
					numaNode.self.node = numaNode
					noderes := numaNode.noderes.(*supply)
					noderes.node = node
					freeres := numaNode.freeres.(*supply)
					freeres.node = node
					numaNode.policy = policy
				case *virtualnode:
					virtualNode := node.(*virtualnode)
					virtualNode.self.node = virtualNode
					noderes := virtualNode.noderes.(*supply)
					noderes.node = node
					freeres := virtualNode.freeres.(*supply)
					freeres.node = node
					virtualNode.policy = policy
				}
			}
			policy.allocations.policy = policy

			scores, filteredPools := policy.sortPoolsByScore(tc.req, tc.affinities)
			fmt.Printf("scores: %v, remaining pools: %v\n", scores, filteredPools)

			if len(filteredPools) != len(tc.expectedRemainingNodes) {
				t.Errorf("Wrong nodes in the filtered pool: expected %v but got %v", tc.expectedRemainingNodes, filteredPools)
			}

			for _, id := range tc.expectedRemainingNodes {
				found := false
				for _, node := range filteredPools {
					if node.NodeID() == id {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Did not find id %d in filtered pools: %v", id, filteredPools)
				}
			}
		})
	}
}

func TestPoolCreation(t *testing.T) {

	// Test pool creation with "real" sysfs data.

	// Create a temporary directory for the test data.
	dir, err := ioutil.TempDir("", "cri-resource-manager-test-sysfs-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	// Uncompress the test data to the directory.
	file, err := os.Open(path.Join("testdata", "sysfs.tar.bz2"))
	if err != nil {
		panic(err)
	}
	err = uncompress(file, dir)
	if err != nil {
		panic(err)
	}

	tcases := []struct {
		path                    string
		name                    string
		req                     Request
		affinities              map[int]int32
		expectedRemainingNodes  []int
		expectedFirstNodeMemory memoryType
		expectedLeafNodeCPUs    int
		expectedRootNodeCPUs    int
	}{
		{
			path: path.Join(dir, "sysfs", "desktop", "sys"),
			name: "sysfs pool creation from a desktop system",
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   memoryUnspec,
				container: &mockContainer{},
			},
			expectedRemainingNodes:  []int{0},
			expectedFirstNodeMemory: memoryUnspec,
			expectedLeafNodeCPUs:    20,
			expectedRootNodeCPUs:    20,
		},
		{
			path: path.Join(dir, "sysfs", "server", "sys"),
			name: "sysfs pool creation from a server system",
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   memoryDRAM,
				container: &mockContainer{},
			},
			expectedRemainingNodes: []int{0, 1, 2, 3, 4, 5, 6},
			// TODO: why not just memoryDRAM?
			expectedFirstNodeMemory: memoryDRAM | memoryPMEM,
			expectedLeafNodeCPUs:    28,
			expectedRootNodeCPUs:    112,
		},
		{
			path: path.Join(dir, "sysfs", "server", "sys"),
			name: "pmem request on a server system",
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   memoryDRAM | memoryPMEM,
				container: &mockContainer{},
			},
			expectedRemainingNodes:  []int{0, 1, 2, 3, 4, 5, 6},
			expectedFirstNodeMemory: memoryDRAM | memoryPMEM,
			expectedLeafNodeCPUs:    28,
			expectedRootNodeCPUs:    112,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			sys, err := system.DiscoverSystemAt(tc.path)
			if err != nil {
				panic(err)
			}

			policy := &policy{
				sys:   sys,
				cache: &mockCache{},
			}

			err = policy.buildPoolsByTopology()
			if err != nil {
				panic(err)
			}

			if policy.root.GetSupply().SharableCPUs().Size() != tc.expectedRootNodeCPUs {
				t.Errorf("Expected %d CPUs, got %d", tc.expectedRootNodeCPUs, policy.root.GetSupply().SharableCPUs().Size())
			}

			for _, p := range policy.pools {
				if p.IsLeafNode() {
					if len(p.Children()) != 0 {
						t.Errorf("Leaf node %v had %d children", p, len(p.Children()))
					}
					if p.GetSupply().SharableCPUs().Size()+p.GetSupply().IsolatedCPUs().Size() != tc.expectedLeafNodeCPUs {
						t.Errorf("Expected %d CPUs, got %d (%s)", tc.expectedLeafNodeCPUs, p.GetSupply().SharableCPUs().Size()+p.GetSupply().IsolatedCPUs().Size(), p.GetSupply())
					}
				}
			}

			scores, filteredPools := policy.sortPoolsByScore(tc.req, tc.affinities)
			fmt.Printf("scores: %v, remaining pools: %v\n", scores, filteredPools)

			if len(filteredPools) != len(tc.expectedRemainingNodes) {
				t.Errorf("Wrong number of nodes in the filtered pool: expected %d but got %d", len(tc.expectedRemainingNodes), len(filteredPools))
			}

			for _, id := range tc.expectedRemainingNodes {
				found := false
				for _, node := range filteredPools {
					if node.NodeID() == id {
						fmt.Println("node id:", node.NodeID())
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Did not find id %d in filtered pools: %s", id, filteredPools)
				}
			}

			if filteredPools[0].GetMemoryType() != tc.expectedFirstNodeMemory {
				t.Errorf("Expected first node memory type %v, got %v", tc.expectedFirstNodeMemory, filteredPools[0].GetMemoryType())
			}
		})
	}
}

func TestWorkloadPlacement(t *testing.T) {

	// Do some workloads (containers) and see how they are placed in the
	// server system.

	// Create a temporary directory for the test data.
	dir, err := ioutil.TempDir("", "cri-resource-manager-test-sysfs-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	// Uncompress the test data to the directory.
	file, err := os.Open(path.Join("testdata", "sysfs.tar.bz2"))
	if err != nil {
		panic(err)
	}
	err = uncompress(file, dir)
	if err != nil {
		panic(err)
	}

	tcases := []struct {
		path                   string
		name                   string
		req                    Request
		affinities             map[int]int32
		expectedRemainingNodes []int
		expectedLeafNode       bool
	}{
		{
			path: path.Join(dir, "sysfs", "server", "sys"),
			name: "workload placement on a server system leaf node",
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   memoryUnspec,
				isolate:   false,
				full:      28,
				container: &mockContainer{},
			},
			expectedRemainingNodes: []int{0, 1, 2, 3, 4, 5, 6},
			expectedLeafNode:       true,
		},
		{
			path: path.Join(dir, "sysfs", "server", "sys"),
			name: "workload placement on a server system root node",
			req: &request{
				memReq:    10000,
				memLim:    10000,
				memType:   memoryUnspec,
				isolate:   false,
				full:      29,
				container: &mockContainer{},
			},
			expectedRemainingNodes: []int{0, 1, 2, 3, 4, 5, 6},
			expectedLeafNode:       false,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			sys, err := system.DiscoverSystemAt(tc.path)
			if err != nil {
				panic(err)
			}

			policy := &policy{
				sys:   sys,
				cache: &mockCache{},
			}

			err = policy.buildPoolsByTopology()
			if err != nil {
				panic(err)
			}

			scores, filteredPools := policy.sortPoolsByScore(tc.req, tc.affinities)
			fmt.Printf("scores: %v, remaining pools: %v\n", scores, filteredPools)

			if len(filteredPools) != len(tc.expectedRemainingNodes) {
				t.Errorf("Wrong number of nodes in the filtered pool: expected %d but got %d", len(tc.expectedRemainingNodes), len(filteredPools))
			}

			for _, id := range tc.expectedRemainingNodes {
				found := false
				for _, node := range filteredPools {
					if node.NodeID() == id {
						fmt.Println("node id:", node.NodeID())
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Did not find id %d in filtered pools: %s", id, filteredPools)
				}
			}

			if filteredPools[0].IsLeafNode() != tc.expectedLeafNode {
				t.Errorf("Workload should have been placed in a leaf node: %t", tc.expectedLeafNode)
			}
		})
	}
}
