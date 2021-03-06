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

package cache

import (
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/intel/cri-resource-manager/pkg/cri/resource-manager/kubernetes"
	"strings"
)

const (
	// SelfReference indicates a container self-referencing value.
	//SelfReference = "@self:"

	// annotation key for specifying container affinity rules
	keyAffinity = "affinity"
	// annotation key for specifying container anti-affinity rules
	keyAntiAffinity = "anti-affinity"
)

// simpleAffinity is an alternative, simplified syntax for intra-pod container affinity.
type simpleAffinity map[string][]string

// PodContainerAffinity defines a set of per-container affinities and anti-affinities.
type podContainerAffinity map[string][]*Affinity

// Affinity specifies a single container affinity.
type Affinity struct {
	Scope  *Expression `json:"scope,omitempty"`  // scope for evaluating this affinity
	Match  *Expression `json:"match"`            // affinity expression
	Weight int32       `json:"weight,omitempty"` // (optional) weight for this affinity
}

// Expression is used to describe a criteria to select objects within a domain.
type Expression struct {
	//  Domain  Domain   `json:"domain"`          // domain of operation, ATM implicitly labels
	Key    string   `json:"key"`              // domain key
	Op     Operator `json:"operator"`         // operator to apply to value of Key and Values
	Values []string `json:"values,omitempty"` // value(s) for domain key
}

/*
// Domain specifies possible domains to evaluate Expressions in.
type Domain string

const (
	// ScopeLabels specifies the operation to be performed
	LabelsDomain Domain = "labels"
)
*/

// Operator defines the possible operators for an Expression.
type Operator string

const (
	// Equals tests for equality with a single value.
	Equals Operator = "Equals"
	// NotEqual test for inequality with a single value.
	NotEqual Operator = "NotEqual"
	// In tests if the key's value is one of the specified set.
	In Operator = "In"
	// NotIn tests if the key's value is not one of the specified set.
	NotIn Operator = "NotIn"
	// Exists evalutes to true if the named key exists.
	Exists Operator = "Exists"
	// NotExist evalutes to true if the named key does not exist.
	NotExist Operator = "NotExist"
)

// Validate checks the affinity for (obvious) invalidity.
func (a *Affinity) Validate() error {
	if err := a.Scope.Validate(); err != nil {
		return cacheError("invalid affinity scope: %v", err)
	}

	if err := a.Match.Validate(); err != nil {
		return cacheError("invalid affinity match: %v", err)
	}

	return nil
}

// Validate checks the expression for (obvious) invalidity.
func (e *Expression) Validate() error {
	if e == nil {
		return cacheError("nil expression")
	}

	switch e.Op {
	case Equals, NotEqual:
		if len(e.Values) != 1 {
			return cacheError("invalid expression, '%s' requires a single value", e.Op)
		}
	case Exists, NotExist:
		if e.Values != nil && len(e.Values) != 0 {
			return cacheError("invalid expression, '%s' does not take any values", e.Op)
		}
	}

	return nil
}

// EvaluateAffinity evaluates the given affinity against all known in-scope containers.
func (cch *cache) EvaluateAffinity(a *Affinity) map[string]int32 {
	results := make(map[string]int32)
	for _, c := range cch.FilterScope(a.Scope) {
		if a.Match.Evaluate(c) {
			id := c.GetCacheID()
			results[id] += a.Weight
		}
	}
	return results
}

// FilterScope returns the containers selected by the scope expression.
func (cch *cache) FilterScope(scope *Expression) []Container {
	cch.Debug("calculating scope %s", scope.String())
	result := []Container{}
	for _, c := range cch.GetContainers() {
		if scope.Evaluate(c) {
			cch.Debug("  + container %s: IN scope", c.PrettyName())
			result = append(result, c)
		} else {
			cch.Debug("  - container %s: NOT IN scope", c.PrettyName())
		}
	}
	return result
}

// Evaluate evaluates an expression against a container.
func (e *Expression) Evaluate(container Container) bool {
	value, ok := e.KeyValue(container)
	result := false

	switch e.Op {
	case Equals:
		result = ok && (value == e.Values[0] || e.Values[0] == "*")
	case NotEqual:
		result = !ok || value != e.Values[0]
	case In:
		result = false
		if ok {
			for _, v := range e.Values {
				if value == v || v == "*" {
					result = true
				}
			}
		}
	case NotIn:
		result = true
		if ok {
			for _, v := range e.Values {
				if value == v || v == "*" {
					result = false
				}
			}
		}
	case Exists:
		result = ok
	case NotExist:
		result = !ok
	}

	return result
}

// KeyValue extracts the value of the expresssion key from a container.
func (e *Expression) KeyValue(container Container) (string, bool) {
	value, ok := container.GetLabel(e.Key)
	return value, ok
}

// String returns the affinity as a string.
func (a *Affinity) String() string {
	kind := ""
	if a.Weight < 0 {
		kind = "anti-"
	}
	return fmt.Sprintf("<%saffinity: scope %s %s => %d>",
		kind, a.Scope.String(), a.Match.String(), a.Weight)
}

// String returns the expression as a string.
func (e *Expression) String() string {
	return fmt.Sprintf("<%s %s %s>", e.Key, e.Op, strings.Join(e.Values, ","))
}

// Try to parse affinities in simplified notation from the given annotation value.
func (pca *podContainerAffinity) parseSimple(pod Pod, value string, weight int32) bool {
	parsed := simpleAffinity{}
	if err := yaml.Unmarshal([]byte(value), &parsed); err != nil {
		return false
	}

	podScope := pod.ScopeExpression()
	for name, values := range parsed {
		(*pca)[name] = append((*pca)[name],
			&Affinity{
				Scope: podScope,
				Match: &Expression{
					Key:    kubernetes.ContainerNameLabel,
					Op:     In,
					Values: values,
				},
				Weight: weight,
			})
	}

	return true
}

// Try to parse affinities in full notation from the given annotation value.
func (pca *podContainerAffinity) parseFull(pod Pod, value string, weight int32) error {
	parsed := podContainerAffinity{}
	if err := yaml.Unmarshal([]byte(value), &parsed); err != nil {
		return cacheError("failed to parse affinity annotation '%s': %v", value, err)
	}

	podScope := pod.ScopeExpression()
	for name, pa := range parsed {
		ca, ok := (*pca)[name]
		if !ok {
			ca = make([]*Affinity, 0, len(pa))
		}
		for _, a := range pa {
			if a.Scope == nil {
				a.Scope = podScope
			}
			if a.Weight == 0 {
				a.Weight = weight
			}

			if err := a.Validate(); err != nil {
				return err
			}

			ca = append(ca, a)
		}
		(*pca)[name] = ca
	}

	return nil
}
