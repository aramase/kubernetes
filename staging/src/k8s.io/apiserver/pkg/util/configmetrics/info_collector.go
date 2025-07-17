/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package configmetrics

import (
	"sync/atomic"

	"k8s.io/component-base/metrics"
	"k8s.io/utils/ptr"
)

// HashProvider is an interface for getting the current config hash values
type HashProvider interface {
	GetCurrentHashes() []string
}

// AtomicHashProvider implements HashProvider using atomic operations for thread-safe access
type AtomicHashProvider struct {
	labelNames []string
	hashes     map[string]*atomic.Pointer[string]
}

// NewAtomicHashProvider creates a new atomic hash provider with the specified label names
func NewAtomicHashProvider(labelNames ...string) *AtomicHashProvider {
	if len(labelNames) == 0 {
		panic("NewAtomicHashProvider: at least one label name is required")
	}

	p := &AtomicHashProvider{
		labelNames: labelNames,
		hashes:     make(map[string]*atomic.Pointer[string]),
	}
	// Initialize with empty strings for each label
	for _, name := range labelNames {
		atomicPtr := &atomic.Pointer[string]{}
		atomicPtr.Store(ptr.To(""))
		p.hashes[name] = atomicPtr
	}
	return p
}

func (h *AtomicHashProvider) GetCurrentHashes() []string {
	result := make([]string, 0, len(h.labelNames))
	for _, name := range h.labelNames {
		result = append(result, *h.hashes[name].Load())
	}
	return result
}

func (h *AtomicHashProvider) SetHash(name, value string) {
	if atomicPtr, exists := h.hashes[name]; exists {
		atomicPtr.Store(ptr.To(value))
	}
}

func (h *AtomicHashProvider) SetHashes(values map[string]string) {
	for name, value := range values {
		h.SetHash(name, value)
	}
}

func (h *AtomicHashProvider) Reset() {
	for _, atomicPtr := range h.hashes {
		atomicPtr.Store(ptr.To(""))
	}
}

// NewConfigInfoCustomCollector creates a custom collector for config hash info metrics.
// This eliminates the need for state management and locks by collecting metrics on demand.
func NewConfigInfoCustomCollector(desc *metrics.Desc, hashProvider HashProvider) metrics.StableCollector {
	return &configInfoCustomCollector{
		desc:         desc,
		hashProvider: hashProvider,
	}
}

type configInfoCustomCollector struct {
	metrics.BaseStableCollector
	desc         *metrics.Desc
	hashProvider HashProvider
}

var _ metrics.StableCollector = &configInfoCustomCollector{}

func (c *configInfoCustomCollector) DescribeWithStability(ch chan<- *metrics.Desc) {
	ch <- c.desc
}

func (c *configInfoCustomCollector) CollectWithStability(ch chan<- metrics.Metric) {
	hashes := c.hashProvider.GetCurrentHashes()
	if len(hashes) == 0 {
		return
	}

	// Only emit metric if all hash values are non-empty
	for _, value := range hashes {
		if len(value) == 0 {
			return
		}
	}

	// hashes is already in the correct order, use it directly as label values
	ch <- metrics.NewLazyConstMetric(c.desc, metrics.GaugeValue, 1, hashes...)
}
