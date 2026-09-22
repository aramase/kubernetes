/*
Copyright The Kubernetes Authors.

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

package mutating

import (
	"bytes"
	"fmt"
	"testing"

	"k8s.io/apiserver/pkg/admission/plugin/webhook/config/apis/webhookadmission"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// TestStaticOrderAccepted verifies that the MutatingAdmissionWebhook plugin accepts
// every supported merge order.
func TestStaticOrderAccepted(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.ManifestBasedAdmissionControlConfig, true)
	manifestsDir := t.TempDir()

	for _, staticOrder := range []webhookadmission.StaticOrder{"", webhookadmission.StaticFirst, webhookadmission.StaticLast, webhookadmission.ByName} {
		t.Run(string(staticOrder), func(t *testing.T) {
			configFile := fmt.Sprintf(`
kind: WebhookAdmissionConfiguration
apiVersion: apiserver.config.k8s.io/v1
staticManifestsDir: %q
staticOrder: %q
`, manifestsDir, staticOrder)

			p, err := NewMutatingWebhook(bytes.NewBufferString(configFile))
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			want := staticOrder
			if len(want) == 0 {
				want = webhookadmission.StaticFirst
			}
			if got := p.Webhook.StaticOrder(); got != want {
				t.Fatalf("expected StaticOrder %q, got %q", want, got)
			}
		})
	}
}
