/*
Copyright 2026.

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

package rbacproxy_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/ingress-node-firewall/pkg/rbacproxy"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestRBACProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RBACProxy Wrapper Suite")
}

var _ = Describe("Run", func() {
	const metricsBindAddress = "127.0.0.1:8080"

	var (
		tempDir  string
		script   string
		argsFile string
		keyPath  string
		config   rbacproxy.Config
	)

	BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "rbacproxy-test-*")
		Expect(err).NotTo(HaveOccurred())

		// Create a fake kube-rbac-proxy script that dumps args to a file
		argsFile = filepath.Join(tempDir, "args.txt")

		script = `#!/bin/bash
# Dump all arguments to a file, one per line
for arg in "$@"; do
  echo "$arg" >> ` + argsFile + `
done
exit 0
`
		// Create test certificate files
		certPath := filepath.Join(tempDir, "tls.crt")
		Expect(os.WriteFile(certPath, []byte("fake-cert"), 0644)).To(Succeed())

		keyPath = filepath.Join(tempDir, "tls.key")
		Expect(os.WriteFile(keyPath, []byte("fake-key"), 0644)).To(Succeed())

		config = rbacproxy.Config{
			MetricsBindAddress: metricsBindAddress,
			CertPath:           certPath,
			KeyPath:            keyPath,
			ListenAddress:      ":9443",
			ProxyBinary:        filepath.Join(tempDir, "fake-kube-rbac-proxy"),
			Logger:             zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)),
		}
	})

	JustBeforeEach(func() {
		Expect(os.WriteFile(config.ProxyBinary, []byte(script), 0755)).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		_ = os.RemoveAll(tempDir)
	})

	readScriptArgs := func() []string {
		argsData, err := os.ReadFile(argsFile)
		Expect(err).NotTo(HaveOccurred())

		return strings.Split(strings.TrimSpace(string(argsData)), "\n")
	}

	Context("with TLS profile", func() {
		BeforeEach(func() {
			config.TLSProfileSpec = &configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS13,
				Ciphers: []string{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
				},
			}
		})

		It("should pass correct TLS arguments to kube-rbac-proxy", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			Expect(rbacproxy.Run(ctx, config)).To(Succeed())

			actualArgs := readScriptArgs()

			Expect(actualArgs).To(ContainElement("--secure-listen-address=:9443"))
			Expect(actualArgs).To(ContainElement("--upstream=http://" + metricsBindAddress))
			Expect(actualArgs).To(ContainElement("--tls-cert-file=" + config.CertPath))
			Expect(actualArgs).To(ContainElement("--tls-private-key-file=" + keyPath))
			Expect(actualArgs).To(ContainElement("--tls-cipher-suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"))
			Expect(actualArgs).To(ContainElement("--tls-min-version=VersionTLS13"))
		})
	})

	Context("with no TLS profile", func() {
		It("should pass fallback cipher suites to kube-rbac-proxy", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			Expect(rbacproxy.Run(ctx, config)).To(Succeed())

			actualArgs := readScriptArgs()

			Expect(actualArgs).To(ContainElement("--tls-cipher-suites=" + strings.Join(rbacproxy.DefaultFallbackCipherSuites, ",")))
			Expect(actualArgs).NotTo(ContainElement(HavePrefix("--tls-min-version")))
		})
	})

	When("certificate files don't appear", func() {
		BeforeEach(func() {
			// Create config pointing to non-existent certs
			config.CertPath = filepath.Join(tempDir, "nonexistent.crt")
			config.KeyPath = filepath.Join(tempDir, "nonexistent.key")
		})

		It("should return an error", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			Expect(rbacproxy.Run(ctx, config)).NotTo(Succeed())
		})
	})

	When("the context is cancelled", func() {
		BeforeEach(func() {
			script = `#!/bin/bash
echo "started" > ` + argsFile + `
sleep infinity
`
		})

		Specify("the proxy binary should exit successfully", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			errChan := make(chan error, 1)
			go func() {
				errChan <- rbacproxy.Run(ctx, config)
			}()

			// Wait for the subprocess to start
			Eventually(func(g Gomega) {
				data, err := os.ReadFile(argsFile)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(string(data)).To(ContainSubstring("started"))
			}, 5*time.Second, 50*time.Millisecond).Should(Succeed())

			cancel()

			// Verify Run completes with no error
			Eventually(errChan, 2*time.Second).Should(Receive(BeNil()))
		})
	})
})
