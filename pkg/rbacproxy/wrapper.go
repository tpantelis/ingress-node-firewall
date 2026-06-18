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

package rbacproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	CertificateWaitTimeout   = 20 * time.Minute
	CertificateCheckInterval = 1 * time.Second
	LogFrequency             = 1 * time.Minute
)

// DefaultFallbackCipherSuites are the cipher suites used when no TLS profile is configured
var DefaultFallbackCipherSuites = []string{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_RSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
}

// Config holds the configuration for running kube-rbac-proxy
type Config struct {
	// MetricsBindAddress is the upstream metrics endpoint (e.g., "127.0.0.1:39400")
	MetricsBindAddress string
	// CertPath is the path to the TLS certificate file
	CertPath string
	// KeyPath is the path to the TLS key file
	KeyPath string
	// ListenAddress is the secure listen address for kube-rbac-proxy
	ListenAddress string
	// ProxyBinary is the path to the kube-rbac-proxy binary
	ProxyBinary string
	// TLSProfileSpec contains the TLS security profile configuration
	TLSProfileSpec *configv1.TLSProfileSpec
	// Logger for structured logging
	Logger logr.Logger
}

// Run waits for TLS certificates to be available and then runs kube-rbac-proxy as a subprocess
func Run(ctx context.Context, cfg Config) error {
	if cfg.ProxyBinary == "" {
		cfg.ProxyBinary = "/usr/bin/kube-rbac-proxy"
	}

	cfg.Logger.Info("Starting kube-rbac-proxy wrapper, waiting for TLS certificates", "certPath", cfg.CertPath, "keyPath", cfg.KeyPath)

	// Wait for certificate files to exist with timeout
	pollCount := 0
	logInterval := int(LogFrequency / CertificateCheckInterval)

	err := wait.PollUntilContextTimeout(ctx, CertificateCheckInterval, CertificateWaitTimeout, true, func(ctx context.Context) (bool, error) {
		certExists := fileExists(cfg.CertPath)
		keyExists := fileExists(cfg.KeyPath)

		if certExists && keyExists {
			cfg.Logger.Info("TLS certificates found, starting kube-rbac-proxy")
			return true, nil
		}

		// Log periodically while waiting
		pollCount++
		if pollCount%logInterval == 0 {
			cfg.Logger.Info("Still waiting for TLS certificates...")
		}

		return false, nil
	})

	if err != nil {
		return fmt.Errorf("failed waiting for certificates: %w", err)
	}

	args := buildProxyArgs(cfg)

	// Run kube-rbac-proxy as subprocess
	return runProxy(ctx, cfg.ProxyBinary, args, cfg.Logger)
}

// buildProxyArgs constructs the arguments for kube-rbac-proxy
func buildProxyArgs(cfg Config) []string {
	args := []string{
		"--secure-listen-address=" + cfg.ListenAddress,
		"--upstream=http://" + cfg.MetricsBindAddress,
		"--tls-cert-file=" + cfg.CertPath,
		"--tls-private-key-file=" + cfg.KeyPath,
	}

	// Add TLS configuration
	if cfg.TLSProfileSpec != nil && len(cfg.TLSProfileSpec.Ciphers) > 0 {
		args = append(args, "--tls-cipher-suites="+strings.Join(cfg.TLSProfileSpec.Ciphers, ","))
	} else {
		args = append(args, "--tls-cipher-suites="+strings.Join(DefaultFallbackCipherSuites, ","))
	}

	if cfg.TLSProfileSpec != nil && cfg.TLSProfileSpec.MinTLSVersion != "" {
		args = append(args, "--tls-min-version="+string(cfg.TLSProfileSpec.MinTLSVersion))
	}

	return args
}

// fileExists checks if a file exists and is readable
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// runProxy runs kube-rbac-proxy as a subprocess and waits for it to complete
// The subprocess will be killed if the context is cancelled
func runProxy(ctx context.Context, binaryPath string, args []string, logger logr.Logger) error {
	logger.Info("Starting kube-rbac-proxy subprocess",
		"binary", binaryPath,
		"args", args)

	// Find the full path to the binary
	resolvedPath, err := exec.LookPath(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to find kube-rbac-proxy binary: %w", err)
	}

	// Create command with context (subprocess will be killed when context is cancelled)
	cmd := exec.CommandContext(ctx, resolvedPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start kube-rbac-proxy: %w", err)
	}

	logger.Info("kube-rbac-proxy started", "pid", cmd.Process.Pid)

	// Wait for the process to complete
	err = cmd.Wait()
	if err != nil {
		// Check if it was killed due to context cancellation
		if ctx.Err() == context.Canceled {
			logger.Info("kube-rbac-proxy stopped due to context cancellation")
			return nil // Not an error, just shutdown
		}
		return fmt.Errorf("kube-rbac-proxy exited with error: %w", err)
	}

	logger.Info("kube-rbac-proxy exited successfully")
	return nil
}
