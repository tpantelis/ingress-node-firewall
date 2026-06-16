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

package tls

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/openshift/library-go/pkg/crypto"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type Profile struct {
	TLSOpts     []func(*tls.Config)
	ProfileSpec *configv1.TLSProfileSpec
	Adherence   configv1.TLSAdherencePolicy
}

func GetProfileInfo(ctx context.Context, client ctrlclient.Client) (Profile, error) {
	log := logr.FromContextOrDiscard(ctx)

	// Fetch the API Server configuration to get both TLS profile and adherence policy
	apiServer := &configv1.APIServer{}
	if err := client.Get(ctx, types.NamespacedName{Name: openshifttls.APIServerName}, apiServer); err != nil {
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			log.Info("OpenShift TLS profile API not available")
			return Profile{}, nil
		}

		return Profile{}, fmt.Errorf("failed to fetch apiserver.config.openshift.io/%s: %w", openshifttls.APIServerName, err)
	}

	profileSpec, err := openshifttls.GetTLSProfileSpec(apiServer.Spec.TLSSecurityProfile)
	if err != nil {
		return Profile{}, fmt.Errorf("failed to get TLS profile spec: %w", err)
	}

	info := Profile{
		ProfileSpec: &profileSpec,
		Adherence:   apiServer.Spec.TLSAdherence,
	}

	if !crypto.ShouldHonorClusterTLSProfile(apiServer.Spec.TLSAdherence) {
		log.Info("Not honoring TLS profile due to adherence policy", "adherence", apiServer.Spec.TLSAdherence)
		return info, nil
	}

	// Convert profile spec to tls.Config using official OpenShift package
	tlsConfigFunc, unsupportedCiphers := openshifttls.NewTLSConfigFromProfile(profileSpec)

	// Log warnings for any unsupported ciphers
	for _, cipher := range unsupportedCiphers {
		log.Info("Cipher suite not available in this Go version, skipping", "cipher", cipher)
	}

	info.TLSOpts = []func(*tls.Config){tlsConfigFunc}

	return info, nil
}

func WatchProfile(ctx context.Context, current Profile, mgr ctrl.Manager, onChange func()) error {
	log := logr.FromContextOrDiscard(ctx)

	if current.ProfileSpec == nil {
		return nil
	}

	tlsProfileWatcher := &openshifttls.SecurityProfileWatcher{
		Client:                    mgr.GetClient(),
		InitialTLSProfileSpec:     *current.ProfileSpec,
		InitialTLSAdherencePolicy: current.Adherence,
		OnProfileChange: func(_ context.Context, oldProfile, newProfile configv1.TLSProfileSpec) {
			log.Info(fmt.Sprintf("TLS security profile changed. Old: MinVersion=%s Ciphers=%d, New: MinVersion=%s Ciphers=%d",
				oldProfile.MinTLSVersion, len(oldProfile.Ciphers), newProfile.MinTLSVersion, len(newProfile.Ciphers)))
			onChange()
		},
		OnAdherencePolicyChange: func(_ context.Context, oldTLSAdherencePolicy, newTLSAdherencePolicy configv1.TLSAdherencePolicy) {
			log.Info(fmt.Sprintf("TLS Adherence policy changed. Old: %s, New: %s", oldTLSAdherencePolicy, newTLSAdherencePolicy))
			onChange()
		},
	}

	if err := tlsProfileWatcher.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup TLS profile watcher: %w", err)
	}

	return nil
}
