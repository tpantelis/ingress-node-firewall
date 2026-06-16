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

package tls_test

import (
	"context"
	"crypto/tls"
	"os"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	inftls "github.com/openshift/ingress-node-firewall/pkg/tls"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	_ = Describe("GetProfileInfo", testGetProfileInfo)
	_ = Describe("WatchProfile", testWatchProfile)
)

func testGetProfileInfo() {
	t := newTestDriver()

	applyTLSOpts := func(opts []func(*tls.Config)) *tls.Config {
		tlsConfig := &tls.Config{}
		for _, f := range opts {
			f(tlsConfig)
		}

		return tlsConfig
	}

	Context("with Intermediate TLS profile", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile.Type = configv1.TLSProfileIntermediateType
		})

		It("should return a profile with MinVersion TLS 1.2", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.ProfileSpec).To(Equal(configv1.TLSProfiles[configv1.TLSProfileIntermediateType]))
			Expect(profile.Adherence).To(Equal(configv1.TLSAdherencePolicyStrictAllComponents))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(tlsConfig.CipherSuites).NotTo(BeEmpty())
		})
	})

	Context("with Modern TLS profile (TLS 1.3)", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile.Type = configv1.TLSProfileModernType
		})

		It("should return a profile with MinVersion TLS 1.3 and no CipherSuites", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.ProfileSpec).To(Equal(configv1.TLSProfiles[configv1.TLSProfileModernType]))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			Expect(tlsConfig.CipherSuites).To(BeEmpty())
		})
	})

	Context("with Custom TLS profile", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS11,
						Ciphers: []string{
							"ECDHE-ECDSA-AES128-GCM-SHA256",
							"ECDHE-RSA-AES128-GCM-SHA256",
							"Unknown",
						},
					},
				},
			}
		})

		It("should return a valid profile with the custom settings", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)

			Expect(err).NotTo(HaveOccurred())
			Expect(profile.ProfileSpec).To(Equal(&t.apiServer.Spec.TLSSecurityProfile.Custom.TLSProfileSpec))

			tlsConfig := applyTLSOpts(profile.TLSOpts)
			Expect(tlsConfig.MinVersion).To(Equal(uint16(tls.VersionTLS11)))
			Expect(tlsConfig.CipherSuites).To(HaveLen(2))
		})
	})

	Context("with tlsAdherence set to LegacyAdheringComponentsOnly", func() {
		BeforeEach(func() {
			t.apiServer.Spec.TLSSecurityProfile.Type = configv1.TLSProfileModernType
			t.apiServer.Spec.TLSAdherence = configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly
		})

		It("should return a valid profile with emtpy TLSOpts", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)
			Expect(err).NotTo(HaveOccurred())

			Expect(profile.TLSOpts).To(BeEmpty())
			Expect(profile.ProfileSpec).To(Equal(configv1.TLSProfiles[configv1.TLSProfileModernType]))
			Expect(profile.Adherence).To(Equal(configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly))
		})
	})

	When("the APIServer resource does not exist", func() {
		BeforeEach(func() {
			t.apiServer = nil
		})

		It("should return an empty profile", func() {
			profile, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)
			Expect(err).NotTo(HaveOccurred())

			Expect(profile.ProfileSpec).To(BeNil())
			Expect(profile.TLSOpts).To(BeEmpty())
		})
	})

	When("the APIServer resource retrieval fails", func() {
		BeforeEach(func() {
			t.tlsClient = fake.NewClientBuilder().
				WithScheme(t.clientScheme).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
						return apierrors.NewServiceUnavailable("mock error")
					},
				}).
				Build()
		})

		It("should return an error", func() {
			_, err := inftls.GetProfileInfo(newLogContext(), t.tlsClient)
			Expect(err).To(HaveOccurred())
		})
	})
}

func testWatchProfile() {
	t := newTestDriver()

	var fakeMgr *FakeManager

	JustBeforeEach(func() {
		mgr, err := ctrl.NewManager(&rest.Config{}, ctrl.Options{
			Metrics: server.Options{
				BindAddress: "0",
			},
			Controller: ctrlconfig.Controller{
				SkipNameValidation: ptr.To(true),
			},
		})
		Expect(err).NotTo(HaveOccurred())

		fakeMgr = &FakeManager{
			Manager: mgr,
		}

		// Create fake client with interceptor that triggers reconciliation on APIServer updates.
		fakeMgr.client = fake.NewClientBuilder().
			WithScheme(k8sscheme.Scheme).
			WithObjects(t.apiServer).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, client client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
					if err := client.Update(ctx, obj, opts...); err != nil {
						return err
					}

					if apiServer, ok := obj.(*configv1.APIServer); ok {
						fakeMgr.triggerReconcile(ctx, apiServer)
					}

					return nil
				},
			}).Build()
	})

	testAPIServerUpdate := func(modify func(*configv1.APIServer)) {
		ctx, cancel := context.WithCancel(newLogContext())
		defer cancel()

		profileSpec, err := openshifttls.GetTLSProfileSpec(t.apiServer.Spec.TLSSecurityProfile)
		Expect(err).NotTo(HaveOccurred())

		Expect(inftls.WatchProfile(ctx, inftls.Profile{
			ProfileSpec: &profileSpec,
			Adherence:   t.apiServer.Spec.TLSAdherence,
		}, fakeMgr, cancel)).To(Succeed())

		// Update the APIServer object to change the TLS profile to Modern
		apiServer := &configv1.APIServer{}
		Expect(fakeMgr.client.Get(ctx, client.ObjectKey{Name: openshifttls.APIServerName}, apiServer)).To(Succeed())

		modify(apiServer)

		Expect(fakeMgr.client.Update(ctx, apiServer)).To(Succeed())

		// Wait for the context to be canceled
		Eventually(ctx.Done()).Within(2 * time.Second).Should(BeClosed())
	}

	When("the TLS profile changes", func() {
		It("should invoke onChange", func() {
			testAPIServerUpdate(func(apiServer *configv1.APIServer) {
				apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
					Type: configv1.TLSProfileModernType,
				}
			})
		})
	})

	When("TLS adherence changes", func() {
		It("should invoke onChange", func() {
			testAPIServerUpdate(func(apiServer *configv1.APIServer) {
				apiServer.Spec.TLSAdherence = configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly
			})
		})
	})
}

type testDriver struct {
	tlsClient    client.Client
	clientScheme *runtime.Scheme
	apiServer    *configv1.APIServer
}

func newTestDriver() *testDriver {
	t := &testDriver{}

	BeforeEach(func() {
		t.apiServer = &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{
				Name: openshifttls.APIServerName,
			},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{},
				TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}

		t.clientScheme = runtime.NewScheme()
		utilruntime.Must(configv1.Install(t.clientScheme))

		t.tlsClient = fake.NewClientBuilder().WithScheme(t.clientScheme).Build()
	})

	JustBeforeEach(func() {
		if t.apiServer != nil {
			Expect(t.tlsClient.Create(context.TODO(), t.apiServer)).To(Succeed())
		}
	})

	return t
}

type FakeManager struct {
	manager.Manager
	client     client.Client
	reconciler reconcile.Reconciler
}

func (f *FakeManager) GetClient() client.Client {
	return f.client
}

// Add captures reconcilers so we can trigger them manually
func (f *FakeManager) Add(runnable manager.Runnable) error {
	if r, ok := runnable.(reconcile.Reconciler); ok {
		f.reconciler = r
	}

	return f.Manager.Add(runnable)
}

func (f *FakeManager) triggerReconcile(ctx context.Context, apiServer *configv1.APIServer) {
	req := reconcile.Request{
		NamespacedName: client.ObjectKey{
			Name: apiServer.Name,
		},
	}

	go func(r reconcile.Reconciler) {
		_, _ = r.Reconcile(ctx, req)
	}(f.reconciler)
}

func newLogContext() context.Context {
	return logr.NewContext(context.TODO(), zap.New(zap.WriteTo(os.Stdout), zap.UseDevMode(true)))
}
