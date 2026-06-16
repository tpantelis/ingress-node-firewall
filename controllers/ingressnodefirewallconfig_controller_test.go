package controllers

import (
	"context"
	"fmt"
	"slices"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	ingressnodefwv1alpha1 "github.com/openshift/ingress-node-firewall/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

var _ = Describe("Ingress nodefirewall config Controller", func() {
	const (
		daemonContainerName = "daemon"
		eventsContainerName = "events"
		proxyContainerName  = "kube-rbac-proxy"
	)

	Context("syncIngressNodeFwConfig", func() {
		var config *ingressnodefwv1alpha1.IngressNodeFirewallConfig

		BeforeEach(func() {
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      IngressNodeFirewallResourceName,
					Namespace: IngressNodeFwConfigTestNameSpace,
				},
				Spec: ingressnodefwv1alpha1.IngressNodeFirewallConfigSpec{
					Debug: ptr.To(true),
				},
			}
		})

		JustBeforeEach(func() {
			By("Creating a Ingress node firewall config resource")

			Expect(k8sClient.Create(context.Background(), config)).To(Succeed())
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(context.Background(), config)).To(Succeed())

			_ = k8sClient.Delete(context.Background(), &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      DeamonSetName,
					Namespace: IngressNodeFwConfigTestNameSpace,
				},
			})
		})

		It("Should create manifests with images and namespace overridden", func() {
			daemonContainers := map[string]string{
				daemonContainerName: "test-daemon:latest",
				eventsContainerName: "test-daemon:latest",
				proxyContainerName:  "kube-rbac-proxy:latest",
			}

			By("Validating that the daemonset variables were templated correctly")
			daemonSet := awaitDaemonset()
			Expect(daemonSet.Spec.Template.Spec.Containers).To(HaveLen(len(daemonContainers)))

			for idx, c := range daemonSet.Spec.Template.Spec.Containers {
				image, ok := daemonContainers[c.Name]
				Expect(ok).To(BeTrue(), fmt.Sprintf("container %s not found in %s", c.Name, daemonContainers))
				Expect(c.Image).To(Equal(image))
				// check debug flag make sure its set
				if c.Name == "daemon" {
					for _, env := range daemonSet.Spec.Template.Spec.Containers[idx].Env {
						if env.Name == "ENABLE_EBPF_LPM_LOOKUP_DBG" {
							Expect(env.Value).To(Equal("1"))
						}
					}
				}
			}

			script := getContainerCommandScript(daemonSet, proxyContainerName)

			// With no TLS profile set (test default), should use fallback cipher suites
			Expect(script).To(ContainSubstring("--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
			// Should not have --tls-min-version when TLS profile is not set
			Expect(script).NotTo(ContainSubstring("--tls-min-version"))

			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err := k8sClient.Get(context.Background(), types.NamespacedName{Name: IngressNodeFirewallResourceName, Namespace: IngressNodeFwConfigTestNameSpace}, config)
			Expect(err).NotTo(HaveOccurred())
			By("Specify the NodeSelector")
			config.Spec.NodeSelector = map[string]string{"node-role.kubernetes.io/worker": "true"}
			err = k8sClient.Update(context.TODO(), config)
			Expect(err).NotTo(HaveOccurred())
			daemonSet = &appsv1.DaemonSet{}
			Eventually(func() map[string]string {
				err := k8sClient.Get(context.TODO(), types.NamespacedName{Name: DeamonSetName, Namespace: IngressNodeFwConfigTestNameSpace}, daemonSet)
				if err != nil {
					return nil
				}
				return daemonSet.Spec.Template.Spec.NodeSelector
			}, 2*time.Second, 200*time.Millisecond).Should(Equal(config.Spec.NodeSelector))
			Expect(daemonSet).NotTo(BeZero())
			Expect(len(daemonSet.Spec.Template.Spec.Containers)).To(BeNumerically(">", 0))
			// Reset nodeSelector configuration
			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: IngressNodeFirewallResourceName, Namespace: IngressNodeFwConfigTestNameSpace}, config)
			Expect(err).NotTo(HaveOccurred())
			config.Spec.NodeSelector = map[string]string{}
			err = k8sClient.Update(context.TODO(), config)
			Expect(err).NotTo(HaveOccurred())

			config = &ingressnodefwv1alpha1.IngressNodeFirewallConfig{}
			err = k8sClient.Get(context.Background(), types.NamespacedName{Name: IngressNodeFirewallResourceName, Namespace: IngressNodeFwConfigTestNameSpace}, config)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("When TLS profile is configured", func() {
			BeforeEach(func() {
				tlsProfile := &configv1.TLSProfileSpec{
					MinTLSVersion: configv1.VersionTLS13,
					Ciphers: []string{
						"TLS_AES_128_GCM_SHA256",
						"TLS_AES_256_GCM_SHA384",
					},
				}
				tlsProfileSpec.Store(tlsProfile)
			})

			It("Should apply TLS profile to kube-rbac-proxy when configured", func() {
				By("Validating that TLS configuration is applied to daemonset")

				script := getContainerCommandScript(awaitDaemonset(), proxyContainerName)
				Expect(script).To(ContainSubstring("--tls-cipher-suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"))
				Expect(script).To(ContainSubstring("--tls-min-version=VersionTLS13"))
			})
		})
	})
})

func awaitDaemonset() *appsv1.DaemonSet {
	daemonSet := &appsv1.DaemonSet{}
	Eventually(func() error {
		return k8sClient.Get(context.Background(), types.NamespacedName{Name: DeamonSetName, Namespace: IngressNodeFwConfigTestNameSpace},
			daemonSet)
	}, 5*time.Second, 100*time.Millisecond).ShouldNot((HaveOccurred()))

	return daemonSet
}

func getContainerCommandScript(daemonSet *appsv1.DaemonSet, name string) string {
	index := slices.IndexFunc(daemonSet.Spec.Template.Spec.Containers, func(c corev1.Container) bool {
		return c.Name == name
	})
	Expect(index).NotTo(Equal(-1))
	Expect(daemonSet.Spec.Template.Spec.Containers[index].Command).To(HaveLen(3))

	return daemonSet.Spec.Template.Spec.Containers[index].Command[2]
}
