/*

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

package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/argoproj/argo-cd/common"
	appv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	argoappsv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"

	"github.com/argoproj/argo-cd/util/clusterauth"
	crossplanev1alpha1 "github.com/crossplaneio/crossplane/apis/compute/v1alpha1"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log                 logr.Logger
	Scheme              *runtime.Scheme
	CrossplaneNamespace string
	ArgoCDNamespace     string
}

const finalizer string = "argocd-connector/finalizers.vadasambar.github.io"
const argocdConnector string = "argocd-connector"

// KubernetesSystemNamespace is the system namespace of kubernetes
const KubernetesSystemNamespace = "kube-system"

// +kubebuilder:rbac:groups=connectors.argocd-connector.vadasambar.github.io,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=connectors.argocd-connector.vadasambar.github.io,resources=secrets/status,verbs=get;update;patch
func (r *SecretReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("secret", req.NamespacedName)

	if req.NamespacedName.Namespace != r.CrossplaneNamespace {
		return ctrl.Result{}, nil
	}

	r.Log.V(0).Info("processing request", "request", req.NamespacedName)

	ctx := context.Background()
	secret := &v1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, secret); err != nil {
		r.Log.Error(err, "could not get the secret", "instance", "SecretReconciler")
		return ignoreNotFound(err)
	}

	if !secret.ObjectMeta.DeletionTimestamp.IsZero() {
		r.Log.Info("deleting the cluster connection in argocd", "instance", "SecretReconciler")
		err := r.removeClusterFromArgoCD(secret)
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	if isSecretOwnedByCluster(secret) {
		r.Log.V(0).Info("found cluster connection secret", "secret", req.NamespacedName)

		internalClientSet, err := r.getInternalClientSet()
		if err != nil {
			return ctrl.Result{}, nil
		}

		if alreadyExists, err := r.doesArgoCDClusterConnectionAlreadyExists(internalClientSet, secret); err != nil || alreadyExists {
			return ctrl.Result{}, nil
		}

		externalClientSet, externalRestConfig, err := r.getExternalClientSetWithRestConfig(secret)
		if err != nil {
			r.Log.Error(err, "could not create secrets client for provisioned cluster", "instance", "Secret Controller")
			return ctrl.Result{}, err
		}

		if ctrlResult, err := r.addClusterToArgoCD(externalClientSet, internalClientSet, externalRestConfig, secret); err != nil {
			return ctrlResult, err
		}

		if ctrlResult, err := r.addFinalizerToCrossplaneConnectionSecret(secret); err != nil {
			return ctrlResult, err
		}

	}

	return ctrl.Result{}, nil
}

// addFinalizerToCrossplaneConnectionSecret adds finalizer to the crossplane connnection secret
// this is to ensure argocd cluster connection is deleted when crossplane connection secret is deleted
func (r *SecretReconciler) addFinalizerToCrossplaneConnectionSecret(secret *v1.Secret) (ctrl.Result, error) {
	ctx := context.Background()
	if !containsString(secret.ObjectMeta.Finalizers, finalizer) {
		secret.ObjectMeta.Finalizers = append(secret.ObjectMeta.Finalizers, finalizer)
		err := r.Client.Update(ctx, secret)
		if err != nil {
			r.Log.Error(err, "failed to add finalizer to cluster connection secret", "instance", "Secret Controller", "secret", secret.ObjectMeta.Name)
			return ctrl.Result{}, err
		} else {
			r.Log.V(0).Info("added finalizer to cluster connection secret", "instance", "Secret Controller",
				"secret", secret.ObjectMeta.Name, "finalizer", finalizer)
		}
	}
	return ctrl.Result{}, nil
}

// addClusterToArgoCD adds a cluster connection to argocd
func (r *SecretReconciler) addClusterToArgoCD(externalClientSet *kubernetes.Clientset,
	internalClientSet *kubernetes.Clientset,
	externalRestConfig *rest.Config, secret *v1.Secret) (ctrl.Result, error) {

	clusterToAddName, err := r.getArgoCDConnectionClusterName(secret)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.Log.V(0).Info("adding cluster to argocd", "instance", "Secret Controller", "cluster name in argocd", clusterToAddName)
	r.Log.V(0).Info("setting up RBAC in the provisioned cluster", "instance", "Secret Controller")

	bearerToken, err := clusterauth.InstallClusterManagerRBAC(externalClientSet, KubernetesSystemNamespace)
	if err != nil {
		r.Log.Error(err, "could not get bearer token", "instance", "Secret Controller")
		return ctrl.Result{Requeue: true}, err
	}

	argoCluster := argoappsv1.Cluster{
		Server: externalRestConfig.Host,
		Name:   clusterToAddName,
		Config: argoappsv1.ClusterConfig{
			BearerToken: bearerToken,
			TLSClientConfig: argoappsv1.TLSClientConfig{
				Insecure:   externalRestConfig.TLSClientConfig.Insecure,
				ServerName: externalRestConfig.TLSClientConfig.ServerName,
				CAData:     externalRestConfig.TLSClientConfig.CAData,
			},
			AWSAuthConfig: nil, // this should read aws config
		},
	}

	// this should be read either from env variable or some other means instead of hard coding
	secretsClient := internalClientSet.CoreV1().Secrets(r.ArgoCDNamespace)

	addClusterSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterToAddName,
			Labels: map[string]string{
				common.LabelKeySecretType: common.LabelValueSecretTypeCluster,
				"created-by":              argocdConnector,
			},
			Annotations: map[string]string{
				common.AnnotationKeyManagedBy: common.AnnotationValueManagedByArgoCD,
				"crossplane-secret":           secret.Name,
			},
		},
	}

	addClusterSecret.Data = clusterToData(&argoCluster)

	_, err = secretsClient.Create(addClusterSecret)
	if err != nil {
		if !kerrors.IsAlreadyExists(err) {
			r.Log.Error(err, "could not create secret", "instance", "Secret Controller")
			return ctrl.Result{
				Requeue:      true,
				RequeueAfter: time.Second * 10,
			}, nil
		}

		r.Log.Error(err, "cluster already exists in argocd", "instance", "Secret Controller")
		return ctrl.Result{}, err
	}

	r.Log.V(0).Info("added cluster to argocd", "instance", "Secret Controller", "cluster name in argocd", clusterToAddName)

	return ctrl.Result{}, nil
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(r)
}

// doesArgoCDClusterConnectionAlreadyExists checks if the crossplane connection secret already has a correspondong cluster connection in argocd
func (r *SecretReconciler) doesArgoCDClusterConnectionAlreadyExists(internalClientSet *kubernetes.Clientset, secret *v1.Secret) (bool, error) {
	argocdSecrets, err := internalClientSet.CoreV1().Secrets(r.ArgoCDNamespace).List(metav1.ListOptions{})
	if err != nil {
		r.Log.Error(err, "could not read secrets from argocd", "instance", "Secret Controller")
		return false, err
	}

	newClusterSecretName, err := r.getArgoCDConnectionClusterName(secret)
	if err != nil {
		return false, err
	}
	for _, argocdSecret := range argocdSecrets.Items {
		if argocdSecret.Name == newClusterSecretName && argocdSecret.ObjectMeta.Annotations["crossplane-secret"] == secret.Name {
			r.Log.Info("cluster already exists in argocd", "secret in argocd", argocdSecret.Name, "crossplane connection secret", secret.Name)
			return true, nil
		}
	}

	return false, nil
}

// getArgoCDConnectionClusterName returns name of the cluster connection to create in argocd
func (r *SecretReconciler) getArgoCDConnectionClusterName(secret *v1.Secret) (string, error) {
	kubernetesClusterName := secret.ObjectMeta.OwnerReferences[0].Name
	kubernetesCluster := &crossplanev1alpha1.KubernetesCluster{}
	err := r.Get(context.Background(), types.NamespacedName{Name: kubernetesClusterName, Namespace: r.CrossplaneNamespace}, kubernetesCluster)
	if err != nil {
		r.Log.Error(err, "could not get external cluster name", "instance", "Secret Controller")
		return "", err
	}

	annotations := kubernetesCluster.ObjectMeta.GetAnnotations()
	externalClusterName, ok := annotations["crossplane.io/external-name"]
	if !ok {
		err := errors.New("could not retrieve external cluster name")
		r.Log.Error(err, "'KubernetesCluster' resource should have 'crossplane.io/external-name' annotation to specify cluster name")
		autoGeneratedName := autoGenerateArgoCDConnectionClusterName(secret)
		r.Log.V(0).Info("auto generating cluster name for argocd connection", "cluster-name", autoGeneratedName)
		return autoGeneratedName, nil
	}

	return externalClusterName, nil
}

func autoGenerateArgoCDConnectionClusterName(secret *v1.Secret) string {
	clusterName := secret.ObjectMeta.OwnerReferences[0].Name
	return fmt.Sprintf("cluster-%s-crossplane-%s", clusterName, secret.ObjectMeta.UID)
}

// removeClusterFromArgoCD removes cluster from argocd if the cluster connection secret has been deleted in crossplane
func (r *SecretReconciler) removeClusterFromArgoCD(secret *v1.Secret) error {

	clusterName := secret.ObjectMeta.OwnerReferences[0].Name
	clusterSecretName := fmt.Sprintf("cluster-%s-crossplane-%s", clusterName, secret.ObjectMeta.UID)

	internalRestConfig, err := getInternalRestConfig()
	if err != nil {
		r.Log.Error(err, "could not read rest config from inside the argocd cluster", "instance", "Secret Controller")
		return err
	}
	internalClientSet, err := kubernetes.NewForConfig(internalRestConfig)
	if err != nil {
		r.Log.Error(err, "could not create secrets client for argocd", "instance", "Secret Controller")
		return err
	}

	secretsClient := internalClientSet.CoreV1().Secrets(r.ArgoCDNamespace)
	err = secretsClient.Delete(clusterSecretName, &metav1.DeleteOptions{})
	if err != nil {
		r.Log.Error(err, "could not remove the cluster from  argocd", "instance", "Secret Controller")
		return err
	}

	secret.ObjectMeta.Finalizers = removeString(secret.ObjectMeta.Finalizers, finalizer)
	err = r.Client.Update(context.Background(), secret)
	if err != nil {
		r.Log.Error(err, "failed to remove finalizer from cluster connection secret", "instance", "Secret Controller", "secret", secret.ObjectMeta.Name)
		return err
	}
	r.Log.Info("deleted the cluster connection from argocd")
	return nil
}

// containsString checks if a slice of string contains the required string
func containsString(slice []string, str string) bool {
	for _, elem := range slice {
		if elem == str {
			return true
		}
	}

	return false
}

// isSecretOwnedByCluster checks if the secret is a cluster connection secret
func isSecretOwnedByCluster(secret *v1.Secret) bool {
	return len(secret.ObjectMeta.OwnerReferences) > 0 && secret.ObjectMeta.OwnerReferences[0].Kind == "KubernetesCluster"
}

// getExternalClientSetWithRestConfig reads kubeconfig from crossplane connection secret and returns the rest config with clientset
func (r *SecretReconciler) getExternalClientSetWithRestConfig(secret *v1.Secret) (*kubernetes.Clientset, *rest.Config, error) {
	kubeConfig := secret.Data["kubeconfig"]
	externalRestConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeConfig)
	if err != nil {
		r.Log.Error(err, "could not retrieve rest config from kubeconfig inside the secret", "secret", secret)
		return nil, nil, err
	}
	r.Log.V(0).Info("extracted rest config from secret", "secret", secret.Name)

	externalClientSet, err := kubernetes.NewForConfig(externalRestConfig)
	if err != nil {
		r.Log.Error(err, "could not create secrets client for provisioned cluster", "instance", "Secret Controller")
		return nil, externalRestConfig, err
	}

	return externalClientSet, externalRestConfig, nil
}

// getInternalRestConfig returns rest config depending on if the controller
// is being run locally or inside a cluster
func getInternalRestConfig() (*rest.Config, error) {
	kubeConfigPath := "/home/user/.kube/config"
	_, err := os.Open(kubeConfigPath)
	if os.IsNotExist(err) {
		return rest.InClusterConfig()
	}
	return clientcmd.BuildConfigFromFlags("", kubeConfigPath)
}

// getInternalClientSet returns client set of the cluster where argocd and crossplane are installed
func (r *SecretReconciler) getInternalClientSet() (*kubernetes.Clientset, error) {
	internalRestConfig, err := getInternalRestConfig()
	if err != nil {
		r.Log.Error(err, "could not read rest config from inside the argocd cluster", "instance", "Secret Controller")
		return nil, err
	}
	internalClientSet, err := kubernetes.NewForConfig(internalRestConfig)
	if err != nil {
		r.Log.Error(err, "could not create secrets client for argocd", "instance", "Secret Controller")
	}

	return internalClientSet, nil
}

// removeString removes a string from a slice
func removeString(slice []string, str string) []string {
	newSlice := []string{}
	for _, elem := range slice {
		if elem == str {
			continue
		}
		newSlice = append(newSlice, elem)
	}

	return newSlice
}

// clusterToData returns the cluster config required to create a cluster connection in argocd
func clusterToData(c *appv1.Cluster) map[string][]byte {
	data := make(map[string][]byte)
	data["server"] = []byte(c.Server)
	if c.Name == "" {
		data["name"] = []byte(c.Server)
	} else {
		data["name"] = []byte(c.Name)
	}
	configBytes, err := json.Marshal(c.Config)
	if err != nil {
		panic(err)
	}
	data["config"] = configBytes
	return data
}

// ignoreNotFound ignores not found errors
func ignoreNotFound(err error) (ctrl.Result, error) {
	if kerrors.IsNotFound(err) {
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, err
}
