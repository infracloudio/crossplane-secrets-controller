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
	"fmt"
	"time"

	"github.com/argoproj/argo-cd/common"
	appv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"
	argoappsv1 "github.com/argoproj/argo-cd/pkg/apis/application/v1alpha1"

	"github.com/argoproj/argo-cd/util/clusterauth"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

const finalizer string = "argocd-connector/finalizers.vadasambar.github.io"

// +kubebuilder:rbac:groups=connectors.argocd-connector.vadasambar.github.io,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=connectors.argocd-connector.vadasambar.github.io,resources=secrets/status,verbs=get;update;patch
func (r *SecretReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("secret", req.NamespacedName)

	if req.NamespacedName.Namespace != "crossplane-system" {
		return ctrl.Result{}, nil
	}

	r.Log.V(0).Info("processing request", "request", req.NamespacedName)

	ctx := context.Background()
	secret := &v1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, secret); err != nil {
		r.Log.Error(err, "could not get the secret", "instance", "SecretReconciler")
		r.Log.Info("deleting the cluster connection in argocd", "instance", "SecretReconciler")
		if kerrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !secret.ObjectMeta.DeletionTimestamp.IsZero() {
		err := r.removeClusterFromArgoCD(secret)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	if len(secret.ObjectMeta.OwnerReferences) > 0 && secret.ObjectMeta.OwnerReferences[0].Kind == "KubernetesCluster" {
		r.Log.V(0).Info("found cluster connection secret", "secret", req.NamespacedName)

		clusterName := secret.ObjectMeta.OwnerReferences[0].Name
		kubeConfig := secret.Data["kubeconfig"]
		externalRestConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeConfig)
		if err != nil {
			r.Log.Error(err, "could not retrieve rest config from kubeconfig inside the secret", "secret", secret)
		}
		r.Log.V(0).Info("extracted rest config from secret", "secret", secret.Name)

		internalRestConfig, err := clientcmd.BuildConfigFromFlags("", "/home/user/.kube/config")

		// internalRestConfig, err := rest.InClusterConfig()
		if err != nil {
			r.Log.Error(err, "could not read rest config from inside the argocd cluster", "instance", "Secret Controller")
			return ctrl.Result{}, nil
		}
		internalClientSet, err := kubernetes.NewForConfig(internalRestConfig)
		if err != nil {
			r.Log.Error(err, "could not create secrets client for argocd", "instance", "Secret Controller")
		}

		argocdSecrets, err := internalClientSet.CoreV1().Secrets("argocd").List(metav1.ListOptions{})
		if err != nil {
			r.Log.Error(err, "could not read secrets from argocd", "instance", "Secret Controller")
		}

		newClusterSecretName := fmt.Sprintf("cluster-%s-crossplane-%s", clusterName, secret.ObjectMeta.UID)
		for _, argocdSecret := range argocdSecrets.Items {
			if argocdSecret.Name == newClusterSecretName && argocdSecret.ObjectMeta.Annotations["crossplane-secret"] == secret.Name {
				r.Log.Info("cluster already exists in argocd", "secret in argocd", argocdSecret.Name, "crossplane connection secret", secret.Name)
				return ctrl.Result{}, nil
			}
		}

		if err != nil {
			r.Log.Error(err, "could not get rest config for the controller instance", "instance", "Secret Controller")
		}
		externalClientSet, err := kubernetes.NewForConfig(externalRestConfig)
		if err != nil {
			r.Log.Error(err, "could not create secrets client for provisioned cluster", "instance", "Secret Controller")
		}

		bearerToken, err := clusterauth.InstallClusterManagerRBAC(externalClientSet, "kube-system")
		if err != nil {
			r.Log.Error(err, "could not get bearer token", "instance", "Secret Controller")
		}

		argoCluster := argoappsv1.Cluster{
			Server: externalRestConfig.Host,
			Name:   newClusterSecretName,
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
		secretsClient := internalClientSet.CoreV1().Secrets("argocd")

		addClusterSecret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: newClusterSecretName,
				Labels: map[string]string{
					common.LabelKeySecretType: common.LabelValueSecretTypeCluster,
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
		}

		r.Log.V(0).Info("FINALIZERS", "OBJECT META", secret.ObjectMeta)
		if !containsString(secret.ObjectMeta.Finalizers, finalizer) {
			secret.ObjectMeta.Finalizers = append(secret.ObjectMeta.Finalizers, finalizer)
			err = r.Client.Update(ctx, secret)
			if err != nil {
				r.Log.Error(err, "failed to add finalizer to cluster connection secret", "instance", "Secret Controller", "secret", secret.ObjectMeta.Name)
				return ctrl.Result{}, nil
			} else {
				r.Log.V(0).Info("added finalizer to cluster connection secret", "instance", "Secret Controller",
					"secret", secret.ObjectMeta.Name, "finalizer", finalizer)
			}
		}

	}

	return ctrl.Result{}, nil
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}).
		Complete(r)
}
func (r *SecretReconciler) removeClusterFromArgoCD(secret *v1.Secret) error {

	clusterName := secret.ObjectMeta.OwnerReferences[0].Name
	clusterSecretName := fmt.Sprintf("cluster-%s-crossplane-%s", clusterName, secret.ObjectMeta.UID)

	// internalRestConfig, err := rest.InClusterConfig()
	internalRestConfig, err := clientcmd.BuildConfigFromFlags("", "/home/user/.kube/config")
	if err != nil {
		r.Log.Error(err, "could not read rest config from inside the argocd cluster", "instance", "Secret Controller")
		return err
	}
	internalClientSet, err := kubernetes.NewForConfig(internalRestConfig)
	if err != nil {
		r.Log.Error(err, "could not create secrets client for argocd", "instance", "Secret Controller")
		return err
	}

	secretsClient := internalClientSet.CoreV1().Secrets("argocd")
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

func containsString(slice []string, str string) bool {
	for _, elem := range slice {
		if elem == str {
			return true
		}
	}

	return false
}

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
