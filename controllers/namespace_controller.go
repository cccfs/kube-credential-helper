/*
Copyright 2022.

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
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/presslabs/controller-util/pkg/syncer"
	"github.com/vaughan0/go-ini"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	"reflect"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"strings"
)

// NamespaceReconciler reconciles a Namespace object
type NamespaceReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

type Config struct {
	ExcludedNamespace   string
	ImagePullSecretName string
	ConfigPath          string
	ServiceAccountName  string
}

//+kubebuilder:rbac:groups=crd.k8s.deeproute.cn,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=crd.k8s.deeproute.cn,resources=namespaces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=crd.k8s.deeproute.cn,resources=namespaces/finalizers,verbs=update

//+kubebuilder:rbac:groups="",resources=secrets;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Namespace object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile

var config Config

func init() {
	//startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	//startCmd.StringVar(&c.ConfigPath, "config-path", LookupEnvOrString("CONFIG_PATH", "config.ini"), "The config.ini files path")
	//startCmd.StringVar(&c.ExcludedNamespace, "excluded-namespace", LookupEnvOrString("EXCLUDED_NAMESPACE", "kube-system"), "Comma-separated namespaces excluded from processing")
	//startCmd.StringVar(&c.ImagePullSecretName, "image-pull-secret-name", LookupEnvOrString("IMAGE_PULL_SECRET_NAME", "image-pull-secret"), "Name of managed secrets")
	//startCmd.Parse(os.Args[2:])
	flag.StringVar(&config.ConfigPath, "config-path", LookupEnvOrString("CONFIG_PATH", "config.ini"), "The config.ini files path")
	flag.StringVar(&config.ExcludedNamespace, "excluded-namespace", LookupEnvOrString("EXCLUDED_NAMESPACE", "kube-system"), "Comma-separated namespaces excluded from processing")
	flag.StringVar(&config.ImagePullSecretName, "image-pull-secret-name", LookupEnvOrString("IMAGE_PULL_SECRET_NAME", "image-pull-secret"), "Name of managed secrets")
	flag.StringVar(&config.ServiceAccountName, "service-account-name", LookupEnvOrString("SERVICE_ACCOUNT_NAME", "default"), "Comma-separated list of serviceAccounts to patch")
}

func (r *NamespaceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// TODO(user): your logic here
	namespaceInstance := &corev1.Namespace{}
	err := r.Client.Get(ctx, req.NamespacedName, namespaceInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			klog.V(4).Info("Namespace [%s] resource not found. Ignoring since object must be deleted", namespaceInstance.Name)
			return ctrl.Result{}, nil
		}
		klog.Error(err, "Unable to fetch namespace")
		return ctrl.Result{}, err
	}

	if namespaceInstance.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}

	if config.namespaceIsExcluded(namespaceInstance) {
		klog.V(4).Infof("Namespace [%s] ignoring since object must be excluded", namespaceInstance.Name)
		return reconcile.Result{}, nil
	}

	namespaceStatus := *namespaceInstance.Status.DeepCopy()
	defer func() {
		if !reflect.DeepEqual(namespaceStatus, namespaceInstance.Status) {
			err = r.Status().Update(ctx, namespaceInstance)
			if err != nil {
				klog.Error(err, "Failed to update namespace status")
			}
		}
	}()

	dockerConfigDataObject, err1 := config.parseConfigFiles()
	if err1 != nil {
		klog.Errorf("Not found %v files", config.ConfigPath)
	}

	secretSyncers := []syncer.Interface{
		NewSecretSyncer(r.Client, namespaceInstance, dockerConfigDataObject),
	}

	secretInstance := &corev1.Secret{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: config.ImagePullSecretName, Namespace: namespaceInstance.Name}, secretInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			klog.V(4).Infof("Secret [%s/%s] resources not found", namespaceInstance.Name, config.ImagePullSecretName)
			if err = r.sync(secretSyncers, namespaceInstance); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		err = r.updateSecret(ctx, secretSyncers, secretInstance, namespaceInstance, dockerConfigDataObject)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	serviceAccountInstance := &corev1.ServiceAccount{}
	err = r.Client.Get(ctx, types.NamespacedName{Name: config.ServiceAccountName, Namespace: namespaceInstance.Name}, serviceAccountInstance)
	if err != nil {
		if errors.IsNotFound(err) {
			klog.V(4).Infof("ServiceAccount [%s/%s] resources not found", namespaceInstance.Name, config.ServiceAccountName)
			//var interval int64 = 1
			//return ctrl.Result{RequeueAfter: time.Second * time.Duration(interval)}, nil
			return ctrl.Result{Requeue: true}, nil
		}
		klog.Errorf("Unable to fetch ServiceAccount [%s/%s]", namespaceInstance.Name, config.ServiceAccountName)
	}
	// remove serviceAccount imagePullSecrets for other values or imagePullSecrets exists multi values
	if len(serviceAccountInstance.ImagePullSecrets) > 1 || !includeImagePullSecret(serviceAccountInstance) {
		if serviceAccountInstance.ImagePullSecrets != nil {
			serviceAccountInstance.ImagePullSecrets = nil
			klog.Infof("Delete serviceAccount [%s/%s] imagePullSecrets", namespaceInstance.Name, config.ServiceAccountName)
		}
	}
	if !includeImagePullSecret(serviceAccountInstance) {
		err = r.updateServiceAccount(ctx, serviceAccountInstance, namespaceInstance)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NamespaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Namespace{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Complete(r)
}

func (r *NamespaceReconciler) sync(syncers []syncer.Interface, ns *corev1.Namespace) error {
	for _, s := range syncers {
		if err := syncer.Sync(context.TODO(), s, r.Recorder); err != nil {
			return err
		}
		klog.Infof("Secret [%s/%s] is created", ns.Name, config.ImagePullSecretName)
	}
	return nil
}

// 当namespace配置annotations为kube-credential-helper-namespace-exclude: true时，该namespace将跳过免密拉取secret注入
// 同时当启动kube-credential-helper-namespace时配置excluded-namespaces=xxxx,xxx选项参数时，这些namespace将跳过免密拉取secret注入
func (c *Config) namespaceIsExcluded(namespace *corev1.Namespace) bool {
	v, ok := namespace.Annotations[annotationNamespaceExclude]
	if ok && v == "true" {
		return true
	}
	for _, name := range strings.Split(c.ExcludedNamespace, ",") {
		if name == namespace.Name {
			return true
		}
	}
	return false
}

func (r *NamespaceReconciler) updateSecret(ctx context.Context, secretSyncer []syncer.Interface, secret *corev1.Secret, ns *corev1.Namespace, dataObject string) error {
	listOpts := []client.ListOption{
		client.InNamespace(secret.Namespace),
		client.MatchingLabels(GetInstanceLabels(config.ImagePullSecretName)),
	}
	var secretList corev1.SecretList
	secretName := config.ImagePullSecretName
	err := r.List(ctx, &secretList, listOpts...)
	if err != nil {
		klog.Errorf("Unable to list [%s/%s] secret", secret.Namespace, secretName)
		return err
	}

	switch verifySecret(secret, dataObject) {
	case secretOk:
		klog.V(4).Infof("Secret [%s/%s] is valid", secret.Namespace, secretName)
	case secretWrongType, secretNoKey, secretDataNotMatch, secretLabelsNotMatch:
		klog.Warningf("Secret [%s/%s] is not valid, override now", secret.Namespace, secretName)
		err := r.Client.Delete(ctx, secret)
		if err != nil {
			klog.Errorf("Failed to delete secret: %v", err)
		}
		err = r.Client.Create(ctx, secret)
		if err = r.sync(secretSyncer, ns); err != nil {
			return err
		}
	}
	return err
}

// config.ini files struct
type authInfo struct {
	Url, User, Password string
}

// .dockerconfigjson files struct
type dockerConfig struct {
	Auths map[string]map[string]string `json:"auths"`
}

func (c *Config) parseConfigFiles() (string, error) {
	file, err := ini.LoadFile(c.ConfigPath)
	if err != nil {
		return "", err
	}
	authMap := make(map[string]map[string]string)
	config := &dockerConfig{}
	info := &authInfo{}
	for _, section := range file {
		info.Url = section["url"]
		info.User = section["user"]
		info.Password = section["password"]

		encoder := fmt.Sprintf("%s:%s", strings.Trim(info.User, "\""), strings.Trim(info.Password, "\""))
		authMap[strings.Trim(info.Url, "\"")] = map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(encoder))}
	}
	config.Auths = authMap
	jsonStr, _ := json.MarshalIndent(config, "", "  ")
	return string(jsonStr), nil
}

type verifySecretResult string

func verifySecret(secret *corev1.Secret, dockerConfigJSON string) verifySecretResult {
	if secret.Type != corev1.SecretTypeDockerConfigJson {
		return secretWrongType
	}

	if !reflect.DeepEqual(secret.Labels, GetInstanceLabels(secret.Name)) {
		return secretLabelsNotMatch
	}

	b, ok := secret.Data[corev1.DockerConfigJsonKey]
	if !ok {
		return secretNoKey
	}
	if string(b) != dockerConfigJSON {
		return secretDataNotMatch
	}
	return secretOk
}

func (r *NamespaceReconciler) updateServiceAccount(ctx context.Context, sa *corev1.ServiceAccount, ns *corev1.Namespace) error {
	patch, err := getPatchString(sa)
	if err != nil {
		return err
	}
	patchData := client.RawPatch(types.StrategicMergePatchType, patch)

	err = r.Client.Patch(ctx, sa, patchData)
	if err != nil {
		klog.Errorf("Failed to patch imagePullSecrets to serviceAccount [%s=%s]: %v", ns.Name, config.ServiceAccountName, err)
	}
	klog.Infof("Patched namespace [%s] imagePullSecrets to %s serviceAccount successful.", ns.Name, config.ServiceAccountName)

	return err
}

func includeImagePullSecret(sa *corev1.ServiceAccount) bool {
	for _, imagePullSecret := range sa.ImagePullSecrets {
		if imagePullSecret.Name == config.ImagePullSecretName {
			return true
		}
	}
	return false
}

type patch struct {
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
}

func getPatchString(sa *corev1.ServiceAccount) ([]byte, error) {
	saPatch := patch{
		// copy the slice
		ImagePullSecrets: append([]corev1.LocalObjectReference(nil), sa.ImagePullSecrets...),
	}

	if !includeImagePullSecret(sa) {
		saPatch.ImagePullSecrets = append(saPatch.ImagePullSecrets, corev1.LocalObjectReference{Name: config.ImagePullSecretName})
	}
	return json.Marshal(saPatch)
}
