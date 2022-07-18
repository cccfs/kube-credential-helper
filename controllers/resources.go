package controllers

import (
	"github.com/presslabs/controller-util/pkg/syncer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewSecretSyncer(cli client.Client, ns *corev1.Namespace, dataObject string) syncer.Interface {
	secret := &corev1.Secret{
		Type: corev1.SecretTypeDockerConfigJson,
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.ImagePullSecretName,
			Namespace: ns.Name,
			Labels: map[string]string{
				labelsName:      config.ImagePullSecretName,
				labelsCreatedBy: filepath.Base(os.Args[0]),
			},
		},
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: []byte(dataObject),
		},
	}
	return syncer.NewObjectSyncer("Secret", ns, secret, cli, func() error {
		return nil
	})
}
