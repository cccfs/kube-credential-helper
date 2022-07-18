package controllers

const (
	annotationNamespaceExclude string = "kube-credential-helper-namespace-exclude"
	labelsCreatedBy            string = "app.kubernetes.io/created-by"
	labelsName                 string = "app.kubernetes.io/name"
	// result code for verifySecret
	secretOk             verifySecretResult = "SecretOk"
	secretWrongType      verifySecretResult = "SecretWrongType"
	secretNoKey          verifySecretResult = "SecretNoKey"
	secretDataNotMatch   verifySecretResult = "SecretDataNotMatch"
	secretLabelsNotMatch verifySecretResult = "SecretLabelsNotMatch"
)
