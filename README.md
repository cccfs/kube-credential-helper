### kube-credential-helper

### 组件介绍
kube-credential-helper通过自定义配置私有镜像仓库信息实现免密拉取镜像



### 参数选项

| 参数                   | 环境变量               |                   | 描述                                     |
| ---------------------- | ---------------------- | ----------------- | ---------------------------------------- |
| config-path            | CONFIG_PATH            | config.ini        | 配置文件名与路径                         |
| excluded-namespace     | EXCLUDED_NAMESPACE     | kube-system       | 排除的Namespace                          |
| image-pull-secret-name | IMAGE_PULL_SECRET_NAME | image-pull-secret | 创建类型为dockerconfigjson的Secret名称   |
| service-account-name   | SERVICE_ACCOUNT_NAME   | default           | 追加imagePullSecrets字段服务账号默认名称 |



### 使用说明

- 配置文件示例

  ```
  [docker]
  url = hub.docker.com
  user = admin
  password = xxxxx
  
  [harbor]
  url = hub.harbor.com
  user = admin
  password = xxxxx
  ```

  

### 功能介绍

- 支持多镜像仓库源
- 支持Docker、Containerd容器运行时