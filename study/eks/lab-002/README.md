# Setup EKS Monitoring with Metrics + Prometheus

### Open a terminal

1. Deploy the Metrics Server with the following command:

```
$ DOWNLOAD_URL=$(curl -Ls "https://api.github.com/repos/kubernetes-sigs/metrics-server/releases/latest" | jq -r .tarball_url) 
$ DOWNLOAD_VERSION=$(grep -o '[^/v]*$' <<< $DOWNLOAD_URL)
$ kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v$DOWNLOAD_VERSION/components.yaml
```

2. Verify that the metrics-server deployment is running the desired number of pods with the following command.
```
$ kubectl get deployment metrics-server -n kube-system
``` 
**Output**
```
NAME             READY   UP-TO-DATE   AVAILABLE   AGE
metrics-server   1/1     1            1           6m
```

3. To view the raw metrics output, use kubectl with the --raw flag. This command allows you to pass any HTTP path and returns the raw response.
```
$ kubectl get --raw /metrics
```
### Installing HELM
1. Installing HELM through this link (https://helm.sh/docs/intro/install/)

### Deploying Prometheus

1. Configuring Helm repositorie
```
$ helm repo add stable https://kubernetes-charts.storage.googleapis.com
```
2. Creating a Prometheus namespace.
```
$ kubectl create namespace prometheus
```
3. Deploying Prometheus.
```
helm install prometheus stable/prometheus \
    --namespace prometheus \
    --set alertmanager.persistentVolume.storageClass="gp2",server.persistentVolume.storageClass="gp2"
```

*The Prometheus server can be accessed via port 80 on the following DNS name from within your cluster:*
prometheus-server.prometheus.svc.cluster.local


4. Getting the Prometheus server URL by running these commands in the same shell:
```
$ export POD_NAME=$(kubectl get pods --namespace prometheus -l "app=prometheus,component=server" -o jsonpath="{.items[0].metadata.name}")
$ kubectl --namespace prometheus port-forward $POD_NAME 9090
```

**The Prometheus alertmanager can be accessed via port 80 on the following DNS name from within your cluster:**
prometheus-alertmanager.prometheus.svc.cluster.local

5. Get the Alertmanager URL by running these commands in the same shell:
```
$ export POD_NAME=$(kubectl get pods --namespace prometheus -l "app=prometheus,component=alertmanager" -o jsonpath="{.items[0].metadata.name}")
$ kubectl --namespace prometheus port-forward $POD_NAME 9093
```

#################################################################################
######   WARNING: Pod Security Policy has been moved to a global property.  #####
######            use .Values.podSecurityPolicy.enabled with pod-based      #####
######            annotations                                               #####
######            (e.g. .Values.nodeExporter.podSecurityPolicy.annotations) #####
#################################################################################


*The Prometheus PushGateway can be accessed via port 9091 on the following DNS name from within your cluster:*
prometheus-pushgateway.prometheus.svc.cluster.local

**Get the PushGateway URL by running these commands in the same shell:**
```
$ export POD_NAME=$(kubectl get pods --namespace prometheus -l "app=prometheus,component=pushgateway" -o jsonpath="{.items[0].metadata.name}")
$ kubectl --namespace prometheus port-forward $POD_NAME 9091
```
**For more information on running Prometheus, visit:**
[Prometheus](https://prometheus.io/)

3. Verify that all of the pods in the prometheus namespace are in the READY state.
```
$ kubectl get pods -n prometheus
```
4. Use kubectl to port forward the Prometheus console to your local machine.
```
$ kubectl --namespace=prometheus port-forward deploy/prometheus-server 9090
```
5. Point a web browser to localhost:9090 to view the Prometheus console.

6. Choose a metric from the - insert metric at cursor menu, then choose Execute. Choose the Graph tab to show the metric over time. The following image shows container_memory_usage_bytes over time.

image::images/prometheus_console01.png[Prometheus Console]

7. From the top navigation bar, choose Status, then Targets.

image::images/prometheus_console02.png[Prometheus Console]

All of the Kubernetes endpoints that are connected to Prometheus using service discovery are displayed.

### Install Kubernetes Dashboard. Following the documentation below:

https://docs.aws.amazon.com/pt_br/eks/latest/userguide/dashboard-tutorial.html[Install dashboard on Kubernetes] 

## References:

https://docs.aws.amazon.com/pt_br/eks/latest/userguide/metrics-server.html[Install metric-server on Kubernetes]

https://docs.aws.amazon.com/pt_br/eks/latest/userguide/prometheus.html[Install Prometheus on Kubernetes]