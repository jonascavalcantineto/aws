# ALB Ingress Controller to an Amazon EKS cluster

#### Tag the subnets in your VPC that you want to use for your load balancers so that the ALB Ingress Controller knows that it can use them. For more information, see Subnet tagging requirement. If you deployed your cluster with eksctl, then the tags are already applied.

* All subnets in your VPC should be tagged accordingly so that Kubernetes can discover them.
```
Key                                     Value
kubernetes.io/cluster/<cluster-name>    shared
```
* Public subnets in your VPC should be tagged accordingly so that Kubernetes knows to use only those subnets for external load balancers.
```
Key                     Value
kubernetes.io/role/elb  1
```

* Private subnets must be tagged in the following way so that Kubernetes knows it can use the subnets for internal load balancers. If you use an Amazon EKS AWS CloudFormation template to create your VPC after 03/26/2020, then the subnets created by the template are tagged when they're created. For more information about the Amazon EKS AWS CloudFormation VPC templates, see Creating a VPC for your Amazon EKS cluster.
```
Key	                            Value
kubernetes.io/role/internal-elb 1
```

1. Create an IAM OIDC provider and associate it with your cluster
```
eksctl utils associate-iam-oidc-provider \
    --region <region-code> \
    --cluster <cluster_name> \
    --approve
```

2. Download an IAM policy for the ALB Ingress Controller pod that allows it to make calls to AWS APIs on your behalf.
```
$ curl -o iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-alb-ingress-controller/v1.1.8/docs/examples/iam-policy.json
```
3. Create an IAM policy called ALBIngressControllerIAMPolicy using the policy downloaded in the previous step.
```
$ aws iam create-policy \
    --policy-name ALBIngressControllerIAMPolicy \
    --policy-document file://iam-policy.json
```
**Take note of the policy ARN that is returned.**

4. Create a Kubernetes service account named alb-ingress-controller in the kube-system namespace, a cluster role, and a cluster role binding for the ALB Ingress Controller to use with the following command.
```
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/aws-alb-ingress-controller/v1.1.8/docs/examples/rbac-role.yaml

```

5. Create an IAM role for the ALB Ingress Controller and attach the role to the service account created in the previous step
```
$ eksctl create iamserviceaccount \
    --region <region-code> \
    --name alb-ingress-controller \
    --namespace kube-system \
    --cluster <cluster_name> \
    --attach-policy-arn <example: arn:aws:iam::111122223333:policy/ALBIngressControllerIAMPolicy> \
    --override-existing-serviceaccounts \
    --approve
```

6. Deploy the ALB Ingress Controller with the following command.
```
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/aws-alb-ingress-controller/v1.1.8/docs/examples/alb-ingress-controller.yaml

```
7. Open the ALB Ingress Controller deployment manifest for editing with the following command.
```
$ kubectl edit deployment.apps/alb-ingress-controller -n kube-system
```
7.1. Add a line for the cluster name after the --ingress-class=alb line. If you're running the ALB Ingress Controller on Fargate, then you must also add the lines for the VPC ID, and AWS Region name of your cluster. Once you've added the appropriate lines, save and close the file.
```
spec:
      containers:
      - args:
        - --ingress-class=alb
        - --cluster-name=prod
        # The lines below is if the EKS is running on Fargate
        - --aws-vpc-id=vpc-03468a8157edca5bd
        - --aws-region=region-code
```
8. Confirm that the ALB Ingress Controller is running with the following command.
```
kubectl get pods -n kube-system
```
**Expected output:**
NAME                                      READY   STATUS    RESTARTS   AGE
alb-ingress-controller-55b5bbcb5b-bc8q9   1/1     Running   0          56s

9. Fllowing a configuration example of the ingress manisfast to you set in your project
```
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: <appname>
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
  labels:
    app: <appname>
spec:
  rules:
    - http:
        paths:
          - path: /*
            backend:
              serviceName: <appname_service_name>
              servicePort: 8080
```
**Note**
If your Ingress has not been created after several minutes, run the following command.
```
kubectl logs -n kube-system   deployment.apps/alb-ingress-controller

```