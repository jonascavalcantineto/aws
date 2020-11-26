# Deploy EKS on AWS

### The following applications are required to access the AWS infrastrucuture: awscli and aws-iam-authenticator

* Download the *accessKey.csv* file of the AWS administrator on AWS Console portal.

### Install the awscli client

### Requirements:
    - Python > version 2.7 
    - Pip3

1. Use pip to install the AWS CLI.

```
pip3 install awscli --upgrade --user
aws --version
```

### aws-iam-authenticator Instalation

1. To install aws-iam-authenticator on Linux Download the Amazon EKS-vended aws-iam-authenticator binary from Amazon S3:

```
curl -o aws-iam-authenticator https://amazon-eks.s3-us-west-2.amazonaws.com/1.14.6/2019-08-22/bin/linux/amd64/aws-iam-authenticator
```

2. Apply execute permissions to the binary.

```
chmod +x ./aws-iam-authenticator
```

3. Copy the binary to a folder in your $PATH. We recommend creating a $HOME/bin/aws-iam-authenticator and ensuring that $HOME/bin comes first in your $PATH.

* Add $HOME/bin to your PATH environment variable.

```
echo 'export PATH=$PATH:$HOME/bin' >> ~/.bashrc
```

* Test that the aws-iam-authenticator binary works.

```
aws-iam-authenticator help
```

### Configuring your AWS CLI Credentials (Get you accessKey.csv file) - When you type this command, the AWS CLI prompts you for four pieces of information: access key, secret access key, AWS Region, and output format. This information is stored in a profile (a collection of settings) named default. This profile is used unless you specify another one.

```
$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-east-1
Default output format [None]: json
```

### Installing eksctl(a simple command line utility for creating and managing Kubernetes clusters on Amazon EKS)

1. Download and extract the latest release of eksctl with the following command.

```
curl --silent --location "https://github.com/weaveworks/eksctl/releases/download/latest_release/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
```

2. Move the extracted binary to /usr/local/bin.

```
sudo mv /tmp/eksctl /usr/local/bin
```

3. Test that your installation was successful with the following command.

```
eksctl version
```

### Installing and Set Up kubectl

1. Download the latest release with the command:

```
curl -LO https://storage.googleapis.com/kubernetes-release/release/`curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl
```

2. To download a specific version, replace the $(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt) portion of the command with the specific version.

* For example, to download version v1.17.0 on Linux, type:

```
curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.17.0/bin/linux/amd64/kubectl
```

3. Make the kubectl binary executable.

```
chmod +x ./kubectl
```

4. Move the binary in to your PATH.

```
sudo mv ./kubectl /usr/local/bin/kubectl
```

5. Test to ensure the version you installed is up-to-date:

```
kubectl version --client
```

6. Enable kubectl autocompletion

```
Source the completion script in your ~/.bashrc file:
echo 'source <(kubectl completion bash)' >>~/.bashrc
```

7. Add the completion script to the /etc/bash_completion.d directory:

```
kubectl completion bash >/etc/bash_completion.d/kubectl
```

8. If you have an alias for kubectl, you can extend shell completion to work with that alias:

```
echo 'alias k=kubectl' >>~/.bashrc
echo 'complete -F __start_kubectl k' >>~/.bashrc
```

### Creating your cluster with eksctl

```
eksctl create cluster \
--name <cluster_name> \
--version 1.17 \
--region <region-code> \
--nodegroup-name standard-workers \
--node-type <instance_type> \
--nodes 3 \
--nodes-min 1 \
--nodes-max 4 \
--ssh-access \
--ssh-public-key <path>/.ssh/id_rsa.pub \
--managed
```

### Acessing the cluster 
```
aws eks --region <region-code> update-kubeconfig --name <cluster_name>
```


## References

* Creating a new AWS account ( https://portal.aws.amazon.com/billing/signup#/start )
* Create a new Admin user account on IaM ( https://console.aws.amazon.com/iam/home?#/home )
* awscli ( https://docs.aws.amazon.com/pt_br/cli/latest/userguide/install-linux.html )
* aws-iam-authenticator ( https://docs.aws.amazon.com/pt_br/eks/latest/userguide/install-aws-iam-authenticator.html )
* eksctl ( https://docs.aws.amazon.com/pt_br/eks/latest/userguide/getting-started-eksctl.html )
* kubectl ( https://kubernetes.io/docs/tasks/tools/install-kubectl/ )
* helm ( https://helm.sh/docs/intro/install/ )
* Authentication on AWS Services with aws configure command ( https://docs.aws.amazon.com/pt_br/cli/latest/userguide/cli-chap-configure.html )
* Installing the EKS Cluster with eksctl command ( https://docs.aws.amazon.com/pt_br/eks/latest/userguide/create-cluster.html )

