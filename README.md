

# CKS 官方考纲

CKS 官方考纲: [CKS_Curriculum_ v1.19.pdf](./CKS_Curriculum_ v1.19.pdf)

### Cluster Setup - 10%

[Securing a Cluster](https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/) 

- Use Network security policies to restrict cluster level access
  - https://kubernetes.io/docs/concepts/services-networking/network-policies/

- Use CIS benchmark to review the security configuration of Kubernetes components(etcd, kubelet, kubedns, kubeapi)
  - https://www.cisecurity.org/benchmark/kubernetes/)  

- Properly set up Ingress objects with security control
  - https://kubernetes.io/docs/concepts/services-networking/ingress/#tls

- Protect node metadata and endpoints
  - https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access

- Minimize use of, and access to, GUI elements
  - https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/#accessing-the-dashboard-ui

- Verify platform binaries before deploying
  - https://github.com/kubernetes/kubernetes/releases
    - Kubernetes binaries can be verified by their digest **sha512 hash**
      - checking the Kubernetes release page for the specific release
      - checking the change log for the [images and their digests](https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.19.md#downloads-for-v1191)


### Cluster Hardening - 15%

- Restrict access to Kubernetes API

    - https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/

- Use Role-Based Access Controls to minimize exposure

    - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
    - [handy site collects together articles, tools and the official documentation all in one place](https://rbac.dev/)

- Exercise caution in using service accounts e.g. [disable defaults](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server), minimize permissions on newly created ones

    - opt out of automounting API credentials for a service account

      - service account scope

          ```yaml
         apiVersion: v1
         kind: ServiceAccount
         metadata:
         name: build-robot
         automountServiceAccountToken: false
         ```
       - pod scope
           ```yaml
           apiVersion: v1
           kind: Pod
           metadata:
             name: cks-pod
           spec:
             serviceAccountName: default
             automountServiceAccountToken: false
          ```


- Update Kubernetes frequently

  - https://kubernetes.io/docs/reference/setup-tools/kubeadm/kubeadm-upgrade/

### System Hardening - 15%

- Minimize host OS footprint (reduce attack surface)
  - Reduce host attack surface
  - seccomp which stands for secure computing was originally intended as a means of safely running untrusted compute-bound programs.
    - https://kubernetes.io/docs/tutorials/clusters/seccomp/)
  - AppArmor can be configured for any application to reduce its potential host attack surface and provide greater in-depth defense.
    - https://kubernetes.io/docs/tutorials/clusters/apparmor/)
     - PSP pod security policy enforces
          - https://kubernetes.io/docs/concepts/policy/pod-security-policy/
     - apply host updates frequently
     - Install minimal required OS fingerprint  安装所需的最小操作系统
     - Protect access to data with permissions
          - Restirct allowed hostpaths
               - https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems

- Minimize IAM roles
  - Access authentication and authorization
    - https://kubernetes.io/docs/reference/access-authn-authz/authentication/

- Minimize external access to the network
  - not tested, however, the thinking is that all pods can talk to all pods in all name spaces but not to the outside of the cluster!!!

    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: deny-external-egress
    spec:
      podSelector: {}
      policyTypes:
      - Egress
      egress:
        to:
        - namespaceSelector: {}
    ```

- Appropriately use kernel hardening tools such as AppArmor, seccomp
  - AppArmor
    - https://kubernetes.io/docs/tutorials/clusters/apparmor/
  - seccomp
    - https://kubernetes.io/docs/tutorials/clusters/seccomp/

### Minimize Microservice Vulnerabilities - 20%

- Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts
  - Pod Security Policies
    - https://kubernetes.io/docs/concepts/policy/pod-security-policy/
  - Open Policy Agent
    - https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/
  - Security Contexts
    - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

- Manage kubernetes secrets
  - https://kubernetes.io/docs/concepts/configuration/secret/

- Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)
  - container runtime
    - https://kubernetes.io/docs/concepts/containers/runtime-class/ 
  - gvisor, kata containers
    - https://github.com/kubernetes/enhancements/blob/5dcf841b85f49aa8290529f1957ab8bc33f8b855/keps/sig-node/585-runtime-class/README.md#examples

- Implement pod to pod encryption by use of mTLS
  - https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/
  - TODO: Check if service mesh is part of the CKS exam.

### Supply Chain Security - 20%

- Minimize base image footprint
  - Use distroless, UBI minimal, Alpine, or relavent to your app nodejs, python but the minimal build.
  - Do not include uncessary software not required for container during runtime
    - e.g build tools and utilities, troubleshooting and debug binaries.
      - [Learnk8s smaller docker images blog](https://learnk8s.io/blog/smaller-docker-images)
      - [GKE 7 best practices for building containers](https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers)

- Secure your supply chain: whitelist allowed image registries, sign and validate images
  - whitelist allowed image registries
    - https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/#why-do-i-need-admission-controllers

- Use static analysis of user workloads (e.g. kubernetes resources, docker files)
  - https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#7-statically-analyse-yaml

- Scan images for known vulnerabilities
  - https://kubernetes.io/blog/2018/07/18/11-ways-not-to-get-hacked/#10-scan-images-and-run-ids
  - [Aqua security Trivy](https://github.com/aquasecurity/trivy#quick-start)
  - [Anchore command line scans](https://github.com/anchore/anchore-cli#command-line-examples)

### Monitoring, Logging and Runtime Security - 20%


- Perform behavioural analytics of syscall process and file activities at the host and container level to detect malicious activities

  - [Old kubernetes.io URL: install falco on k8s 1.17](https://v1-17.docs.kubernetes.io/docs/tasks/debug-application-cluster/falco/)
- Detect threats within a physical infrastructure, apps, networks, data, users and workloads
- Detect all phases of attack regardless where it occurs and how it spreads

   - Attack Phases
   
      - [Kubernetes attack martix Microsoft blog](https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/)
      - [MITRE attack framwork using sysdig falco](https://sysdig.com/blog/mitre-attck-framework-for-container-runtime-security-with-sysdig-falco/)
      - [CNCF Webinar: Mitigating Kubernetes attacks](https://www.cncf.io/webinars/mitigating-kubernetes-attacks/)

- Perform deep analytical investigation and identification of bad actors within the environment
  - [Monitoring Kubernetes with sysdig](https://kubernetes.io/blog/2015/11/monitoring-kubernetes-with-sysdig/)
  - [CNCF Webinar: Getting started with container runtime security using Falco](https://youtu.be/VEFaGjfjfyc)
- Ensure immutability of containers at runtime
  - https://kubernetes.io/blog/2018/03/principles-of-container-app-design/
- Use Audit Logs to monitor access
  - https://kubernetes.io/docs/tasks/debug-application-cluster/audit/



# Extra helpful material

### Books

1. [Container Security](https://learning.oreilly.com/library/view/container-security/9781492056690/) or view [here](./books/Container Security by Liz Rice)
1. [Learn Kubernetes Security](https://learning.oreilly.com/library/view/learn-kubernetes-security/9781839216503/) or view [here](./books/Learn Kubernetes Security by Pranjal Jumde; Loris Degioanni; Kaizhe Huang)

### Youtube Videos

1. [Google/Ian Lewis: Kubernetes security best practices](https://youtu.be/wqsUfvRyYpw)
1. [Code in Action for the **book Learn Kubernetes Security** playlist](https://www.youtube.com/playlist?list=PLeLcvrwLe1859Rje9gHrD1KEp4y5OXApB)
1. [Kubernetes security concepts and demos](https://youtu.be/VjlvS-qiz_U)
1. [How to Train your Red Team (for Cloud-Native) - Andrew Martin, ControPlane](https://youtu.be/LJrSAPUNHvE)
1. [InGuardians/Jay Beale: Kubernetes Practical attacks and defences](https://youtu.be/LtCx3zZpOfs)\
  - [Webinars](#webinars)
    - [AquaSec webiners collection](https://www.aquasec.com/resources/virtual-container-security-channel/) - Webinars and videos presented by leading industry experts covering Microservices, Container & Serverless security, Kubernetes, DevSecOps, and everything related to the most disruptive area in IT.

### Containers and Kubernetes Security Training

1. [Killer.sh CKS practice exam](https://killer.sh/cks)       &#x27F9; use code **walidshaari** for **20%** discount
1. [Udemy Kubernetes CKS 2020 Complete Course and Simulator](https://www.udemy.com/course/certified-kubernetes-security-specialist/)
1. [Linux Foundation Kubernetes Security essentials LFS 260](https://training.linuxfoundation.org/training/kubernetes-security-essentials-lfs260/)
1. [Linux Academy/ACloudGuru Kubernetes security](https://acloud.guru/learn/7d2c29e7-cdb2-4f44-8744-06332f47040e)
1. [Cloud native security defending containers and kubernetes](https://www.sans.org/event/stay-sharp-blue-team-ops-and-cloud-dec-2020/course/cloud-native-security-defending-containers-kubernetes)
1. [Tutorial: Getting Started With Cloud-Native Security - Liz Rice, Aqua Security & Michael Hausenblas](https://youtu.be/MisS3wSds40)
    - [hands-on tutorial](https://tutorial.kubernetes-security.info/)
1. [K21 academy CKS step by step activity hands-on-lab activity guide](https://k21academy.com/docker-kubernetes/certified-kubernetes-security-specialist-cks-step-by-step-activity-guide-hands-on-lab)
1. [Andrew Martin Attacking and Defending Cloud Native Infrastructure](https://youtu.be/TXems9GPWMs)
1. [Andrew Martin Control Plane Security training](https://control-plane.io/training/)

### Extra Kubernetes security resources
1. [Kubernetes-security.info](https://kubernetes-security.info/) 
1. [Aquasecurity Blogs](https://blog.aquasec.com/)
1. [Control-plane/Andrew Martin @sublimino: 11 ways not to get hacked](https://control-plane.io/posts/11-ways-not-to-get-hacked/)
1. [Securekubernetes](https://securekubernetes.com/)
1. [Simulator: A distributed systems and infrastructure simulator for attacking and debugging Kubernetes](https://github.com/kubernetes-simulator/simulator)

#### CVEs
1. [CNCF Kubernetes Security Anatomy and the Recently Disclosed CVEs (CVE-2020-8555, CVE-2020-8552)](https://youtu.be/Dp1RCYCpyJk)
1. [Kubernetes Vulnerability Puts Clusters at Risk of Takeover (CVE-2020-8558)](https://unit42.paloaltonetworks.com/cve-2020-8558/)

#### Other CKS related repos

1. [Stackrox CKS study guide](https://github.com/stackrox/Kubernetes_Security_Specialist_Study_Guide)
1. [Viktor Vedmich](https://github.com/vedmichv/CKS-Certified-Kubernetes-Security-Specialist) - CKS resources
1. [Abdennour](https://github.com/abdennour/certified-kubernetes-security-specialist) - CKS resources
1. [Ibrahim Jelliti](https://github.com/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist)  - CKS resources
1. [Madhu Akula's Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)  - vulnerable cluster environment to learn and practice Kubernetes security.
1. [Kubernetes Capture the Flag vagrant environment](https://github.com/NodyHub/k8s-ctf-rocks) - was hosted online on http://k8s-ctf.rocks/




> **参考资料：**
>
> [walidshaari](https://github.com/walidshaari)/**[Certified-Kubernetes-Security-Specialist](https://github.com/walidshaari/Certified-Kubernetes-Security-Specialist)**