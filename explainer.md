# Kubernetes Admission Controller: Architectural Explainer

This document explains the concepts, request lifecycles, and code mechanics behind the Secret Scanner and Label Mutator Admission Controller.

---

## 1. What is an Admission Controller?

In Kubernetes, an **Admission Controller** is a piece of code that intercepts requests to the Kubernetes API server *prior* to persistence of the object, but *after* the request is authenticated and authorized.

```
                  +-------------------------------------------------+
                  |               Kubernetes API Server             |
                  |                                                 |
kubectl apply --->| 1. Authenticate & Authorize                     |
                  | 2. Mutating Webhooks (Alters spec)              | <---> [ /mutate endpoint ]
                  | 3. Schema Validation                            |
                  | 4. Validating Webhooks (Accepts/Denies)         | <---> [ /validate endpoint ]
                  | 5. Persist to etcd                              |
                  +-------------------------------------------------+
```

Webhooks are grouped into two phases:
1. **Mutating Phase**: Allows modifying the object. (e.g., Injecting labels/sidecars).
2. **Validating Phase**: Allows rejecting the object based on custom business logic. (e.g., Blocking plaintext credentials).

---

## 2. Detailed End-to-End Request Flow

When you run `kubectl apply -f deploy/test-pod-unsafe.yaml`, the lifecycle proceeds as follows:

```mermaid
sequenceDiagram
    autonumber
    participant Developer as Developer / kubectl
    participant API as Kubernetes API Server
    participant Webhook as Webhook Server (Go)
    participant Etcd as etcd (Database)

    Developer->>API: kubectl apply (Pod creation request)
    API->>API: Authenticate & Authorize request
    
    %% Mutating Phase
    API->>Webhook: HTTPS POST /mutate (AdmissionReview)
    Note over Webhook: pkg/patch/patch.go:<br/>Generates JSON Patch list<br/>adding label "verified-by: va"
    Webhook-->>API: 200 OK (AdmissionReview Response with Patch)
    API->>API: Apply JSON patch to Pod spec
    
    %% Validating Phase
    API->>API: Perform standard schema validation
    API->>Webhook: HTTPS POST /validate (AdmissionReview)
    Note over Webhook: pkg/webhook/handler.go:<br/>1. Prints container image, ports, cmd<br/>2. Calls scanner.ScanContainer()
    Note over Webhook: pkg/scanner/scanner.go:<br/>Scans env values & args against<br/>regex rules & keyword heuristics
    
    alt Secret detected (EnforceBlock = true)
        Webhook-->>API: 200 OK (AdmissionReview: Allowed = false + Error Status)
        API-->>Developer: Error: Forbidden (Pod blocked)
    else No Secrets detected (or EnforceBlock = false)
        Webhook-->>API: 200 OK (AdmissionReview: Allowed = true)
        API->>Etcd: Write Pod object
        Etcd-->>API: Saved
        API-->>Developer: pod/test-pod-safe created
    end
```

---

## 3. Webhook Technical Specifications

### A. The AdmissionReview Contract
Kubernetes communicates with the webhook server using the `AdmissionReview` API object (defined in `k8s.io/api/admission/v1`).

#### Request Format (Sent by API Server)
The API server serializes the target object (e.g., Pod) into the `request.object.raw` JSON field:
```json
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "request": {
    "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
    "kind": {"group": "", "version": "v1", "kind": "Pod"},
    "resource": {"group": "", "version": "v1", "resource": "pods"},
    "operation": "CREATE",
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": { "name": "test-pod-safe" },
      "spec": { ... }
    }
  }
}
```

---

### B. Mutating Webhook & JSON Patch (`/mutate`)
Mutating admission webhooks return changes in [RFC 6902 JSON Patch](https://datatracker.ietf.org/doc/html/rfc6902) format.

If the incoming Pod has no existing labels (`pod.Labels == nil`), the JSON patch must initialize the `/metadata/labels` map:
```json
[
  {
    "op": "add",
    "path": "/metadata/labels",
    "value": { "verified-by": "va" }
  }
]
```

If labels already exist, the patch adds a key directly:
```json
[
  {
    "op": "add",
    "path": "/metadata/labels/verified-by",
    "value": "va"
  }
]
```

This JSON patch must be base64-encoded and returned inside the response:
```json
{
  "apiVersion": "admission.k8s.io/v1",
  "kind": "AdmissionReview",
  "response": {
    "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
    "allowed": true,
    "patchType": "JSONPatch",
    "patch": "W3sib3AiOiAiYWRkIiwgInBhdGgiOiAiL21ldGFkYXRhL2xhYmVscy92ZXJpZmllZC1ieSIsICJ2YWx1ZSI6ICJ2YSJ9XQ=="
  }
}
```

---

### C. Validating Webhook & Secret Scanner (`/validate`)

#### 1. Container Details Logging
The handler logs structural metadata from the incoming Pod spec:
* Name of each container, init container, and ephemeral container.
* Container images.
* Executable commands and arguments.
* Names of all environment variables (values are omitted in general logs for security).
* Declared port bindings.

#### 2. Secret Scanning Engine
The validating webhook forwards container parameters to the scanner package.
* **Regex-based Rules**: Uses regular expressions to match structural patterns:
  * AWS Access Keys
  * GitHub Personal Access Tokens (PATs)
  * Slack Webhook URLs
  * Private Keys (`-----BEGIN...`)
  * Basic Auth in connection strings (e.g. `postgres://user:pass@host:5432`)
* **Keyword Heuristics**: If any environment variable contains names like `PASSWORD`, `TOKEN`, `KEY` or `SECRET`, the value is inspected. If it's a plaintext value (length > 4, does not start with Kubernetes interpolation prefix `$(`, and is not an empty string), it is flagged.

#### 3. Response Decision
* If findings are detected and `ENFORCE_SECRETS_BLOCK=true`, the webhook returns:
  ```json
  {
    "response": {
      "uid": "...",
      "allowed": false,
      "status": {
        "code": 403,
        "message": "Pod creation blocked due to secret exposure: ..."
      }
    }
  }
  ```
* If findings are detected but `ENFORCE_SECRETS_BLOCK=false`, the webhook returns:
  ```json
  {
    "response": {
      "uid": "...",
      "allowed": true,
      "warnings": [
        "Plaintext Secret warning: ..."
      ]
    }
  }
  ```

---

## 4. Secure TLS Infrastructure

Kubernetes requires all webhook requests to go through HTTPS. This project handles TLS security as follows:

1. **Service DNS SAN**: A certificate must explicitly authorize the DNS address used by the API server. In Kubernetes, services resolve as:
   `secret-scanner-webhook-service.default.svc.cluster.local`
   We configure our server certificates to support these exact Subject Alternative Names (SANs).
2. **Kubernetes Trust Configuration**: Webhook configurations define a `caBundle`. The API server reads this base64-encoded certificate, validating that the webhook certificate is signed by this trusted authority.
3. **Secret Mount**: Certificates are mounted into the webhook pod from a Kubernetes TLS Secret at `/etc/webhook/certs` (configured in `deploy/deployment.yaml`), allowing the Go server to read them during HTTPS handshake.
