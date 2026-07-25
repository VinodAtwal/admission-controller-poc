package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"admission-controller/pkg/patch"
	"admission-controller/pkg/scanner"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookServer handles mutating and validating webhook requests.
type WebhookServer struct {
	EnforceBlock bool
}

// NewWebhookServer creates a new WebhookServer initialized with config.
func NewWebhookServer() *WebhookServer {
	enforce := os.Getenv("ENFORCE_SECRETS_BLOCK") == "true"
	return &WebhookServer{
		EnforceBlock: enforce,
	}
}

// HandleMutate handles mutating admission review requests.
func (ws *WebhookServer) HandleMutate(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		log.Println("Empty body in mutate request")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// Verify the content type is JSON
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Printf("invalid Content-Type, expected application/json, got %s", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionReviewReq admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReviewReq); err != nil {
		log.Printf("Could not decode body: %v", err)
		http.Error(w, fmt.Sprintf("could not decode body: %v", err), http.StatusBadRequest)
		return
	}

	if admissionReviewReq.Request == nil {
		log.Println("AdmissionReview Request is nil")
		http.Error(w, "invalid admission review request", http.StatusBadRequest)
		return
	}

	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if admissionReviewReq.Request.Resource != podResource {
		log.Printf("Unsupported resource: %s", admissionReviewReq.Request.Resource.String())
		// For unsupported resources, allow the request without mutation
		ws.sendAllowedResponse(w, &admissionReviewReq)
		return
	}

	// Decode Pod
	var pod corev1.Pod
	if err := json.Unmarshal(admissionReviewReq.Request.Object.Raw, &pod); err != nil {
		log.Printf("Could not unmarshal raw pod object: %v", err)
		http.Error(w, fmt.Sprintf("could not unmarshal pod: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate JSON patch
	patchBytes, err := patch.CreatePatch(pod.Labels)
	if err != nil {
		log.Printf("Could not create patch: %v", err)
		http.Error(w, fmt.Sprintf("could not create patch: %v", err), http.StatusInternalServerError)
		return
	}

	patchType := admissionv1.PatchTypeJSONPatch
	admissionReviewResp := admissionv1.AdmissionReview{
		TypeMeta: admissionReviewReq.TypeMeta,
		Response: &admissionv1.AdmissionResponse{
			UID:       admissionReviewReq.Request.UID,
			Allowed:   true,
			PatchType: &patchType,
			Patch:     patchBytes,
		},
	}

	respBytes, err := json.Marshal(admissionReviewResp)
	if err != nil {
		log.Printf("Could not marshal response: %v", err)
		http.Error(w, fmt.Sprintf("could not marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully mutated pod %s/%s. Injected 'verified-by: va' label.", pod.Namespace, pod.Name)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

// HandleValidate handles validating admission review requests.
func (ws *WebhookServer) HandleValidate(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := io.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		log.Println("Empty body in validate request")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Printf("invalid Content-Type, expected application/json, got %s", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionReviewReq admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReviewReq); err != nil {
		log.Printf("Could not decode body: %v", err)
		http.Error(w, fmt.Sprintf("could not decode body: %v", err), http.StatusBadRequest)
		return
	}

	if admissionReviewReq.Request == nil {
		log.Println("AdmissionReview Request is nil")
		http.Error(w, "invalid admission review request", http.StatusBadRequest)
		return
	}

	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if admissionReviewReq.Request.Resource != podResource {
		log.Printf("Unsupported resource: %s", admissionReviewReq.Request.Resource.String())
		ws.sendAllowedResponse(w, &admissionReviewReq)
		return
	}

	// Decode Pod
	var pod corev1.Pod
	if err := json.Unmarshal(admissionReviewReq.Request.Object.Raw, &pod); err != nil {
		log.Printf("Could not unmarshal raw pod object: %v", err)
		http.Error(w, fmt.Sprintf("could not unmarshal pod: %v", err), http.StatusInternalServerError)
		return
	}

	// 1. Log container details (Images, command, env, etc.)
	ws.logContainerDetails(&pod)

	// 2. Scan containers for secret exposure
	var allFindings []scanner.Finding
	for _, c := range pod.Spec.InitContainers {
		allFindings = append(allFindings, scanner.ScanContainer(c)...)
	}
	for _, c := range pod.Spec.Containers {
		allFindings = append(allFindings, scanner.ScanContainer(c)...)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		// convert EphemeralContainer to Container for scanner
		containerCopy := corev1.Container{
			Name:         c.Name,
			Image:        c.Image,
			Command:      c.Command,
			Args:         c.Args,
			Env:          c.Env,
			EnvFrom:      c.EnvFrom,
			VolumeMounts: c.VolumeMounts,
		}
		allFindings = append(allFindings, scanner.ScanContainer(containerCopy)...)
	}

	admissionReviewResp := admissionv1.AdmissionReview{
		TypeMeta: admissionReviewReq.TypeMeta,
		Response: &admissionv1.AdmissionResponse{
			UID:     admissionReviewReq.Request.UID,
			Allowed: true,
		},
	}

	if len(allFindings) > 0 {
		var findingsMsgs []string
		for _, f := range allFindings {
			msg := fmt.Sprintf("[%s/%s/%s] %s (Value preview: %s)", f.ContainerName, f.Type, f.Name, f.Description, f.ValuePreview)
			findingsMsgs = append(findingsMsgs, msg)
			log.Printf("WARNING: Secret exposure detected in Pod %s/%s - %s", pod.Namespace, pod.Name, msg)
		}

		if ws.EnforceBlock {
			// Reject Pod creation
			admissionReviewResp.Response.Allowed = false
			admissionReviewResp.Response.Result = &metav1.Status{
				Code:    http.StatusForbidden,
				Message: fmt.Sprintf("Pod creation blocked due to secret exposure: %s", strings.Join(findingsMsgs, "; ")),
			}
			log.Printf("BLOCKED creation of Pod %s/%s due to secret exposure.", pod.Namespace, pod.Name)
		} else {
			// Allow Pod creation, but attach warnings
			admissionReviewResp.Response.Warnings = findingsMsgs
			log.Printf("ALLOWED creation of Pod %s/%s, but with %d secret exposure warnings.", pod.Namespace, pod.Name, len(allFindings))
		}
	} else {
		log.Printf("Pod %s/%s passed secret scanning validation.", pod.Namespace, pod.Name)
	}

	respBytes, err := json.Marshal(admissionReviewResp)
	if err != nil {
		log.Printf("Could not marshal response: %v", err)
		http.Error(w, fmt.Sprintf("could not marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

// logContainerDetails prints details of containers in the pod.
func (ws *WebhookServer) logContainerDetails(pod *corev1.Pod) {
	log.Printf("=== Container Details for Pod: %s/%s ===", pod.Namespace, pod.Name)
	
	logContainers := func(containers []corev1.Container, prefix string) {
		for i, c := range containers {
			log.Printf("  [%s #%d] Name: %s", prefix, i+1, c.Name)
			log.Printf("    Image: %s", c.Image)
			if len(c.Command) > 0 {
				log.Printf("    Command: %s", strings.Join(c.Command, " "))
			}
			if len(c.Args) > 0 {
				log.Printf("    Args: %s", strings.Join(c.Args, " "))
			}
			if len(c.Env) > 0 {
				envNames := make([]string, len(c.Env))
				for idx, e := range c.Env {
					envNames[idx] = e.Name
				}
				log.Printf("    Env Vars: %s", strings.Join(envNames, ", "))
			}
			if len(c.Ports) > 0 {
				ports := make([]string, len(c.Ports))
				for idx, p := range c.Ports {
					ports[idx] = fmt.Sprintf("%d/%s", p.ContainerPort, p.Protocol)
				}
				log.Printf("    Ports: %s", strings.Join(ports, ", "))
			}
		}
	}

	logContainers(pod.Spec.InitContainers, "InitContainer")
	logContainers(pod.Spec.Containers, "Container")
	
	for i, c := range pod.Spec.EphemeralContainers {
		log.Printf("  [EphemeralContainer #%d] Name: %s", i+1, c.Name)
		log.Printf("    Image: %s", c.Image)
	}
	log.Printf("====================================================")
}

// sendAllowedResponse generates a clean allow-all admission response.
func (ws *WebhookServer) sendAllowedResponse(w http.ResponseWriter, req *admissionv1.AdmissionReview) {
	admissionReviewResp := admissionv1.AdmissionReview{
		TypeMeta: req.TypeMeta,
		Response: &admissionv1.AdmissionResponse{
			UID:     req.Request.UID,
			Allowed: true,
		},
	}
	respBytes, err := json.Marshal(admissionReviewResp)
	if err != nil {
		log.Printf("Could not marshal response: %v", err)
		http.Error(w, fmt.Sprintf("could not marshal response: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}
