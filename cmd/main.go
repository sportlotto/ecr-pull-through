package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	v1beta1 "k8s.io/api/admission/v1beta1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ECR Pull-through webhook %q", html.EscapeString(r.URL.Path))
}

var config *Config

// sanitizeForLog removes potentially dangerous characters from log messages
// to prevent log injection attacks
func sanitizeForLog(input string) string {
	// Remove control characters and newlines that could be used for log injection
	re := regexp.MustCompile(`[\x00-\x1F\x7F]`)
	sanitized := re.ReplaceAllString(input, "")
	// Limit length to prevent log flooding
	if len(sanitized) > 100 {
		sanitized = sanitized[:100] + "..."
	}
	return sanitized
}

func handleMutate(w http.ResponseWriter, r *http.Request) {

	// read the body / request
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
	}

	// mutate the request
	mutated, err := actuallyMutate(body)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
	}

	// and write it back
	w.WriteHeader(http.StatusOK)
	w.Write(mutated)
}

// Helper function to process Docker Hub official images
func isDockerHubOfficialImage(image string) bool {
	// Handle both "nginx" and "docker.io/nginx" format
	if !strings.Contains(image, "/") {
		return true
	}
	// Handle "docker.io/library/nginx" or "docker.io/nginx" format
	parts := strings.Split(image, "/")
	return len(parts) <= 3 && parts[0] == "docker.io" && (len(parts) == 2 || parts[1] == "library")
}

func actuallyMutate(body []byte) ([]byte, error) {
	// unmarshal request into AdmissionReview struct
	admReview := v1beta1.AdmissionReview{}
	if err := json.Unmarshal(body, &admReview); err != nil {
		return nil, fmt.Errorf("unmarshaling request failed with %s", err)
	}

	var err error

	responseBody := []byte{}
	ar := admReview.Request
	resp := v1beta1.AdmissionResponse{}

	if ar != nil {

		// set response options
		resp.Allowed = true
		resp.UID = ar.UID
		pT := v1beta1.PatchTypeJSONPatch
		resp.PatchType = &pT

		// the actual mutation is done by a string in JSONPatch style, i.e. we don't _actually_ modify the object, but
		// tell K8S how it should modifiy it
		p := []map[string]string{}

		// Determine resource type and extract pod template
		var podSpec *corev1.PodSpec
		var resourceName string
		var resourceNamespace string
		var pathPrefix string

		switch ar.Kind.Kind {
		case "Pod":
			var pod corev1.Pod
			if err := json.Unmarshal(ar.Object.Raw, &pod); err != nil {
				return nil, fmt.Errorf("unable unmarshal pod json object %v", err)
			}
			podSpec = &pod.Spec
			resourceName = pod.ObjectMeta.GenerateName
			resourceNamespace = pod.Namespace
			pathPrefix = "/spec"
			log.Printf("Received request to mutate pod %s:%s", sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName))

		case "Job":
			var job batchv1.Job
			if err := json.Unmarshal(ar.Object.Raw, &job); err != nil {
				return nil, fmt.Errorf("unable unmarshal job json object %v", err)
			}
			podSpec = &job.Spec.Template.Spec
			resourceName = job.ObjectMeta.Name
			resourceNamespace = job.Namespace
			pathPrefix = "/spec/template/spec"
			log.Printf("Received request to mutate job %s:%s", sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName))

		case "CronJob":
			var cronJob batchv1.CronJob
			if err := json.Unmarshal(ar.Object.Raw, &cronJob); err != nil {
				return nil, fmt.Errorf("unable unmarshal cronjob json object %v", err)
			}
			podSpec = &cronJob.Spec.JobTemplate.Spec.Template.Spec
			resourceName = cronJob.ObjectMeta.Name
			resourceNamespace = cronJob.Namespace
			pathPrefix = "/spec/jobTemplate/spec/template/spec"
			log.Printf("Received request to mutate cronjob %s:%s", sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName))

		default:
			return nil, fmt.Errorf("unsupported resource kind: %s", ar.Kind.Kind)
		}

		// Containers
		for i, container := range podSpec.Containers {
			imageReplaced := false
			for _, reg := range config.RegistryList() {
				if strings.HasPrefix(container.Image, reg) {
					newImage := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", config.AwsAccountID, config.AwsRegion, container.Image)
					patch := map[string]string{
						"op":    "replace",
						"path":  fmt.Sprintf("%s/containers/%d/image", pathPrefix, i),
						"value": newImage,
					}
					p = append(p, patch)
					imageReplaced = true
					log.Printf("Created patch for container image %s on %s %s:%s, with %s", sanitizeForLog(container.Image), sanitizeForLog(ar.Kind.Kind), sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName), sanitizeForLog(newImage))
					break // Stop checking other registries if a match is found
				}
			}

			// Check if image is a Docker Hub official image
			if !imageReplaced && isDockerHubOfficialImage(container.Image) {
				for _, reg := range config.RegistryList() {
					if reg == "docker.io" {
						newImage := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/docker.io/library/%s", config.AwsAccountID, config.AwsRegion, container.Image)
						patch := map[string]string{
							"op":    "replace",
							"path":  fmt.Sprintf("%s/containers/%d/image", pathPrefix, i),
							"value": newImage,
						}
						p = append(p, patch)
						log.Printf("Created patch for container image %s on %s %s:%s, with %s", sanitizeForLog(container.Image), sanitizeForLog(ar.Kind.Kind), sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName), sanitizeForLog(newImage))
						break
					}
				}
			}
		}
		// InitContainers
		for i, initcontainer := range podSpec.InitContainers {
			imageReplaced := false
			for _, reg := range config.RegistryList() {
				if strings.HasPrefix(initcontainer.Image, reg) {
					newImage := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", config.AwsAccountID, config.AwsRegion, initcontainer.Image)
					patch := map[string]string{
						"op":    "replace",
						"path":  fmt.Sprintf("%s/initContainers/%d/image", pathPrefix, i),
						"value": newImage,
					}
					p = append(p, patch)
					imageReplaced = true
					log.Printf("Created patch for initcontainer image %s on %s %s:%s, with %s", sanitizeForLog(initcontainer.Image), sanitizeForLog(ar.Kind.Kind), sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName), sanitizeForLog(newImage))
					break // Stop checking other registries if a match is found
				}
			}

			// Check if image is a Docker Hub official image
			if !imageReplaced && isDockerHubOfficialImage(initcontainer.Image) {
				for _, reg := range config.RegistryList() {
					if reg == "docker.io" {
						newImage := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/docker.io/library/%s", config.AwsAccountID, config.AwsRegion, initcontainer.Image)
						patch := map[string]string{
							"op":    "replace",
							"path":  fmt.Sprintf("%s/initContainers/%d/image", pathPrefix, i),
							"value": newImage,
						}
						p = append(p, patch)
						log.Printf("Created patch for initcontainer image %s on %s %s:%s, with %s", sanitizeForLog(initcontainer.Image), sanitizeForLog(ar.Kind.Kind), sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName), sanitizeForLog(newImage))
						break
					}
				}
			}
		}
		// EphemeralContainers
		for i, ephemeralcontainer := range podSpec.EphemeralContainers {
			imageReplaced := false
			for _, reg := range config.RegistryList() {
				if strings.HasPrefix(ephemeralcontainer.Image, reg) {
					newImage := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", config.AwsAccountID, config.AwsRegion, ephemeralcontainer.Image)
					patch := map[string]string{
						"op":    "replace",
						"path":  fmt.Sprintf("%s/ephemeralContainers/%d/image", pathPrefix, i),
						"value": newImage,
					}
					p = append(p, patch)
					imageReplaced = true
					log.Printf("Created patch for ephemeralcontainer image %s on %s %s:%s, with %s", sanitizeForLog(ephemeralcontainer.Image), sanitizeForLog(ar.Kind.Kind), sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName), sanitizeForLog(newImage))
					break // Stop checking other registries if a match is found
				}
			}

			// Check if image is a Docker Hub official image
			if !imageReplaced && isDockerHubOfficialImage(ephemeralcontainer.Image) {
				for _, reg := range config.RegistryList() {
					if reg == "docker.io" {
						newImage := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/docker.io/library/%s", config.AwsAccountID, config.AwsRegion, ephemeralcontainer.Image)
						patch := map[string]string{
							"op":    "replace",
							"path":  fmt.Sprintf("%s/ephemeralContainers/%d/image", pathPrefix, i),
							"value": newImage,
						}
						p = append(p, patch)
						log.Printf("Created patch for ephemeralcontainer image %s on %s %s:%s, with %s", sanitizeForLog(ephemeralcontainer.Image), sanitizeForLog(ar.Kind.Kind), sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName), sanitizeForLog(newImage))
						break
					}
				}
			}
		}

		// parse the []map into JSON
		resp.Patch, _ = json.Marshal(p)

		// Success, of course ;)
		resp.Result = &metav1.Status{
			Status: "Success",
		}

		admReview.Response = &resp
		// back into JSON so we can return the finished AdmissionReview w/ Response directly
		// w/o needing to convert things in the http handler
		responseBody, err = json.Marshal(admReview)

		if err != nil {
			return nil, err // untested section
		}
		log.Printf("Successfully mutated %s %s:%s", sanitizeForLog(strings.ToLower(ar.Kind.Kind)), sanitizeForLog(resourceNamespace), sanitizeForLog(resourceName))
	}

	return responseBody, nil
}

func main() {
	var err error
	config, err = ReadConf("/etc/ecr-pull-through/registries.yaml")
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/mutate", handleMutate)

	s := &http.Server{
		Addr:           ":8443",
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1048576
	}

	// Check for TLS certificate and key files
	_, certErr := os.Stat("/etc/webhook/certs/tls.crt")
	_, keyErr := os.Stat("/etc/webhook/certs/tls.key")

	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		log.Println("Starting server without TLS...")
		log.Fatal(s.ListenAndServe())
	} else {
		log.Println("Starting server with TLS...")
		log.Fatal(s.ListenAndServeTLS("/etc/webhook/certs/tls.crt", "/etc/webhook/certs/tls.key"))
	}
}
