package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

type operation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

type rule struct {
	Expr *regexp.Regexp
	Repl string
}

var scheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(scheme)

type rulesFlags []rule

func (i *rulesFlags) String() string {
	return "rules"
}

func (i *rulesFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		log.Fatalf("Invalid rule %s", value)
	}
	re, err := regexp.Compile("^" + parts[0] + "$")
	if err != nil {
		log.Fatalf("Invalid rule %s: %s", value, err)
	}
	*i = append(*i, rule{
		Expr: re,
		Repl: parts[1],
	})
	return nil
}

func init() {
	corev1.AddToScheme(scheme)
	admissionregistrationv1beta1.AddToScheme(scheme)
}

var rules rulesFlags

func main() {
	var CertFile string
	var KeyFile string

	flag.StringVar(&CertFile, "tls-cert-file", CertFile, ""+
		"File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated "+
		"after server cert).")
	flag.StringVar(&KeyFile, "tls-key-file", KeyFile, ""+
		"File containing the default x509 private key matching --tls-cert-file.")
	flag.Var(&rules, "rule", "EXPR:REPL rule")
	flag.Parse()

	http.HandleFunc("/", serve)

	httpsServer := &http.Server{
		Addr:      ":443",
		TLSConfig: configTLS(CertFile, KeyFile),
	}
	httpsServer.ListenAndServeTLS("", "")
}

func configTLS(CertFile string, KeyFile string) *tls.Config {
	sCert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{sCert},
	}
}

func serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")

	var reviewResponse *v1beta1.AdmissionResponse

	if contentType != "application/json" {
		log.Printf("contentType=%s, expect application/json", contentType)
		return
	}

	ar := v1beta1.AdmissionReview{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		log.Print(err)
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = admit(ar)
	}

	response := v1beta1.AdmissionReview{}
	if reviewResponse != nil {
		response.Response = reviewResponse
		response.Response.UID = ar.Request.UID
	}
	// reset the Object and OldObject, they are not needed in a response.
	ar.Request.Object = runtime.RawExtension{}
	ar.Request.OldObject = runtime.RawExtension{}

	resp, err := json.Marshal(response)
	if err != nil {
		log.Print(err)
	}
	if _, err := w.Write(resp); err != nil {
		log.Print(err)
	}
}

func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func admit(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if ar.Request.Resource != podResource {
		log.Printf("expected resource to be %s", podResource)
		return nil
	}

	if ar.Request.Operation != "CREATE" {
		log.Printf("expected operation to be %s", "CREATE")
		return nil
	}

	raw := ar.Request.Object.Raw
	pod := corev1.Pod{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
		log.Print(err)
		return toAdmissionResponse(err)
	}

	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	operations := makePatch(&pod)
	if len(operations) != 0 {
		patch, err := json.Marshal(operations)
		if err != nil {
			log.Print(err)
			return toAdmissionResponse(err)
		}

		reviewResponse.Patch = patch
		pt := v1beta1.PatchTypeJSONPatch
		reviewResponse.PatchType = &pt
	}

	return &reviewResponse
}

func makePatch(pod *corev1.Pod) []*operation {
	ops := []*operation{}

	for index, container := range pod.Spec.Containers {
		op := makeContainerOperation(index, &container)
		if op != nil {
			ops = append(ops, op)
		}
	}

	return ops
}

func makeContainerOperation(index int, c *corev1.Container) *operation {
	img := replaceImage(c.Image)
	if img == c.Image {
		return nil
	}

	return &operation{
		Op:    "replace",
		Path:  fmt.Sprint("/spec/containers/", index, "/image"),
		Value: img,
	}
}

func replaceImage(img string) string {
	imgParts := strings.SplitN(img, ":", 2)
	imgName := imgParts[0]

	for _, r := range rules {
		newImgName := r.Expr.ReplaceAllString(imgName, r.Repl)
		if newImgName != imgName {
			return strings.Join(append([]string{newImgName}, imgParts[1:]...), ":")
		}
	}

	return img
}
