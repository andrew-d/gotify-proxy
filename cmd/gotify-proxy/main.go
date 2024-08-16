package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
)

var (
	addr        = pflag.String("addr", ":3000", "listen address")
	ntfyAddr    = pflag.String("ntfy-addr", "", "address of ntfy to proxy to")
	accessToken = pflag.String("access-token", "", "gotify access token to expect")
	tags        = pflag.StringSlice("tags", nil, "tags to add to all messages")

	ntfyURL *url.URL // parsed from ntfyAddr
)

func main() {
	pflag.Parse()

	if *addr == "" {
		log.Fatal("addr is required")
	}
	if *ntfyAddr == "" {
		log.Fatal("ntfy-addr is required")
	}
	if *accessToken == "" {
		log.Fatal("access-token is required")
	}

	if u, err := url.ParseRequestURI(*ntfyAddr); err == nil {
		ntfyURL = u
	} else {
		log.Fatalf("invalid ntfy address: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "gotify-proxy is running, proxying to: %s\n", ntfyURL)
	})
	mux.HandleFunc("POST /message", proxyHandler)

	srv := &http.Server{
		Handler: mux,
		Addr:    *addr,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()
	defer log.Printf("gotify-proxy finished")

	log.Printf("gotify-proxy is listening on %s", *addr)
	select {
	case err := <-errCh:
		log.Fatalf("error starting server: %v", err)
	case <-ctx.Done():
		log.Printf("shutting down")
	}

	// Try a graceful shutdown then a hard one.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	err := srv.Shutdown(shutdownCtx)
	if err == nil {
		return
	}

	log.Printf("error shutting down gracefully: %v", err)
	if err := srv.Close(); err != nil {
		log.Printf("error during hard shutdown: %v", err)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	topic, ok := checkAuth(w, r)
	if !ok {
		return
	}

	// Verify that the request is a JSON request.
	if r.Header.Get("Content-Type") != "application/json" {
		writeGotifyError(w, http.StatusUnsupportedMediaType, "only application/json is supported")
		return
	}

	// Okay, we have a valid token. Now read the request body and figure
	// out what we're sending.
	var reqBody gotifyCreateMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		writeGotifyError(w, http.StatusUnauthorized, "invalid request body")
		return
	}

	// Decode the 'extras' field to see if this message is markdown or not.
	var markdown bool
	if display, ok := reqBody.Extras["client::display"]; ok {
		if dm, ok := display.(map[string]any); ok {
			markdown = dm["contentType"] == "text/markdown"
		}
	}

	ntfyBody, _ := json.Marshal(ntfyPublishRequest{
		Topic:    topic,
		Message:  reqBody.Message,
		Title:    reqBody.Title,
		Priority: mapGotifyPriority(reqBody.Priority),
		Markdown: markdown,
		Tags:     *tags,
	})

	// Convert the incoming request to a ntfy request.
	ntfyReq, err := http.NewRequestWithContext(r.Context(), "POST", ntfyURL.String(), bytes.NewReader(ntfyBody))
	if err != nil {
		writeGotifyError(w, http.StatusInternalServerError, "error creating ntfy request")
		return
	}
	ntfyReq.Header.Set("Content-Type", "application/json")

	// Make the request to ntfy.
	ntfyResp, err := http.DefaultClient.Do(ntfyReq)
	if err != nil {
		writeGotifyError(w, http.StatusBadGateway, "error sending message to ntfy")
		return
	}
	defer ntfyResp.Body.Close()

	// Decode the ntfy response and return it to the client.
	var ntfyRespBody ntfyPublishResponse
	if err := json.NewDecoder(ntfyResp.Body).Decode(&ntfyRespBody); err != nil {
		writeGotifyError(w, http.StatusInternalServerError, "error decoding ntfy response")
		return
	}

	// Parse the date into a time so that we can format it.
	date := time.Unix(ntfyRespBody.TimeUnix, 0)

	// Make a gotify-compatible response.
	respBody := gotifyCreateMessageResponse{
		// Copy most of the fields from the request.
		Title:    reqBody.Title,
		Message:  reqBody.Message,
		Priority: reqBody.Priority,
		Extras:   reqBody.Extras,

		// But send the real date
		AppID: 1, // TODO
		Date:  date.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		writeGotifyError(w, http.StatusInternalServerError, "error encoding response")
		return
	}

	// All done!
}

// checkAuth will check the request for an access token and return the ntfy
// topic to send to. If it returns ok==false, it has written an error to the
// ResponseWriter already.
func checkAuth(w http.ResponseWriter, r *http.Request) (topic string, ok bool) {
	var token string
	if q := r.URL.Query().Get("token"); q != "" {
		token = q
	} else if key := r.Header.Get("x-gotify-key"); key != "" {
		token = key
	} else if hdr := r.Header.Get("Authorization"); hdr != "" {
		token = strings.TrimPrefix(hdr, "Bearer ")
	}
	if token == "" {
		writeGotifyError(w, http.StatusUnauthorized, "you need to provide a valid access token or user credentials to access this api")
		return "", false
	}

	// We treat the token as both an authentication token and a
	// specification of what ntfy topic to proxy to. Split the token on the
	// first '/', and use the first part as authentication and the second
	// part as the topic.
	auth, topic, ok := strings.Cut(token, "/")
	if !ok {
		writeGotifyError(w, http.StatusUnauthorized, "you need to provide a valid access token or user credentials to access this api")
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(auth), []byte(*accessToken)) == 0 {
		writeGotifyError(w, http.StatusForbidden, "you need to provide a valid access token or user credentials to access this api")
		return "", false
	}

	return topic, true
}

// mapGotifyPriority maps a Gotify priority to an ntfy priority.
//
// TODO(andrew-d): make this configurable?
func mapGotifyPriority(p int) int {
	switch p {
	case 1, 2:
		return 1 // "min"
	case 3, 4:
		return 2 // "low"
	case 5, 6:
		return 3 // "default"
	case 7, 8:
		return 4 // "high"
	case 9, 10:
		return 5 // "max"
	}

	if p > 10 {
		return 5 // "max"
	}
	return 3 // "default"
}

func writeGotifyError(w http.ResponseWriter, code int, msg string) {
	errResp := gotifyErrorResponse{
		Error:            http.StatusText(code),
		ErrorCode:        code,
		ErrorDescription: msg,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(errResp)
}

// gotifyCreateMessageRequest is the request body for creating a message that
// matches the Gotify API.
type gotifyCreateMessageRequest struct {
	Title    string         `json:"title"`
	Message  string         `json:"message"`
	Priority int            `json:"priority"`
	Extras   map[string]any `json:"extras"`
}

// gotifyCreateMessageResponse is the response body for creating a message that
// matches the Gotify API.
type gotifyCreateMessageResponse struct {
	Title    string         `json:"title"`
	Message  string         `json:"message"`
	Priority int            `json:"priority"`
	Extras   map[string]any `json:"extras"`

	AppID int    `json:"appid"`
	Date  string `json:"date"`
}

// gotifyErrorResponse is the response body for an error response from Gotify.
type gotifyErrorResponse struct {
	Error            string `json:"error"`
	ErrorCode        int    `json:"errorCode"`
	ErrorDescription string `json:"errorDescription"`
}

// ntfyPublishRequest is the request body for publishing a message to ntfy.
type ntfyPublishRequest struct {
	Topic     string   `json:"topic"`
	Message   string   `json:"message,omitempty"`
	Title     string   `json:"title,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Priority  int      `json:"priority,omitempty"`
	ClickURL  string   `json:"click,omitempty"`
	AttachURL string   `json:"attach,omitempty"`
	Filename  string   `json:"filename,omitempty"`
	IconURL   string   `json:"icon,omitempty"`
	Markdown  bool     `json:"markdown,omitempty"`
	Delay     string   `json:"delay,omitempty"`

	//TODO: Actions
}

// ntfyPublishResponse is the response body from publishing a message to ntfy;
// this isn't complete, since we only need a few fields and otherwise respond
// with what the client sent.
type ntfyPublishResponse struct {
	ID          string `json:"id"`
	TimeUnix    int64  `json:"time"`
	ExpiresUnix int64  `json:"expires"`
	Event       string `json:"event"`
	Topic       string `json:"topic"`
}
