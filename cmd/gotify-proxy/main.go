package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
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
	verbose     = pflag.Bool("verbose", false, "enable verbose logging")

	ntfyURL *url.URL // parsed from ntfyAddr

	logger = slog.Default()
)

func main() {
	pflag.Parse()

	if *addr == "" {
		fatal("addr is required")
	}
	if *ntfyAddr == "" {
		fatal("ntfy-addr is required")
	}
	if *accessToken == "" {
		fatal("access-token is required")
	}

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if u, err := url.ParseRequestURI(*ntfyAddr); err == nil {
		ntfyURL = u
	} else {
		fatal("invalid ntfy address", slog.String("addr", *ntfyAddr), errAttr(err))
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
	defer logger.Info("gotify-proxy finished")

	logger.Info("gotify-proxy is listening",
		slog.String("addr", srv.Addr),
		slog.String("ntfy_addr", ntfyURL.String()),
	)
	select {
	case err := <-errCh:
		fatal("error starting server", errAttr(err))
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	// Try a graceful shutdown then a hard one.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	err := srv.Shutdown(shutdownCtx)
	if err == nil {
		return
	}

	logger.Error("error shutting down gracefully", errAttr(err))
	if err := srv.Close(); err != nil {
		logger.Error("error during hard shutdown", errAttr(err))
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	topic, ok := checkAuth(w, r)
	if !ok {
		return
	}

	log := logger.With(
		slog.String("topic", topic),
		slog.String("remote_addr", r.RemoteAddr),
	)

	// Verify that the request is a JSON request.
	if r.Header.Get("Content-Type") != "application/json" {
		log.Debug("invalid content type", slog.String("content_type", r.Header.Get("Content-Type")))
		writeGotifyError(w, http.StatusUnsupportedMediaType, "only application/json is supported")
		return
	}

	// Okay, we have a valid token. Now read the request body and figure
	// out what we're sending.
	var reqBody gotifyCreateMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		log.Warn("error decoding request body", errAttr(err))
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
		log.Error("error sending message to ntfy", errAttr(err))
		writeGotifyError(w, http.StatusBadGateway, "error sending message to ntfy")
		return
	}
	defer ntfyResp.Body.Close()

	// Verify that we get a valid response from ntfy.
	if ntfyResp.StatusCode != http.StatusOK {
		log.Warn("ntfy returned an error", slog.Int("status_code", ntfyResp.StatusCode))
		writeGotifyError(w, ntfyResp.StatusCode, "error sending message to ntfy")
		return
	}

	// Decode the ntfy response and return it to the client.
	var ntfyRespBody ntfyPublishResponse
	if err := json.NewDecoder(ntfyResp.Body).Decode(&ntfyRespBody); err != nil {
		log.Error("error decoding ntfy response", errAttr(err))
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
		log.Error("error encoding response", errAttr(err))
		writeGotifyError(w, http.StatusInternalServerError, "error encoding response")
		return
	}

	// All done!
	attrs := []any{
		slog.String("ntfy_id", ntfyRespBody.ID),
		slog.Int("priority", reqBody.Priority),
	}
	if reqBody.Title != "" {
		attrs = append(attrs, slog.String("title", reqBody.Title))
	}
	log.Info("message sent to ntfy", attrs...)
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
		logger.Warn("no Gotify token provided")
		writeGotifyError(w, http.StatusUnauthorized, "you need to provide a valid access token or user credentials to access this api")
		return "", false
	}

	// We treat the token as both an authentication token and a
	// specification of what ntfy topic to proxy to. Split the token on the
	// first '/', and use the first part as authentication and the second
	// part as the topic.
	auth, topic, ok := strings.Cut(token, "/")
	if !ok {
		logger.Warn("invalid Gotify token format; no slash")
		writeGotifyError(w, http.StatusUnauthorized, "you need to provide a valid access token or user credentials to access this api")
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(auth), []byte(*accessToken)) == 0 {
		logger.Warn("invalid Gotify token provided; invalid access token")
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

func fatal(msg string, args ...any) {
	logger.Error("fatal error: "+msg, args...)
	os.Exit(1)
}

func errAttr(err error) slog.Attr {
	if err == nil {
		return slog.String("error", "<nil>")
	}

	return slog.String("error", err.Error())
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
