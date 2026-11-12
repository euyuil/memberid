package dingtalk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func streamTestClient(t *testing.T, handle func(context.Context, *websocket.Conn)) *Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/gateway/connections/open":
			var body struct {
				ClientID      string              `json:"clientId"`
				Secret        string              `json:"clientSecret"`
				UA            string              `json:"ua"`
				Subscriptions []map[string]string `json:"subscriptions"`
				LocalIP       string              `json:"localIp"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || r.Method != "POST" || body.ClientID != "example-client" || body.Secret != "synthetic-secret" || body.UA != "MemberID" || body.LocalIP != "" || len(body.Subscriptions) != 1 || body.Subscriptions[0]["type"] != "EVENT" || body.Subscriptions[0]["topic"] != "*" {
				t.Error("invalid gateway contract")
				w.WriteHeader(400)
				return
			}
			_, _ = io.WriteString(w, `{"endpoint":"wss://wss-open-connection.dingtalk.com:443/connect","ticket":"synthetic+/ticket"}`)
		case "/connect":
			if r.URL.Query().Get("ticket") != "synthetic+/ticket" {
				t.Error("ticket was not encoded")
				w.WriteHeader(400)
				return
			}
			socket, err := websocket.Accept(w, r, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer socket.CloseNow()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			handle(ctx, socket)
		default:
			t.Error("unexpected provider path")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	client := New()
	transport := server.Client().Transport
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || (r.URL.Hostname() != "api.dingtalk.com" && r.URL.Hostname() != "wss-open-connection.dingtalk.com") {
			t.Error("escaped fixed provider origins")
			return nil, errors.New("invalid test origin")
		}
		copied := r.Clone(r.Context())
		copied.URL.Host = target.Host
		copied.Host = target.Host
		return transport.RoundTrip(copied)
	})
	return client
}

func TestStreamAcknowledgementsAndRedaction(t *testing.T) {
	callbackCalls := 0
	connected := false
	done := make(chan struct{})
	client := streamTestClient(t, func(ctx context.Context, socket *websocket.Conn) {
		defer close(done)
		frames := []struct {
			kind, topic, event, time, data string
			code                           int
			want                           string
		}{
			{kind: "SYSTEM", topic: "ping", data: `{"opaque":"value"}`, code: 200, want: `{"opaque":"value"}`},
			{kind: "EVENT", event: "unrelated_event", data: "ignored", code: 200, want: `{"status":"SUCCESS","message":""}`},
			{kind: "EVENT", event: "user_leave_org", time: "1", data: `{"userId":["employee"]}`, code: 200, want: `{"status":"SUCCESS","message":""}`},
			{kind: "EVENT", event: "user_add_org", time: "2", data: `{"userId":["employee"]}`, code: 500, want: `{"status":"LATER","message":""}`},
			{kind: "EVENT", event: "user_modify_org", time: "invalid", data: `{"userId":["employee"]}`, code: 500, want: `{"status":"LATER","message":""}`},
			{kind: "SYSTEM", topic: "disconnect", code: 200},
		}
		for i, test := range frames {
			id := strconv.Itoa(i)
			frame := streamFrame{Type: test.kind, Headers: map[string]string{"messageId": id, "topic": test.topic, "eventId": "example-event", "eventCorpId": "example-corp", "eventType": test.event, "eventBornTime": test.time}, Data: test.data}
			if err := wsjson.Write(ctx, socket, frame); err != nil {
				t.Error(err)
				return
			}
			var reply streamReply
			if err := wsjson.Read(ctx, socket, &reply); err != nil {
				t.Error(err)
				return
			}
			if reply.Code != test.code || reply.Headers["messageId"] != id || reply.Headers["contentType"] != "application/json" || reply.Message != "ok" || reply.Data != test.want {
				t.Errorf("unexpected acknowledgement: %+v", reply)
			}
		}
		if _, _, err := socket.Read(ctx); err == nil {
			t.Error("disconnect did not close socket")
		}
	})
	err := client.Stream(t.Context(), "example-client", "synthetic-secret", func() { connected = true }, func(_ context.Context, event DirectoryEvent) error {
		callbackCalls++
		if event.ID != "example-event" || event.CorpID != "example-corp" || len(event.UserIDs) != 1 || event.UserIDs[0] != "employee" {
			t.Error("lost event fields")
		}
		if event.Type == "user_add_org" {
			return errors.New("private database and credential diagnostics")
		}
		return nil
	})
	<-done
	if err != ErrUnavailable || !connected || callbackCalls != 2 {
		t.Fatal("stream contract failed", err, callbackCalls)
	}
}

func TestStreamRejectsUntrustedEndpointsAndGatewayErrors(t *testing.T) {
	for _, endpoint := range []string{"http://wss-open-connection.dingtalk.com/connect", "wss://example.invalid/connect", "wss://wss-open-connection.dingtalk.com.evil.invalid/connect", "wss://user@wss-open-connection.dingtalk.com/connect", "wss://wss-open-connection.dingtalk.com:444/connect", "wss://wss-open-connection.dingtalk.com/connect?existing=1", "wss://wss-open-connection.dingtalk.com/connect#fragment", ":"} {
		t.Run(endpoint, func(t *testing.T) {
			client := New()
			calls := 0
			client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				data, _ := json.Marshal(map[string]string{"endpoint": endpoint, "ticket": "synthetic-ticket"})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
			})
			err := client.Stream(t.Context(), "example-client", "synthetic-secret", nil, func(context.Context, DirectoryEvent) error { t.Error("called consumer"); return nil })
			if err != ErrUnavailable || calls != 1 {
				t.Fatal("untrusted endpoint reached", err, calls)
			}
		})
	}
	client := New()
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"code":"unauthorized.client","message":"private diagnostics"}`)), Header: make(http.Header)}, nil
	})
	if err := client.Stream(t.Context(), "example-client", "synthetic-secret", nil, func(context.Context, DirectoryEvent) error { return nil }); err != ErrUnavailable {
		t.Fatal("stream failure falsely proved corporation revocation", err)
	}
}

func TestStreamCancellationAndFrameBounds(t *testing.T) {
	for _, kind := range []string{"cancel", "binary", "oversized", "malformed", "missing message ID"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan struct{})
			client := streamTestClient(t, func(ctx context.Context, socket *websocket.Conn) {
				defer close(done)
				messageType := websocket.MessageText
				data := []byte("not json")
				switch kind {
				case "binary":
					messageType = websocket.MessageBinary
				case "oversized":
					data = []byte(strings.Repeat("x", (512<<10)+1))
				case "missing message ID":
					data = []byte(`{"type":"SYSTEM","headers":{"topic":"ping"}}`)
				case "cancel":
					_, _, _ = socket.Read(ctx)
					return
				}
				_ = socket.Write(ctx, messageType, data)
				_, _, _ = socket.Read(ctx)
			})
			if err := client.Stream(ctx, "example-client", "synthetic-secret", func() {
				if kind == "cancel" {
					cancel()
				}
			}, func(context.Context, DirectoryEvent) error { t.Error("malformed frame reached consumer"); return nil }); err != ErrUnavailable {
				t.Fatal(err)
			}
			<-done
		})
	}
}
