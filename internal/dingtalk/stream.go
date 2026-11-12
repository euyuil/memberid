package dingtalk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

// DirectoryEvent contains only the fields needed for membership evidence.
// Profile diffs and unrelated event payloads are never retained.
type DirectoryEvent struct {
	ID       string
	CorpID   string
	Type     string
	BornTime int64
	UserIDs  []string
}

type streamFrame struct {
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers"`
	Data    string            `json:"data"`
}

type streamReply struct {
	Code    int               `json:"code"`
	Headers map[string]string `json:"headers"`
	Message string            `json:"message"`
	Data    string            `json:"data"`
}

// Stream connects only to the provider's fixed HTTPS and WSS origins. An event
// callback must commit its effects before returning success. Errors are redacted.
func (client *Client) Stream(ctx context.Context, clientID, secret string, connected func(), consume func(context.Context, DirectoryEvent) error) error {
	if !identifier.MatchString(clientID) || !validValue(secret, 4096) || consume == nil {
		return ErrUnavailable
	}
	var connection struct {
		Endpoint string `json:"endpoint"`
		Ticket   string `json:"ticket"`
	}
	body := map[string]any{"clientId": clientID, "clientSecret": secret, "ua": "MemberID", "subscriptions": []map[string]string{{"type": "EVENT", "topic": "*"}}}
	if err := client.request(ctx, http.MethodPost, "https://api.dingtalk.com/v1.0/gateway/connections/open", body, "", false, &connection); err != nil {
		return ErrUnavailable
	}
	endpoint, err := url.Parse(connection.Endpoint)
	if err != nil || endpoint.Scheme != "wss" || endpoint.Hostname() != "wss-open-connection.dingtalk.com" || (endpoint.Port() != "" && endpoint.Port() != "443") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || !validValue(connection.Ticket, 16384) {
		return ErrUnavailable
	}
	endpoint.RawQuery = url.Values{"ticket": {connection.Ticket}}.Encode()
	transport := *client.http
	transport.Timeout = 0 // The connection outlives an individual HTTP request.
	dial, cancel := context.WithTimeout(ctx, 10*time.Second)
	socket, _, err := websocket.Dial(dial, endpoint.String(), &websocket.DialOptions{HTTPClient: &transport, CompressionMode: websocket.CompressionDisabled})
	cancel()
	if err != nil {
		return ErrUnavailable
	}
	defer socket.CloseNow()
	socket.SetReadLimit(512 << 10)
	if connected != nil {
		connected()
	}
	for {
		read, cancel := context.WithTimeout(ctx, 180*time.Second)
		kind, data, err := socket.Read(read)
		cancel()
		if err != nil || kind != websocket.MessageText {
			return ErrUnavailable
		}
		var frame streamFrame
		if json.Unmarshal(data, &frame) != nil || !validValue(frame.Headers["messageId"], 512) {
			return ErrUnavailable
		}
		reply := streamReply{Code: 200, Headers: map[string]string{"contentType": "application/json", "messageId": frame.Headers["messageId"]}, Message: "ok"}
		disconnect := false
		switch frame.Type {
		case "SYSTEM":
			switch frame.Headers["topic"] {
			case "ping":
				reply.Data = frame.Data
			case "disconnect":
				disconnect = true
			default:
				return ErrUnavailable
			}
		case "EVENT":
			reply.Data = `{"status":"SUCCESS","message":""}`
			if supportedDirectoryEvent(frame.Headers["eventType"]) {
				event := DirectoryEvent{ID: frame.Headers["eventId"], CorpID: frame.Headers["eventCorpId"], Type: frame.Headers["eventType"]}
				var payload struct {
					UserIDs []string `json:"userId"`
				}
				event.BornTime, err = strconv.ParseInt(frame.Headers["eventBornTime"], 10, 64)
				if err == nil {
					err = json.Unmarshal([]byte(frame.Data), &payload)
				}
				event.UserIDs = payload.UserIDs
				if err == nil {
					apply, stop := context.WithTimeout(ctx, 10*time.Second)
					err = consume(apply, event)
					stop()
				}
				if err != nil {
					reply.Code = 500
					reply.Data = `{"status":"LATER","message":""}`
				}
			}
		default:
			return ErrUnavailable
		}
		encoded, _ := json.Marshal(reply)
		write, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = socket.Write(write, websocket.MessageText, encoded)
		cancel()
		if err != nil || disconnect {
			return ErrUnavailable
		}
	}
}

func supportedDirectoryEvent(kind string) bool {
	return kind == "user_leave_org" || kind == "user_add_org" || kind == "user_modify_org"
}
