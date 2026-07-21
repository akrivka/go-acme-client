package http01

import (
    "io"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestHandler_ServesChallenge(t *testing.T) {
    token := "tok123"
    keyAuthz := "tok123.thumb"

    // prepare globals
    challResources = make(map[string]string)
    validReceived = make(chan bool, 1)
    challResources[token] = keyAuthz

    req := httptest.NewRequest(http.MethodGet, Prefix+token, nil)
    rr := httptest.NewRecorder()

    handler(rr, req)

    res := rr.Result()
    if res.StatusCode != http.StatusOK {
        t.Fatalf("status code = %d, want %d", res.StatusCode, http.StatusOK)
    }
    if got := res.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
        t.Fatalf("content type = %q, want %q", got, "text/plain; charset=utf-8")
    }
    if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
        t.Fatalf("x-content-type-options = %q, want %q", got, "nosniff")
    }
    body, _ := io.ReadAll(res.Body)
    if string(body) != keyAuthz {
        t.Fatalf("body = %s, want %s", string(body), keyAuthz)
    }

    select {
    case <-validReceived:
        // expected
    default:
        t.Fatalf("expected validReceived to receive true")
    }
}

func TestHandler_UnknownToken(t *testing.T) {
    challResources = make(map[string]string) // empty map
    validReceived = make(chan bool, 1)

    req := httptest.NewRequest(http.MethodGet, Prefix+"unknowntoken", nil)
    rr := httptest.NewRecorder()

    handler(rr, req)

    if rr.Result().StatusCode != http.StatusNotFound {
        t.Fatalf("status code = %d, want %d", rr.Result().StatusCode, http.StatusNotFound)
    }
} 