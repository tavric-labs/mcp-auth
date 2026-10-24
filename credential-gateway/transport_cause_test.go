package credentialgateway

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTransportCauseNamesTheFailureWithoutTheURL(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close() // nothing listens here now

	client := &http.Client{Timeout: 2 * time.Second}
	_, err = client.Get("http://" + address + "/secret-path?token=abc")
	if err == nil {
		t.Fatal("expected a connection failure")
	}
	cause := transportCause(err)
	if cause != "connect-refused-or-unroutable" {
		t.Fatalf("cause = %q", cause)
	}
	if strings.Contains(cause, address) || strings.Contains(cause, "secret-path") || strings.Contains(cause, "token") {
		t.Fatal("the cause leaked part of the URL")
	}
	if got := transportCause(context.DeadlineExceeded); got != "timeout" {
		t.Fatalf("deadline cause = %q", got)
	}
	if got := transportCause(&net.DNSError{Name: "x.example", Err: "no such host"}); got != "dns" {
		t.Fatalf("dns cause = %q", got)
	}
}
