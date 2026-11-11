package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// addrListener reports a different address than the one it listens on, so a
// test can make Serve believe it is exposed without binding a public interface.
type addrListener struct {
	net.Listener
	addr net.Addr
}

func (l addrListener) Addr() net.Addr { return l.addr }

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// httpGet fetches a URL with a short timeout.
func httpGet(t *testing.T, url string) (*http.Response, error) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	return client.Get(url)
}

// waitServing polls the health endpoint until the server answers.
func waitServing(t *testing.T, base string) {
	t.Helper()
	waitFor(t, 5*time.Second, "the server to answer", func() bool {
		resp, err := httpGet(t, base+"/api/health")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

func TestServeLifecycle(t *testing.T) {
	ln := listenLoopback(t)
	parent := t.TempDir()
	var stderr syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, Config{TempDir: parent, Stderr: &stderr, Logger: testLogger()})
	}()

	base := "http://" + ln.Addr().String()
	waitServing(t, base)

	resp, err := httpGet(t, base+"/api/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("health body = %s", body)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 1 {
		t.Errorf("while serving, the temp parent must hold the private directory: %v (%v)", entries, err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v after a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after the context was cancelled")
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Errorf("the private directory must be removed on shutdown: %v (%v)", entries, err)
	}
	if _, err := httpGet(t, base+"/api/health"); err == nil {
		t.Error("the server still answers after shutdown")
	}

	out := stderr.String()
	if !strings.Contains(out, "teardown dashboard: http://"+ln.Addr().String()) {
		t.Errorf("banner missing from %q", out)
	}
	if strings.Contains(out, "WARNING") || strings.Contains(strings.ToLower(out), "unauthenticated") {
		t.Errorf("a loopback server must not print the exposure warning: %q", out)
	}
}

func TestServeWarnsLoudlyWhenExposed(t *testing.T) {
	real := listenLoopback(t)
	exposed := addrListener{Listener: real, addr: &net.TCPAddr{IP: net.IPv4zero, Port: 7777}}
	var stderr syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, exposed, Config{TempDir: t.TempDir(), Stderr: &stderr, Logger: testLogger()})
	}()
	waitServing(t, "http://"+real.Addr().String())
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	out := stderr.String()
	for _, want := range []string{"WARNING", "0.0.0.0:7777", "unauthenticated", "Host-header allow-list is disabled"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning lacks %q:\n%s", want, out)
		}
	}
}

func TestAnnounce(t *testing.T) {
	var local bytes.Buffer
	announce(&local, "127.0.0.1:7777", true)
	if !strings.HasPrefix(local.String(), "teardown dashboard: http://127.0.0.1:7777\n") || strings.Contains(local.String(), "WARNING") {
		t.Errorf("loopback banner = %q", local.String())
	}
	for _, addr := range []string{"0.0.0.0:7777", "[::]:7777", "192.168.1.5:80"} {
		var out bytes.Buffer
		announce(&out, addr, false)
		text := out.String()
		if !strings.Contains(text, "WARNING") || !strings.Contains(text, "unauthenticated") || !strings.Contains(text, addr) {
			t.Errorf("exposed banner for %s = %q", addr, text)
		}
	}
}

func TestServeEndsEventStreamsPromptlyOnShutdown(t *testing.T) {
	ln := listenLoopback(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, Config{TempDir: t.TempDir(), Stderr: io.Discard, Logger: testLogger()})
	}()
	base := "http://" + ln.Addr().String()
	waitServing(t, base)

	resp, err := http.Get(base + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatalf("no first frame: %v", err)
	}

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(shutdownGrace + 5*time.Second):
		t.Fatal("Serve hung")
	}
	if elapsed := time.Since(start); elapsed > shutdownGrace/2 {
		t.Errorf("shutdown took %s: open event streams must not eat the grace period", elapsed)
	}
}

func TestRunListensOnTheConfiguredAddress(t *testing.T) {
	var stderr syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Addr: "127.0.0.1:0", TempDir: t.TempDir(), Stderr: &stderr, Logger: testLogger()})
	}()

	banner := regexp.MustCompile(`teardown dashboard: (http://127\.0\.0\.1:\d+)`)
	var base string
	waitFor(t, 5*time.Second, "the start-up banner", func() bool {
		m := banner.FindStringSubmatch(stderr.String())
		if m == nil {
			return false
		}
		base = m[1]
		return true
	})
	waitServing(t, base)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunFailsWhenTheAddressIsTaken(t *testing.T) {
	taken := listenLoopback(t)
	defer taken.Close()
	err := Run(context.Background(), Config{Addr: taken.Addr().String(), TempDir: t.TempDir(), Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("Run on a busy address = %v, want a listen error", err)
	}
}

func TestServeRejectsBadConfigAndReleasesTheListener(t *testing.T) {
	ln := listenLoopback(t)
	err := Serve(context.Background(), ln, Config{Keep: -1, Stderr: io.Discard})
	if err == nil {
		t.Fatal("expected a configuration error")
	}
	if _, err := ln.Accept(); err == nil {
		t.Error("the listener must be closed when the configuration is rejected")
	}
}

func TestServeReportsListenerFailure(t *testing.T) {
	ln := listenLoopback(t)
	parent := t.TempDir()
	if err := ln.Close(); err != nil { // a dead listener: Serve fails at once
		t.Fatal(err)
	}
	err := Serve(context.Background(), ln, Config{TempDir: parent, Stderr: io.Discard, Logger: testLogger()})
	if err == nil || !strings.Contains(err.Error(), "serve") {
		t.Fatalf("Serve on a closed listener = %v", err)
	}
	if entries, rerr := os.ReadDir(parent); rerr != nil || len(entries) != 0 {
		t.Errorf("the private directory must be removed even on failure: %v (%v)", entries, rerr)
	}
	if errors.Is(err, http.ErrServerClosed) {
		t.Error("a listener failure must not be reported as a clean shutdown")
	}
}

func TestHTTPServerSettings(t *testing.T) {
	srv := newHTTPServer(http.NotFoundHandler(), testLogger())
	if srv.ReadHeaderTimeout != 10*time.Second || srv.IdleTimeout != 60*time.Second || srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("timeouts/limits = %v %v %d", srv.ReadHeaderTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Error("uploads and event streams need no server-wide Read/Write timeouts")
	}
	if srv.ErrorLog == nil {
		t.Error("server errors must go through the structured logger")
	}
}
