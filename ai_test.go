package Cx1ClientGo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A stream that stays open and keeps reporting jobRunning:true must be cut off by the overall deadline.
func TestPollSASTAITriage_DeadlineInterruptsOpenStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for {
			fmt.Fprint(w, "data: {\"currentPhase\":\"working\",\"percentage\":10,\"jobRunning\":true}\n\n")
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	start := time.Now()
	phase, err := c.PollSASTAITriageStatusWithTimeout("proj", "sim", 1, 2)
	elapsed := time.Since(start)

	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if phase != "working" {
		t.Errorf("expected last phase to be returned, got %q", phase)
	}
	if elapsed < 2*time.Second || elapsed > 6*time.Second {
		t.Errorf("expected ~2s, took %v", elapsed)
	}
}

// A stream that opens but never sends anything must also be cut off.
func TestPollAIRemediation_DeadlineInterruptsSilentStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	start := time.Now()
	_, err := c.PollAIRemediationStatusWithTimeout("scan", "sast", "res", 1, 1)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("silent stream not interrupted, took %v", time.Since(start))
	}
}

func TestPollAITriage_FinishesNormally(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"currentPhase\":\"a\",\"jobRunning\":true}\n\n")
		fmt.Fprint(w, "data: {\"currentPhase\":\"done\",\"jobRunning\":false}\n\n")
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	phase, err := c.PollSCAAITriageStatusWithTimeout("proj", "res", "pkg", 1, 10)
	if err != nil || phase != "done" {
		t.Fatalf("got %q, %v", phase, err)
	}
}

// If the stream ends early the poll reopens it until the job finishes.
func TestPollAITriage_ReopensEndedStream(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			fmt.Fprint(w, "data: {\"currentPhase\":\"a\",\"jobRunning\":true}\n\n")
			return
		}
		fmt.Fprint(w, "data: {\"currentPhase\":\"done\",\"jobRunning\":false}\n\n")
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	phase, err := c.PollSASTAITriageStatusWithTimeout("proj", "sim", 1, 30)
	if err != nil || phase != "done" || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("got %q, %v, calls=%d", phase, err, atomic.LoadInt32(&calls))
	}
}

func TestPollAITriage_ErrorIsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	_, err := c.PollSASTAITriageStatusWithTimeout("proj", "sim", 1, 30)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected a 400 error, got %v", err)
	}
}

// maxSeconds == 0 keeps the "no limit" meaning and must not time out immediately.
func TestPollAITriage_ZeroMeansNoDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"currentPhase\":\"done\",\"jobRunning\":false}\n\n")
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	if _, err := c.PollSASTAITriageStatusWithTimeout("proj", "sim", 1, 0); err != nil {
		t.Fatal(err)
	}
}

// SCA triage needs both SimilarityID and PackageIdentifier; an empty one would otherwise poll a non-existent job until timeout.
func TestSCAAITriage_RequiresSimilarityIDAndPackageID(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, 0, 0)
	for _, args := range [][2]string{{"", "pkg"}, {"sim", ""}, {"", ""}} {
		if _, err := c.PollSCAAITriageStatusWithTimeout("proj", args[0], args[1], 1, 1); err == nil {
			t.Errorf("poll with similarityId=%q packageId=%q: expected error", args[0], args[1])
		}
		if _, err := c.GetSCAAITriage("scan", "proj", args[0], args[1]); err == nil {
			t.Errorf("get with similarityId=%q packageId=%q: expected error", args[0], args[1])
		}
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("no requests should be sent for invalid input, got %d", n)
	}
}
