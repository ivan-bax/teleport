/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// SAML-OSS fork: tests for access_review_watcher.go, which is fork-added code
// backing automatic review of access requests in OSS. Upstream has no
// equivalent, so there is nothing to fall back on if this regresses.

package auth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessmonitoringrulesv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/accessmonitoringrules/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/accessmonitoring"
	"github.com/gravitational/teleport/lib/accessmonitoring/review"
)

// fakeReviewClient embeds review.Client so it satisfies the full interface while
// only implementing the methods the watcher actually exercises. Any other call
// panics with a nil-pointer dereference, which is the desired signal: the test
// should be updated to cover whatever new call was introduced.
type fakeReviewClient struct {
	review.Client

	mu        sync.Mutex
	listCalls int
	listErr   error
}

func (c *fakeReviewClient) ListAccessMonitoringRulesWithFilter(
	context.Context,
	*accessmonitoringrulesv1.ListAccessMonitoringRulesWithFilterRequest,
) ([]*accessmonitoringrulesv1.AccessMonitoringRule, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listCalls++
	if c.listErr != nil {
		return nil, "", c.listErr
	}
	return nil, "", nil
}

func (c *fakeReviewClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.listCalls
}

// fakeWatcher is a types.Watcher driven directly by the test.
type fakeWatcher struct {
	events chan types.Event
	done   chan struct{}
	err    error

	closeOnce sync.Once
}

func newFakeWatcher() *fakeWatcher {
	return &fakeWatcher{
		events: make(chan types.Event, 8),
		done:   make(chan struct{}),
	}
}

func (w *fakeWatcher) Events() <-chan types.Event { return w.events }
func (w *fakeWatcher) Done() <-chan struct{}      { return w.done }
func (w *fakeWatcher) Error() error               { return w.err }

func (w *fakeWatcher) Close() error {
	w.closeOnce.Do(func() { close(w.done) })
	return nil
}

// failWith terminates the watcher with err, as a real watcher does when its
// backend connection drops.
func (w *fakeWatcher) failWith(err error) {
	w.err = err
	w.Close()
}

// fakeEvents hands out watchers and records how many were requested.
type fakeEvents struct {
	newWatcher func(ctx context.Context, watch types.Watch) (types.Watcher, error)
	calls      atomic.Int32
}

func (e *fakeEvents) NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error) {
	e.calls.Add(1)
	return e.newWatcher(ctx, watch)
}

// testCtx bounds each test. watchAccessReviewEvents blocks in its event loop by
// design, so a regression that skips one of its guard clauses would otherwise
// hang until the CI job's timeout instead of failing fast and legibly. Verified
// by removing the OpInit guard: without a deadline the test hung; with one it
// fails in seconds.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newTestHandler(t *testing.T, client review.Client) *review.Handler {
	t.Helper()
	handler, err := review.NewHandler(review.Config{
		Logger:      slog.New(slog.DiscardHandler),
		HandlerName: "builtin",
		Client:      client,
		Cache:       accessmonitoring.NewCache(),
	})
	require.NoError(t, err)
	return handler
}

func TestStartAccessReviewWatcher(t *testing.T) {
	t.Parallel()

	t.Run("requires a review client", func(t *testing.T) {
		t.Parallel()
		// The handler's own validation rejects a nil client; the watcher must
		// surface that rather than starting a goroutine that cannot work.
		err := StartAccessReviewWatcher(testCtx(t), AccessReviewWatcherConfig{
			Events: &fakeEvents{},
		})
		require.Error(t, err)
		assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
	})

	t.Run("defaults the logger", func(t *testing.T) {
		t.Parallel()
		// A nil Logger must be defaulted rather than panicking once the
		// background goroutine logs.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		watcher := newFakeWatcher()
		t.Cleanup(func() { watcher.Close() })

		err := StartAccessReviewWatcher(ctx, AccessReviewWatcherConfig{
			Logger: nil,
			Events: &fakeEvents{
				newWatcher: func(context.Context, types.Watch) (types.Watcher, error) {
					return watcher, nil
				},
			},
			ReviewClient: &fakeReviewClient{},
		})
		require.NoError(t, err)
	})
}

func TestWatchAccessReviewEvents_watchesBothKinds(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gotWatch types.Watch
	watcher := newFakeWatcher()
	events := &fakeEvents{
		newWatcher: func(_ context.Context, watch types.Watch) (types.Watcher, error) {
			gotWatch = watch
			return watcher, nil
		},
	}

	go func() {
		watcher.events <- types.Event{Type: types.OpInit}
		// Let initialization complete, then unblock the function under test.
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := watchAccessReviewEvents(ctx, slog.New(slog.DiscardHandler), events, newTestHandler(t, &fakeReviewClient{}))
	require.NoError(t, err)

	// Auto-approval needs both: the requests to review, and the rules deciding
	// which to review. Missing either silently disables the feature.
	kinds := make([]string, 0, len(gotWatch.Kinds))
	for _, k := range gotWatch.Kinds {
		kinds = append(kinds, k.Kind)
	}
	assert.ElementsMatch(t, []string{types.KindAccessRequest, types.KindAccessMonitoringRule}, kinds)
}

func TestWatchAccessReviewEvents_requiresInitEvent(t *testing.T) {
	t.Parallel()

	watcher := newFakeWatcher()
	t.Cleanup(func() { watcher.Close() })
	events := &fakeEvents{
		newWatcher: func(context.Context, types.Watch) (types.Watcher, error) {
			return watcher, nil
		},
	}

	// A non-init first event means the watcher is not in a known-good state, so
	// the rule cache would be built from an incomplete view.
	watcher.events <- types.Event{Type: types.OpPut}

	err := watchAccessReviewEvents(testCtx(t), slog.New(slog.DiscardHandler), events, newTestHandler(t, &fakeReviewClient{}))
	require.Error(t, err)
	assert.True(t, trace.IsBadParameter(err), "expected BadParameter, got %v", err)
}

func TestWatchAccessReviewEvents_propagatesWatcherFailures(t *testing.T) {
	t.Parallel()

	t.Run("NewWatcher fails", func(t *testing.T) {
		t.Parallel()
		events := &fakeEvents{
			newWatcher: func(context.Context, types.Watch) (types.Watcher, error) {
				return nil, trace.ConnectionProblem(nil, "backend down")
			},
		}
		err := watchAccessReviewEvents(testCtx(t), slog.New(slog.DiscardHandler), events, newTestHandler(t, &fakeReviewClient{}))
		require.Error(t, err)
		assert.True(t, trace.IsConnectionProblem(err), "expected ConnectionProblem, got %v", err)
	})

	t.Run("watcher closes after init", func(t *testing.T) {
		t.Parallel()
		watcher := newFakeWatcher()
		events := &fakeEvents{
			newWatcher: func(context.Context, types.Watch) (types.Watcher, error) {
				return watcher, nil
			},
		}

		sentinel := errors.New("watcher died")
		go func() {
			watcher.events <- types.Event{Type: types.OpInit}
			time.Sleep(50 * time.Millisecond)
			watcher.failWith(sentinel)
		}()

		err := watchAccessReviewEvents(testCtx(t), slog.New(slog.DiscardHandler), events, newTestHandler(t, &fakeReviewClient{}))
		require.Error(t, err)
		assert.ErrorIs(t, err, sentinel)
	})

	t.Run("rule cache initialization fails", func(t *testing.T) {
		t.Parallel()
		watcher := newFakeWatcher()
		t.Cleanup(func() { watcher.Close() })
		events := &fakeEvents{
			newWatcher: func(context.Context, types.Watch) (types.Watcher, error) {
				return watcher, nil
			},
		}
		watcher.events <- types.Event{Type: types.OpInit}

		// Starting with an unpopulated rule cache would mean silently reviewing
		// nothing, so this must be reported and retried rather than swallowed.
		client := &fakeReviewClient{listErr: trace.ConnectionProblem(nil, "list failed")}
		err := watchAccessReviewEvents(testCtx(t), slog.New(slog.DiscardHandler), events, newTestHandler(t, client))
		require.Error(t, err)
	})
}

func TestWatchAccessReviewEvents_ignoresEventsWithoutResource(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := newFakeWatcher()
	events := &fakeEvents{
		newWatcher: func(context.Context, types.Watch) (types.Watcher, error) {
			return watcher, nil
		},
	}

	client := &fakeReviewClient{}
	go func() {
		watcher.events <- types.Event{Type: types.OpInit}
		// OpDelete events carry no resource; dispatching on GetKind() would
		// dereference nil.
		watcher.events <- types.Event{Type: types.OpDelete}
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	require.NotPanics(t, func() {
		err := watchAccessReviewEvents(ctx, slog.New(slog.DiscardHandler), events, newTestHandler(t, client))
		assert.NoError(t, err)
	})

	// Only the initial cache population should have hit the client.
	assert.Equal(t, 1, client.calls())
}

func TestRunAccessReviewWatcher_stopsOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	events := &fakeEvents{
		newWatcher: func(context.Context, types.Watch) (types.Watcher, error) {
			return nil, trace.ConnectionProblem(nil, "always fails")
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runAccessReviewWatcher(ctx, slog.New(slog.DiscardHandler), events, newTestHandler(t, &fakeReviewClient{}))
	}()

	// The retry loop must not spin: one attempt, then a wait before the next.
	require.Eventually(t, func() bool {
		return events.calls.Load() >= 1
	}, 2*time.Second, 10*time.Millisecond, "watcher never attempted to connect")

	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runAccessReviewWatcher did not return after context cancellation")
	}

	// A tight restart loop would hammer the backend; the 5s backoff means at
	// most a couple of attempts in the window above.
	assert.LessOrEqual(t, events.calls.Load(), int32(2), "retry loop is not backing off")
}
