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

package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/accessmonitoring"
	"github.com/gravitational/teleport/lib/accessmonitoring/review"
)

// AccessReviewWatcherConfig configures the access review watcher.
type AccessReviewWatcherConfig struct {
	// Logger is the logger.
	Logger *slog.Logger
	// Events is used to subscribe to events.
	Events types.Events
	// ReviewClient is the client used by the review handler.
	ReviewClient review.Client
}

// StartAccessReviewWatcher starts a background goroutine that watches for
// access request and access monitoring rule events, and automatically reviews
// access requests based on matching rules.
func StartAccessReviewWatcher(ctx context.Context, cfg AccessReviewWatcherConfig) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	handler, err := review.NewHandler(review.Config{
		Logger:      cfg.Logger,
		HandlerName: "builtin",
		Client:      cfg.ReviewClient,
		Cache:       accessmonitoring.NewCache(),
	})
	if err != nil {
		return trace.Wrap(err)
	}

	go runAccessReviewWatcher(ctx, cfg.Logger, cfg.Events, handler)
	return nil
}

func runAccessReviewWatcher(ctx context.Context, logger *slog.Logger, events types.Events, handler *review.Handler) {
	for ctx.Err() == nil {
		err := watchAccessReviewEvents(ctx, logger, events, handler)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logger.ErrorContext(ctx, "Access review watcher error, restarting", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func watchAccessReviewEvents(ctx context.Context, logger *slog.Logger, events types.Events, handler *review.Handler) error {
	watcher, err := events.NewWatcher(ctx, types.Watch{
		Kinds: []types.WatchKind{
			{Kind: types.KindAccessRequest},
			{Kind: types.KindAccessMonitoringRule},
		},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	defer watcher.Close()

	// Wait for OpInit.
	select {
	case event := <-watcher.Events():
		if event.Type != types.OpInit {
			return trace.BadParameter("expected init event, got %v", event.Type)
		}
	case <-watcher.Done():
		return trace.Wrap(watcher.Error())
	case <-ctx.Done():
		return nil
	}

	// Initialize the handler's rule cache.
	if err := handler.HandleAccessMonitoringRule(ctx, types.Event{Type: types.OpInit}); err != nil {
		return trace.Wrap(err)
	}

	logger.InfoContext(ctx, "Access review watcher initialized")

	for {
		select {
		case event := <-watcher.Events():
			if event.Resource == nil {
				continue
			}
			var handleErr error
			switch event.Resource.GetKind() {
			case types.KindAccessRequest:
				handleErr = handler.HandleAccessRequest(ctx, event)
			case types.KindAccessMonitoringRule:
				handleErr = handler.HandleAccessMonitoringRule(ctx, event)
			}
			if handleErr != nil {
				logger.WarnContext(ctx, "Failed to handle event",
					"kind", event.Resource.GetKind(),
					"error", handleErr,
				)
			}
		case <-watcher.Done():
			return trace.Wrap(watcher.Error())
		case <-ctx.Done():
			return nil
		}
	}
}
