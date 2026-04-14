/**
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
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

import { makeAccessRequest } from 'shared/services/accessRequests';
import { AccessRequest } from 'shared/services/accessRequests';

import cfg from 'teleport/config';
import api from 'teleport/services/api';

export function fetchAccessRequests(): Promise<AccessRequest[]> {
  return api.get(cfg.getAccessRequestUrl()).then(resp => {
    if (Array.isArray(resp)) {
      return resp.map(makeAccessRequest);
    }
    return [];
  });
}

export function fetchAccessRequest(
  requestId: string
): Promise<AccessRequest> {
  return api.get(cfg.getAccessRequestUrl(requestId)).then(makeAccessRequest);
}

export function createAccessRequest(data: {
  roles?: string[];
  resourceIds?: { kind: string; name: string; clusterName: string; subResourceName?: string }[];
  reason?: string;
  suggestedReviewers?: string[];
  maxDuration?: Date;
  dryRun?: boolean;
}): Promise<AccessRequest> {
  return api.post(cfg.getAccessRequestUrl(), data).then(makeAccessRequest);
}

export function deleteAccessRequest(requestId: string): Promise<void> {
  return api.delete(cfg.getAccessRequestUrl(requestId));
}

export function reviewAccessRequest(
  requestId: string,
  review: {
    state: string;
    reason: string;
    roles?: string[];
    assumeStartTime?: Date;
  }
): Promise<AccessRequest> {
  return api
    .post(cfg.getAccessRequestUrl(requestId) + '/review', review)
    .then(makeAccessRequest);
}
