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

// AccessMonitoringRule mirrors the JSON shape of the backend
// accessmonitoringrulesv1.AccessMonitoringRule resource. Only the fields the UI
// renders are typed explicitly; the rest are passed through unchanged when
// editing as YAML.
export type AccessMonitoringRule = {
  kind?: string;
  version?: string;
  metadata?: {
    name?: string;
    description?: string;
    [key: string]: unknown;
  };
  spec?: {
    subjects?: string[];
    condition?: string;
    desired_state?: string;
    notification?: {
      name?: string;
      recipients?: string[];
    };
    automatic_review?: {
      integration?: string;
      decision?: string;
    };
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

export type AccessMonitoringRuleListResponse = {
  items: AccessMonitoringRule[];
};
