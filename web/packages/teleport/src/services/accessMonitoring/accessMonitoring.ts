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

import cfg from 'teleport/config';
import api from 'teleport/services/api';

import {
  AccessMonitoringRule,
  AccessMonitoringRuleListResponse,
} from './types';

export const accessMonitoringService = {
  fetchAccessMonitoringRules(): Promise<AccessMonitoringRule[]> {
    return api
      .get(cfg.getAccessMonitoringRulesUrl())
      .then((resp: AccessMonitoringRuleListResponse) => resp.items || []);
  },

  createAccessMonitoringRule(
    rule: AccessMonitoringRule
  ): Promise<AccessMonitoringRule> {
    return api.post(cfg.getAccessMonitoringRulesUrl(), rule);
  },

  updateAccessMonitoringRule(
    rule: AccessMonitoringRule
  ): Promise<AccessMonitoringRule> {
    return api.put(cfg.getAccessMonitoringRuleUrl(rule.metadata?.name), rule);
  },

  deleteAccessMonitoringRule(name: string): Promise<void> {
    return api.delete(cfg.getAccessMonitoringRuleUrl(name));
  },
};
