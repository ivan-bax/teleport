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
import {
  TrustedDevice,
  TrustedDeviceOSType,
  TrustedDeviceResponse,
} from 'teleport/DeviceTrust/types';
import api from 'teleport/services/api';

export async function fetchDevices(params?: {
  limit?: number;
  startKey?: string;
}): Promise<TrustedDeviceResponse> {
  const resp = await api.get(cfg.getTrustedDevicesUrl(params));
  return {
    items: (resp.items || []).map(makeDevice),
    startKey: resp.startKey || '',
  };
}

function makeDevice(json: any): TrustedDevice {
  return {
    id: json.id || '',
    assetTag: json.assetTag || '',
    osType: (json.osType as TrustedDeviceOSType) || 'Linux',
    enrollStatus: json.enrollStatus === 'enrolled' ? 'enrolled' : 'not enrolled',
    owner: json.owner || '',
  };
}
