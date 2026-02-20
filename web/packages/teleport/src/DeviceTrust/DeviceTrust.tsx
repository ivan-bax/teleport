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

import { useCallback, useEffect, useState } from 'react';

import { Box, Indicator } from 'design';
import { Danger } from 'design/Alert';

import { FeatureBox } from 'teleport/components/Layout';
import { fetchDevices } from 'teleport/services/devices';

import { DeviceList } from './DeviceList';
import { EmptyList } from './EmptyList';
import { TrustedDevice } from './types';

export function DeviceTrust() {
  const [devices, setDevices] = useState<TrustedDevice[]>([]);
  const [startKey, setStartKey] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetch = useCallback(async () => {
    try {
      const resp = await fetchDevices({ startKey });
      setDevices(prev => [...prev, ...resp.items]);
      setStartKey(resp.startKey);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [startKey]);

  useEffect(() => {
    fetch();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchMore = useCallback(() => {
    if (startKey) {
      fetch();
    }
  }, [startKey, fetch]);

  if (loading && devices.length === 0) {
    return (
      <FeatureBox>
        <Box textAlign="center" m={10}>
          <Indicator />
        </Box>
      </FeatureBox>
    );
  }

  if (error) {
    return (
      <FeatureBox>
        <Danger>{error}</Danger>
      </FeatureBox>
    );
  }

  if (devices.length === 0) {
    return (
      <FeatureBox>
        <Box>
          <EmptyList isEnterprise={true} />
        </Box>
      </FeatureBox>
    );
  }

  return (
    <FeatureBox>
      <DeviceList
        items={devices}
        fetchData={startKey ? fetchMore : undefined}
        fetchStatus={startKey ? '' : 'disabled'}
      />
    </FeatureBox>
  );
}
