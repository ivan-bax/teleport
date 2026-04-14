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
import styled from 'styled-components';
import { useParams, useHistory } from 'react-router';

import {
  Alert,
  Box,
  ButtonBorder,
  ButtonPrimary,
  ButtonSecondary,
  Flex,
  Indicator,
  Label,
  Text,
} from 'design';
import Table, { Cell } from 'design/DataTable';
import { displayDateTime } from 'design/datetime';
import {
  renderIdCell,
  renderStatusCell,
  renderUserCell,
  RequestFlags,
} from 'shared/components/AccessRequests/ReviewRequests';
import {
  BlockedByStartTimeButton,
  ButtonPromotedInfo,
  getResourcesOrRolesFromRequest,
} from 'shared/components/AccessRequests/Shared/Shared';
import { requestMatcher } from 'shared/components/AccessRequests/NewRequest/matcher';
import { useAsync, makeEmptyAttempt, Attempt } from 'shared/hooks/useAsync';
import { AccessRequest, canAssumeNow } from 'shared/services/accessRequests';

import cfg from 'teleport/config';
import { useTeleport } from 'teleport';
import {
  fetchAccessRequests,
  fetchAccessRequest,
  deleteAccessRequest as deleteAccessRequestApi,
  reviewAccessRequest,
} from 'teleport/services/accessRequests/accessRequests';
import session from 'teleport/services/websession';

export function AccessRequestsPage() {
  const { requestId } = useParams<{ requestId?: string }>();
  const history = useHistory();

  if (requestId) {
    return (
      <RequestDetailView
        requestId={requestId}
        onBack={() => history.push(cfg.routes.requests.replace(':requestId?', ''))}
      />
    );
  }

  return <RequestListView />;
}

function RequestListView() {
  const ctx = useTeleport();
  const history = useHistory();
  const username = ctx.storeUser.state?.username;
  const accessRequestId = ctx.storeUser.state?.accessRequestId;

  const [fetchAttempt, fetchRequests] = useAsync(fetchAccessRequests);
  const [assumeAttempt, runAssumeRole] = useAsync(
    useCallback(
      async (requestId: string) => {
        await session.renewSession({ requestId });
        window.location.reload();
      },
      []
    )
  );

  useEffect(() => {
    fetchRequests();
  }, []);

  function getFlags(request: AccessRequest): RequestFlags {
    const ownRequest = request.user === username;
    const canAssume = ownRequest && request.state === 'APPROVED';
    const isAssumed = request.id === accessRequestId;
    const isPromoted =
      request.state === 'PROMOTED' && !!request.promotedAccessListTitle;
    const reviewed = request.reviews.find(r => r.author === username);
    const isPendingState = reviewed
      ? reviewed.state === 'PENDING'
      : request.state === 'PENDING';

    return {
      canAssume,
      isAssumed,
      canReview: !ownRequest && isPendingState,
      canDelete: true,
      ownRequest,
      isPromoted,
    };
  }

  return (
    <Layout mx="auto" px={5} pt={3} height="100%">
      {fetchAttempt.status === 'error' && (
        <Alert kind="danger" details={fetchAttempt.statusText}>
          Could not fetch access requests
        </Alert>
      )}
      {assumeAttempt.status === 'error' && (
        <Alert kind="danger" details={assumeAttempt.statusText}>
          Could not assume the role
        </Alert>
      )}
      <Flex justifyContent="end" pb={4}>
        <ButtonPrimary
          ml={2}
          size="small"
          onClick={() => fetchRequests()}
          disabled={fetchAttempt.status === 'processing'}
        >
          Refresh
        </ButtonPrimary>
      </Flex>
      <Table
        data={fetchAttempt.data || []}
        columns={[
          {
            key: 'id',
            headerText: 'Id',
            isSortable: true,
            render: renderIdCell,
          },
          {
            key: 'state',
            headerText: 'Status',
            isSortable: true,
            render: renderStatusCell,
          },
          {
            key: 'user',
            headerText: 'User',
            isSortable: true,
            render: renderUserCell,
          },
          {
            key: 'roles',
            headerText: 'Requested',
            render: request => <RequestedCell request={request} />,
          },
          {
            key: 'resources',
            isNonRender: true,
          },
          {
            key: 'created',
            headerText: 'Created',
            isSortable: true,
            render: ({ createdDuration, created }) => (
              <Cell title={displayDateTime(created)}>{createdDuration}</Cell>
            ),
          },
          {
            key: 'expires',
            headerText: 'Expires',
            isSortable: true,
            render: ({ requestTTLDuration, requestTTL }) => (
              <Cell title={displayDateTime(requestTTL)}>
                {requestTTLDuration}
              </Cell>
            ),
          },
          {
            altKey: 'view-btn',
            render: request =>
              renderActionCell(
                request,
                getFlags(request),
                req => runAssumeRole(req.id),
                assumeAttempt,
                id =>
                  history.push(
                    cfg.routes.requests.replace(':requestId?', id)
                  ),
                () => {}
              ),
          },
        ]}
        emptyText="No Requests Found"
        isSearchable
        pagination={{ pageSize: 20 }}
        initialSort={{ key: 'created', dir: 'DESC' }}
        customSearchMatchers={[requestMatcher]}
      />
    </Layout>
  );
}

function RequestDetailView({
  requestId,
  onBack,
}: {
  requestId: string;
  onBack: () => void;
}) {
  const ctx = useTeleport();
  const username = ctx.storeUser.state?.username;
  const accessRequestId = ctx.storeUser.state?.accessRequestId;

  const [request, setRequest] = useState<AccessRequest | null>(null);
  const [fetchAttempt, setFetchAttempt] =
    useState<Attempt<AccessRequest>>(makeEmptyAttempt);
  const [reviewReason, setReviewReason] = useState('');
  const [reviewAttempt, submitReview] = useAsync(
    useCallback(
      async (state: string, reason: string) => {
        const updated = await reviewAccessRequest(requestId, { state, reason });
        setRequest(updated);
        return updated;
      },
      [requestId]
    )
  );
  const [deleteAttempt, runDelete] = useAsync(
    useCallback(async () => {
      await deleteAccessRequestApi(requestId);
      onBack();
    }, [requestId, onBack])
  );
  const [assumeAttempt, runAssumeRole] = useAsync(
    useCallback(async () => {
      await session.renewSession({ requestId });
      window.location.reload();
    }, [requestId])
  );

  useEffect(() => {
    setFetchAttempt({ status: 'processing', data: null, statusText: '' });
    fetchAccessRequest(requestId).then(
      data => {
        setRequest(data);
        setFetchAttempt({ status: 'success', data, statusText: '' });
      },
      err => {
        setFetchAttempt({
          status: 'error',
          data: null,
          statusText: err?.message || 'Failed to fetch request',
          error: err,
        });
      }
    );
  }, [requestId]);

  function getFlags(): RequestFlags {
    if (!request)
      return {
        canAssume: false,
        isAssumed: false,
        canReview: false,
        canDelete: false,
        ownRequest: false,
        isPromoted: false,
      };
    const ownRequest = request.user === username;
    const canAssume = ownRequest && request.state === 'APPROVED';
    const isAssumed = request.id === accessRequestId;
    const isPromoted =
      request.state === 'PROMOTED' && !!request.promotedAccessListTitle;
    const reviewed = request.reviews.find(r => r.author === username);
    const isPendingState = reviewed
      ? reviewed.state === 'PENDING'
      : request.state === 'PENDING';

    return {
      canAssume,
      isAssumed,
      canReview: !ownRequest && isPendingState,
      canDelete: true,
      ownRequest,
      isPromoted,
    };
  }

  const flags = getFlags();

  if (fetchAttempt.status === '' || fetchAttempt.status === 'processing') {
    return (
      <Box textAlign="center" m={10}>
        <Indicator delay="short" />
      </Box>
    );
  }

  if (fetchAttempt.status === 'error') {
    return (
      <Layout mx="auto" px={5} pt={3}>
        <Alert kind="danger" details={fetchAttempt.statusText}>
          Could not fetch access request
        </Alert>
        <ButtonSecondary onClick={onBack} mt={3}>
          Back to list
        </ButtonSecondary>
      </Layout>
    );
  }

  return (
    <Layout mx="auto" px={5} pt={3}>
      <ButtonSecondary onClick={onBack} mb={3} size="small">
        Back to list
      </ButtonSecondary>

      {reviewAttempt.status === 'error' && (
        <Alert kind="danger" details={reviewAttempt.statusText}>
          Could not submit review
        </Alert>
      )}
      {deleteAttempt.status === 'error' && (
        <Alert kind="danger" details={deleteAttempt.statusText}>
          Could not delete request
        </Alert>
      )}
      {assumeAttempt.status === 'error' && (
        <Alert kind="danger" details={assumeAttempt.statusText}>
          Could not assume roles
        </Alert>
      )}

      <Box
        p={4}
        borderRadius={3}
        css={`
          border: 1px solid ${props => props.theme.colors.spotBackground[1]};
        `}
      >
        <Flex justifyContent="space-between" alignItems="center" mb={4}>
          <Text typography="h4">Access Request</Text>
          <Flex gap={2}>
            {flags.canAssume && canAssumeNow(request.assumeStartTime) && (
              <ButtonPrimary
                size="small"
                onClick={() => runAssumeRole()}
                disabled={
                  flags.isAssumed || assumeAttempt.status === 'processing'
                }
              >
                {flags.isAssumed ? 'Assumed' : 'Assume Roles'}
              </ButtonPrimary>
            )}
            {flags.canDelete && (
              <ButtonBorder
                size="small"
                onClick={() => runDelete()}
                disabled={deleteAttempt.status === 'processing'}
              >
                Delete
              </ButtonBorder>
            )}
          </Flex>
        </Flex>

        <DetailRow label="ID" value={request.id} />
        <DetailRow label="State" value={request.state} />
        <DetailRow label="User" value={request.user} />
        <DetailRow
          label="Roles"
          value={request.roles?.join(', ') || 'None'}
        />
        {request.resources.length > 0 && (
          <DetailRow
            label="Resources"
            value={request.resources
              .map(r => `${r.id.kind}/${r.id.name}`)
              .join(', ')}
          />
        )}
        <DetailRow label="Created" value={request.createdDuration} />
        <DetailRow label="Expires" value={request.expiresDuration} />
        {request.requestReason && (
          <DetailRow label="Reason" value={request.requestReason} />
        )}
        {request.resolveReason && (
          <DetailRow label="Resolve Reason" value={request.resolveReason} />
        )}

        {request.reviews.length > 0 && (
          <Box mt={4}>
            <Text typography="h5" mb={2}>
              Reviews
            </Text>
            {request.reviews.map((review, i) => (
              <Box
                key={i}
                p={2}
                mb={2}
                borderRadius={2}
                css={`
                  background: ${props =>
                    props.theme.colors.spotBackground[0]};
                `}
              >
                <Text bold>{review.author}</Text>
                <Text>
                  {review.state}
                  {review.reason ? ` - ${review.reason}` : ''}
                </Text>
                <Text typography="body3" color="text.muted">
                  {review.createdDuration}
                </Text>
              </Box>
            ))}
          </Box>
        )}

        {flags.canReview && (
          <Box mt={4}>
            <Text typography="h5" mb={2}>
              Submit Review
            </Text>
            <Box mb={2}>
              <textarea
                placeholder="Reason (optional)"
                value={reviewReason}
                onChange={e => setReviewReason(e.target.value)}
                rows={3}
                style={{
                  width: '100%',
                  padding: '8px',
                  borderRadius: '4px',
                  border: '1px solid #555',
                  background: 'transparent',
                  color: 'inherit',
                  resize: 'vertical',
                }}
              />
            </Box>
            <Flex gap={2}>
              <ButtonPrimary
                size="small"
                onClick={() => submitReview('APPROVED', reviewReason)}
                disabled={reviewAttempt.status === 'processing'}
              >
                Approve
              </ButtonPrimary>
              <ButtonBorder
                size="small"
                onClick={() => submitReview('DENIED', reviewReason)}
                disabled={reviewAttempt.status === 'processing'}
              >
                Deny
              </ButtonBorder>
            </Flex>
          </Box>
        )}
      </Box>
    </Layout>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <Flex mb={2} gap={2}>
      <Text bold minWidth="120px">
        {label}:
      </Text>
      <Text>{value}</Text>
    </Flex>
  );
}

const renderActionCell = (
  request: AccessRequest,
  flags: RequestFlags,
  assumeRole: (request: AccessRequest) => void,
  assumeRoleAttempt: Attempt<void>,
  viewRequest: (id: string) => void,
  assumeAccessList: () => void
) => {
  let assumeBtn;
  if (flags.canAssume) {
    if (canAssumeNow(request.assumeStartTime)) {
      assumeBtn = (
        <ButtonPrimary
          size="small"
          disabled={
            flags.isAssumed || assumeRoleAttempt.status === 'processing'
          }
          onClick={() => assumeRole(request)}
          width="108px"
        >
          {flags.isAssumed ? 'Assumed' : 'Assume Roles'}
        </ButtonPrimary>
      );
    } else {
      assumeBtn = (
        <BlockedByStartTimeButton assumeStartTime={request.assumeStartTime} />
      );
    }
  }

  return (
    <Cell align="right" style={{ whiteSpace: 'nowrap' }}>
      <Flex alignItems="center" justifyContent="right" width="184px">
        {assumeBtn}
        {flags.isPromoted && (
          <ButtonPromotedInfo
            request={request}
            ownRequest={flags.ownRequest}
            assumeAccessList={assumeAccessList}
          />
        )}
        <ButtonBorder
          size="small"
          ml={3}
          onClick={() => viewRequest(request.id)}
        >
          View
        </ButtonBorder>
      </Flex>
    </Cell>
  );
};

const RequestedCell = ({ request }: { request: AccessRequest }) => (
  <Cell>
    <Flex gap={1} flexWrap="wrap">
      {getResourcesOrRolesFromRequest(request).map((r, index) => (
        <Label
          kind="secondary"
          key={`${r.title}${index}`}
          title={r.title}
          m={0}
          css={`
            display: flex;
            gap: ${props => props.theme.space[1]}px;
          `}
        >
          <r.Icon size="small" />
          <span
            css={`
              white-space: nowrap;
            `}
          >
            {r.name}
          </span>
        </Label>
      ))}
    </Flex>
  </Cell>
);

const Layout = styled(Box)`
  flex-direction: column;
  display: flex;
  flex: 1;
  max-width: 1248px;

  &::after {
    content: ' ';
    padding-bottom: 24px;
  }
`;
