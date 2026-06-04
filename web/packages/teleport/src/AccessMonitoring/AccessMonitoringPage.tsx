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

import {
  Alert,
  Box,
  ButtonBorder,
  ButtonPrimary,
  ButtonSecondary,
  ButtonWarning,
  Flex,
  Indicator,
  Text,
} from 'design';
import Table, { Cell } from 'design/DataTable';
import Dialog, {
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from 'design/Dialog';
import { useAsync } from 'shared/hooks/useAsync';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import {
  accessMonitoringService,
  AccessMonitoringRule,
} from 'teleport/services/accessMonitoring';
import { yamlService } from 'teleport/services/yaml';
import { YamlSupportedResourceKind } from 'teleport/services/yaml/types';

const DEFAULT_RULE_YAML = `kind: access_monitoring_rule
version: v1
metadata:
  name: my-rule
spec:
  subjects:
    - access_request
  condition: 'access_request.spec.roles.contains("editor")'
  desired_state: reviewed
  automatic_review:
    integration: builtin
    decision: APPROVED
`;

export function AccessMonitoringPage() {
  const [fetchAttempt, fetchRules] = useAsync(
    accessMonitoringService.fetchAccessMonitoringRules
  );

  // editing holds the rule being edited, or 'new' when creating; null when the
  // editor is closed.
  const [editing, setEditing] = useState<AccessMonitoringRule | 'new' | null>(
    null
  );
  const [deleting, setDeleting] = useState<AccessMonitoringRule | null>(null);

  useEffect(() => {
    fetchRules();
  }, []);

  const rules = fetchAttempt.data || [];

  return (
    <FeatureBox>
      <FeatureHeader justifyContent="space-between">
        <FeatureHeaderTitle>Access Monitoring</FeatureHeaderTitle>
        <ButtonPrimary onClick={() => setEditing('new')}>
          New Rule
        </ButtonPrimary>
      </FeatureHeader>

      <Text mb={3} color="text.slightlyMuted">
        Access monitoring rules automate the handling of access requests — for
        example, auto-approving or auto-denying requests that match a condition,
        or routing notifications. Rules are evaluated server-side; create and
        edit them as YAML below.
      </Text>

      {fetchAttempt.status === 'error' && (
        <Alert kind="danger" details={fetchAttempt.statusText}>
          Could not fetch access monitoring rules
        </Alert>
      )}

      {fetchAttempt.status === 'processing' && (
        <Box textAlign="center" m={10}>
          <Indicator />
        </Box>
      )}

      {fetchAttempt.status === 'success' && (
        <Table<AccessMonitoringRule>
          data={rules}
          emptyText="No access monitoring rules found"
          columns={[
            {
              key: 'metadata',
              headerText: 'Name',
              render: rule => <Cell>{rule.metadata?.name}</Cell>,
            },
            {
              altKey: 'subjects',
              headerText: 'Subjects',
              render: rule => (
                <Cell>{(rule.spec?.subjects || []).join(', ')}</Cell>
              ),
            },
            {
              altKey: 'condition',
              headerText: 'Condition',
              render: rule => (
                <Cell>
                  <MonoText>{rule.spec?.condition}</MonoText>
                </Cell>
              ),
            },
            {
              altKey: 'action',
              headerText: 'Action',
              render: rule => <Cell>{describeAction(rule)}</Cell>,
            },
            {
              altKey: 'options',
              headerText: '',
              render: rule => (
                <Cell align="right">
                  <Flex gap={2} justifyContent="flex-end">
                    <ButtonBorder size="small" onClick={() => setEditing(rule)}>
                      Edit
                    </ButtonBorder>
                    <ButtonBorder
                      size="small"
                      onClick={() => setDeleting(rule)}
                    >
                      Delete
                    </ButtonBorder>
                  </Flex>
                </Cell>
              ),
            },
          ]}
        />
      )}

      {editing && (
        <RuleEditorDialog
          rule={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            fetchRules();
          }}
        />
      )}

      {deleting && (
        <DeleteRuleDialog
          rule={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={() => {
            setDeleting(null);
            fetchRules();
          }}
        />
      )}
    </FeatureBox>
  );
}

function describeAction(rule: AccessMonitoringRule): string {
  const review = rule.spec?.automatic_review;
  if (review?.decision) {
    return `Auto-${review.decision.toLowerCase()}`;
  }
  if (rule.spec?.notification) {
    return 'Notify';
  }
  return rule.spec?.desired_state || '—';
}

function RuleEditorDialog({
  rule,
  onClose,
  onSaved,
}: {
  rule: AccessMonitoringRule | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isNew = !rule;
  const [yaml, setYaml] = useState('');

  // When editing an existing rule, render it to YAML for the editor.
  const [loadAttempt, loadYaml] = useAsync(
    useCallback(async () => {
      if (!rule) {
        return DEFAULT_RULE_YAML;
      }
      return yamlService.stringify(YamlSupportedResourceKind.AccessMonitoringRule, {
        resource: rule,
      });
    }, [rule])
  );

  useEffect(() => {
    loadYaml().then(([text]) => {
      if (text !== null) {
        setYaml(text);
      }
    });
  }, []);

  const [saveAttempt, runSave] = useAsync(
    useCallback(async () => {
      const resource = await yamlService.parse<AccessMonitoringRule>(
        YamlSupportedResourceKind.AccessMonitoringRule,
        { yaml }
      );
      if (isNew) {
        return accessMonitoringService.createAccessMonitoringRule(resource);
      }
      return accessMonitoringService.updateAccessMonitoringRule(resource);
    }, [yaml, isNew])
  );

  async function handleSave() {
    const [, err] = await runSave();
    if (!err) {
      onSaved();
    }
  }

  return (
    <Dialog open={true} onClose={onClose} dialogCss={() => ({ width: '700px' })}>
      <DialogHeader>
        <DialogTitle>
          {isNew ? 'New Access Monitoring Rule' : `Edit ${rule.metadata?.name}`}
        </DialogTitle>
      </DialogHeader>
      <DialogContent>
        {saveAttempt.status === 'error' && (
          <Alert kind="danger" mb={3}>
            {saveAttempt.statusText}
          </Alert>
        )}
        {loadAttempt.status === 'error' && (
          <Alert kind="danger" mb={3}>
            {loadAttempt.statusText}
          </Alert>
        )}
        <YamlEditor
          value={yaml}
          onChange={e => setYaml(e.target.value)}
          spellCheck={false}
          rows={20}
        />
      </DialogContent>
      <DialogFooter>
        <ButtonPrimary
          mr={3}
          onClick={handleSave}
          disabled={saveAttempt.status === 'processing' || !yaml.trim()}
        >
          {saveAttempt.status === 'processing' ? 'Saving...' : 'Save'}
        </ButtonPrimary>
        <ButtonSecondary onClick={onClose}>Cancel</ButtonSecondary>
      </DialogFooter>
    </Dialog>
  );
}

function DeleteRuleDialog({
  rule,
  onClose,
  onDeleted,
}: {
  rule: AccessMonitoringRule;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [deleteAttempt, runDelete] = useAsync(
    useCallback(
      () =>
        accessMonitoringService.deleteAccessMonitoringRule(
          rule.metadata?.name || ''
        ),
      [rule]
    )
  );

  async function handleDelete() {
    const [, err] = await runDelete();
    if (!err) {
      onDeleted();
    }
  }

  return (
    <Dialog open={true} onClose={onClose}>
      <DialogHeader>
        <DialogTitle>Delete Access Monitoring Rule?</DialogTitle>
      </DialogHeader>
      <DialogContent>
        {deleteAttempt.status === 'error' && (
          <Alert kind="danger" mb={3}>
            {deleteAttempt.statusText}
          </Alert>
        )}
        <Text>
          Are you sure you want to delete rule{' '}
          <strong>{rule.metadata?.name}</strong>? This cannot be undone.
        </Text>
      </DialogContent>
      <DialogFooter>
        <ButtonWarning
          mr={3}
          onClick={handleDelete}
          disabled={deleteAttempt.status === 'processing'}
        >
          {deleteAttempt.status === 'processing' ? 'Deleting...' : 'Delete'}
        </ButtonWarning>
        <ButtonSecondary onClick={onClose}>Cancel</ButtonSecondary>
      </DialogFooter>
    </Dialog>
  );
}

const MonoText = styled.span`
  font-family: ${p => p.theme.fonts.mono};
  font-size: 12px;
`;

const YamlEditor = styled.textarea`
  width: 100%;
  font-family: ${p => p.theme.fonts.mono};
  font-size: 13px;
  line-height: 1.5;
  padding: ${p => p.theme.space[2]}px;
  border: 1px solid ${p => p.theme.colors.interactive.tonal.neutral[2]};
  border-radius: ${p => p.theme.radii[2]}px;
  background-color: ${p => p.theme.colors.levels.sunken};
  color: ${p => p.theme.colors.text.main};
  resize: vertical;
`;
