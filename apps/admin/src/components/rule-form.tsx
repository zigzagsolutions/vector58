import { ThreatCategorySchema } from '@bsp/policy-types';
import { addRuleAction } from '@/app/actions/tenant';
import { ActionForm } from './action-form';
import { Field, Input, Select, Textarea } from './ui/form';

/** Shared add-rule form for block rules and allow-list entries. Server normalises and validates. */
export function RuleForm({
  orgId,
  policyId,
  mode,
}: {
  orgId: string;
  policyId?: string;
  mode: 'block' | 'allow';
}) {
  const prefix = mode === 'block' ? 'BLOCK' : 'ALLOW';
  return (
    <ActionForm
      action={addRuleAction.bind(null, orgId)}
      submitLabel={mode === 'block' ? 'Add block rule' : 'Add allow entry'}
    >
      {policyId ? <input type="hidden" name="policyId" value={policyId} /> : null}
      <Field label="Match" htmlFor="ruleType">
        <Select id="ruleType" name="ruleType" defaultValue={`${prefix}_DOMAIN`}>
          <option value={`${prefix}_DOMAIN`}>Domain (includes subdomains)</option>
          <option value={`${prefix}_URL`}>Exact URL</option>
        </Select>
      </Field>
      <Field
        label="Domain or URL"
        htmlFor="value"
        hint="Normalised server-side: lowercase, punycode IDNs, no default ports, trailing dots or fragments."
      >
        <Input
          id="value"
          name="value"
          required
          placeholder={mode === 'block' ? 'phase1-block-test.example' : 'trusted-partner.example'}
        />
      </Field>
      {mode === 'block' ? (
        <Field label="Threat category" htmlFor="category">
          <Select id="category" name="category" defaultValue="custom">
            {ThreatCategorySchema.options.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </Select>
        </Field>
      ) : null}
      <Field label="Priority (0-999, within its precedence band)" htmlFor="priority">
        <Input id="priority" name="priority" type="number" min={0} max={999} defaultValue={100} />
      </Field>
      <Field label="Reason" htmlFor="reason">
        <Textarea id="reason" name="reason" maxLength={500} />
      </Field>
    </ActionForm>
  );
}
