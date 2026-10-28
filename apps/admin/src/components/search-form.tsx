import { Input, Select } from './ui/form';
import { Button } from './ui/button';

export interface FilterField {
  readonly name: string;
  readonly label: string;
  readonly type?: 'text' | 'select';
  readonly options?: readonly { value: string; label: string }[];
  readonly placeholder?: string;
}

/** Plain GET form: filters live in the URL, results are filtered server-side under RLS. */
export function SearchForm({ fields, values }: { fields: readonly FilterField[]; values: Record<string, string | undefined> }) {
  return (
    <form method="get" className="flex flex-wrap items-end gap-2 border-b border-border p-3">
      {fields.map((f) => (
        <div key={f.name} className="min-w-36">
          <label htmlFor={`f-${f.name}`} className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted">{f.label}</label>
          {f.type === 'select' ? (
            <Select id={`f-${f.name}`} name={f.name} defaultValue={values[f.name] ?? ''} className="h-8">
              <option value="">Any</option>
              {f.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </Select>
          ) : (
            <Input id={`f-${f.name}`} name={f.name} defaultValue={values[f.name] ?? ''} placeholder={f.placeholder} className="h-8" />
          )}
        </div>
      ))}
      <Button size="sm" type="submit">Apply</Button>
    </form>
  );
}
