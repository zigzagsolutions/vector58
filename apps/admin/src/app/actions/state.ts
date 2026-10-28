export interface ActionState {
  readonly ok: boolean;
  readonly message?: string;
  readonly error?: string;
  readonly data?: Record<string, unknown>;
}
export const initialActionState: ActionState = { ok: false };
