import 'server-only';
import { getAuthorizer } from '../auth';
import { supabaseIdentityDirectory } from '../services/identity';
import type { ApiDeps } from './v1';

export const apiDeps = (): ApiDeps => ({
  authorizer: getAuthorizer(),
  identity: supabaseIdentityDirectory(),
});
