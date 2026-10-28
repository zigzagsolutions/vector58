// Root flat config shared by all TypeScript workspaces. The admin app layers
// Next.js rules on top in apps/admin/eslint.config.mjs.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/build/**',
      '**/coverage/**',
      'services/windows-agent/**',
      '**/*.d.ts',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': 'error',
      'no-restricted-syntax': [
        'error',
        {
          selector: "MemberExpression[property.name='isAdmin']",
          message: 'Use granular permissions from @bsp/auth-permissions instead of an isAdmin flag.',
        },
      ],
    },
  },
);
