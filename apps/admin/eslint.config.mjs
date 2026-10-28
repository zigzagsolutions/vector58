import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTs from 'eslint-config-next/typescript';

export default [
  ...nextVitals,
  ...nextTs,
  { ignores: ['.next/**', 'next-env.d.ts'] },
  {
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['pg', '@/server/db'],
              message: 'Database access belongs in src/server services, not UI components.',
              allowImportNames: [],
            },
          ],
        },
      ],
    },
  },
  {
    files: ['src/server/**/*.ts'],
    rules: { 'no-restricted-imports': 'off' },
  },
];
