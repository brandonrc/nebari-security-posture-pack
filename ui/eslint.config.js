import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist', 'dist-mock', 'node_modules', 'public/mockServiceWorker.js', 'screenshots', 'coverage', 'playwright-report', 'test-results'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: { ecmaVersion: 2022, globals: globals.browser },
    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', destructuredArrayIgnorePattern: '^_', ignoreRestSiblings: true },
      ],
    },
  },
  {
    // Vendored Nebari registry sources are upstream-managed; don't lint-police them.
    files: ['src/components/ui/**', 'src/hooks/**', 'src/lib/utils.ts'],
    rules: { 'react-refresh/only-export-components': 'off', 'react-hooks/refs': 'off', 'react-hooks/immutability': 'off' },
  },
  {
    // Shared component modules intentionally co-export small helpers/constants.
    files: ['src/App.tsx', 'src/components/*.tsx', 'src/test/**'],
    rules: { 'react-refresh/only-export-components': 'off' },
  },
);
