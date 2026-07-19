import js from '@eslint/js';
import globals from 'globals';
import svelte from 'eslint-plugin-svelte';
import tseslint from 'typescript-eslint';

import svelteConfig from './svelte.config.ts';

export default tseslint.config(
  // Generated / build output and tooling configs are not linted.
  { ignores: ['dist/', 'node_modules/', '.vite/', '*.config.js', '*.config.ts'] },

  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...svelte.configs.recommended,

  {
    languageOptions: {
      globals: { ...globals.browser },
    },
    rules: {
      // Allow intentionally-unused bindings named with a leading underscore
      // (e.g. `{#each Array(3) as _, i (i)}`).
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
      // svelte-check owns a11y-warning suppression via <!-- svelte-ignore -->;
      // this rule can't see which compiler warnings are active and false-positives
      // on ignores that svelte-check still needs.
      'svelte/no-unused-svelte-ignore': 'off',
    },
  },

  // Svelte components: parse <script lang="ts"> with the TS parser.
  {
    files: ['**/*.svelte', '**/*.svelte.ts'],
    languageOptions: {
      parserOptions: {
        parser: tseslint.parser,
        extraFileExtensions: ['.svelte'],
        svelteConfig,
      },
    },
  },

  {
    files: ['e2e/**/*.ts'],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
);
