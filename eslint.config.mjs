/**
 * @license GPL-3.0-or-later
 * Copyright (C) 2025 Caleb Gyamfi - Omnixys Technologies
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * For more information, visit <https://www.gnu.org/licenses/>.
 */

// @ts-check
/**
 * Vollständige ESLint Flat-Config für ein TypeScript Node/NestJS Backend.
 * Enthält Best Practices für:
 *  - Typensicherheit
 *  - Codequalität & Wartbarkeit
 *  - Performance
 *  - Security
 *  - Prettier & Clean Code
 */

import eslint from '@eslint/js';
import prettier from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'eslint.config.mjs',
      'dist/**',
      'node_modules/**',
      'coverage/**',
      '*.d.ts',
      '.extras/scripts/commitlint-formatter.js',
      '.extras/docker',
      'commitlint.config.mjs',
      'prisma.config.ts',
      'release.config.js',
      './.extras/**',
      './prisma/**',
      'src/prisma/generated/**',
    ],
  },

  // Basisempfehlungen
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  prettier,

  {
    languageOptions: {
      globals: {
        ...globals.node,
      },
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: {
        project: [
          './tsconfig.json',
          './tsconfig.test.json',
          './release.config.js',
        ],

        // projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },

    rules: {
      /* ───────────────────────────────
       * 🧠 TypeScript Best Practices
       * ─────────────────────────────── */
      '@typescript-eslint/array-type': ['warn', { default: 'array-simple' }],
      '@typescript-eslint/ban-ts-comment': [
        'error',
        { 'ts-ignore': 'allow-with-description' },
      ],
      '@typescript-eslint/consistent-type-assertions': [
        'warn',
        { assertionStyle: 'as', objectLiteralTypeAssertions: 'never' },
      ],
      '@typescript-eslint/consistent-type-definitions': ['warn', 'interface'],
      '@typescript-eslint/consistent-type-imports': [
        'warn',
        { prefer: 'type-imports', fixStyle: 'separate-type-imports' },
      ],
      '@typescript-eslint/explicit-function-return-type': [
        'warn',
        { allowExpressions: true, allowTypedFunctionExpressions: true },
      ],
      '@typescript-eslint/member-ordering': [
        'warn',
        {
          default: ['signature', 'field', 'constructor', 'method'],
        },
      ],
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-for-in-array': 'error',
      '@typescript-eslint/no-inferrable-types': 'off',
      '@typescript-eslint/no-misused-promises': [
        'error',
        { checksVoidReturn: false },
      ],
      '@typescript-eslint/no-namespace': 'error',
      '@typescript-eslint/no-non-null-assertion': 'warn',
      '@typescript-eslint/no-unsafe-assignment': 'warn',
      '@typescript-eslint/no-unsafe-argument': 'warn',
      '@typescript-eslint/no-unsafe-member-access': 'warn',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/prefer-nullish-coalescing': 'warn',
      '@typescript-eslint/prefer-optional-chain': 'warn',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/switch-exhaustiveness-check': 'warn',

      /* ───────────────────────────────
       * 🧹 Clean Code / Style
       * ─────────────────────────────── */
      'no-console': ['warn', { allow: ['warn', 'error', 'debug'] }],
      'no-empty': 'warn',
      'no-multi-spaces': 'error',
      'no-trailing-spaces': 'warn',
      'prefer-const': 'warn',
      'no-var': 'error',
      eqeqeq: ['error', 'smart'],
      'object-shorthand': ['warn', 'always'],
      'arrow-body-style': ['warn', 'as-needed'],
      'spaced-comment': ['warn', 'always', { markers: ['/'] }],
      curly: ['warn', 'all'],

      /* ───────────────────────────────
       * 🧩 NestJS / Node Patterns
       * ─────────────────────────────── */
      'no-process-exit': 'error',
      'no-return-await': 'warn',
      'no-useless-catch': 'warn',
      'no-shadow': 'off', // wird von TS geregelt
      'prefer-template': 'warn',
      'no-new-require': 'error',
      'no-path-concat': 'error',
    },
  },
);
