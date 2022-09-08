/* eslint-disable */
module.exports = {
    // REF: https://typescript-eslint.io/docs/linting/
    root: true,
    parser: '@typescript-eslint/parser',
    plugins: [
        '@typescript-eslint',
    ],
    extends: [
        'eslint:recommended',
        'plugin:@typescript-eslint/recommended',
    ],
};