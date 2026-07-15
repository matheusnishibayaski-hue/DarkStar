import js from "@eslint/js";
import globals from "globals";

export default [
  js.configs.recommended,
  {
    files: ["frontend/js/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.browser,
      },
    },
    rules: {
      eqeqeq: ["error", "always"],
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
    },
  },
];
