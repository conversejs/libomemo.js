import js from "@eslint/js";
import globals from "globals";
import ts from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
    js.configs.recommended,
    {
        files: ["src/**/*.ts", "test/**/*.ts"],
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                project: "./tsconfig.json",
            },
            globals: {
                ...globals.browser,
                chai: "readonly",
                describe: "readonly",
                it: "readonly",
                before: "readonly",
                after: "readonly",
            },
        },
        plugins: {
            "@typescript-eslint": ts,
        },
        rules: {
            ...ts.configs.recommended.rules,
            "no-proto": "off",
            "no-var": "warn",
            "no-debugger": "warn",
            "no-console": "off",
            "@typescript-eslint/no-explicit-any": "warn",
            "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
            "@typescript-eslint/no-unsafe-argument": "off",
            "@typescript-eslint/no-unsafe-assignment": "off",
            "@typescript-eslint/no-unsafe-call": "off",
            "@typescript-eslint/no-unsafe-member-access": "off",
            "@typescript-eslint/no-unsafe-return": "off",
            "@typescript-eslint/no-unnecessary-type-assertion": "warn",
            "@typescript-eslint/require-await": "off",
            "@typescript-eslint/no-floating-promises": "warn",
            "@typescript-eslint/no-misused-promises": "warn",
            "@typescript-eslint/restrict-template-expressions": "warn",
        },
    },
    {
        files: ["src/**/*.js", "test/**/*.js"],
        languageOptions: {
            ecmaVersion: "latest",
            sourceType: "module",
            globals: {
                ...globals.browser,
                chai: "readonly",
                describe: "readonly",
                it: "readonly",
                before: "readonly",
                after: "readonly",
            },
        },
        rules: {
            "no-proto": "off",
            "no-var": "warn",
            "no-debugger": "warn",
            "no-console": "off",
        },
    },
    {
        files: ["test/**/*.js", "test/**/*.ts"],
        rules: {
            "no-redeclare": ["error", { builtinGlobals: false }],
        },
    },
    {
        files: ["rollup.config.js", "eslint.config.mjs", "karma.conf.js", "scripts/**/*.js"],
        languageOptions: {
            globals: {
                ...globals.node,
            },
        },
    },
];
