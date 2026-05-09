import js from "@eslint/js";
import globals from "globals";

export default [
    js.configs.recommended,
    {
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
                Internal: "writable",
                Module: "writable",
                libomemo: "writable",
                util: "writable",
            },
        },
        rules: {
            "no-proto": "off",
            "no-var": "warn",
            "no-debugger": "warn",
        },
    },
    {
        files: ["test/**/*.js"],
        rules: {
            "no-redeclare": ["error", { builtinGlobals: false }],
        },
    },
];
