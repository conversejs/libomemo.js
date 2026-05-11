// Karma configuration
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";

export default function (config) {
    config.set({
        basePath: "",

        frameworks: ["mocha"],

        files: [
            { pattern: "protos/WhisperTextProtocol.proto", served: true, included: false },
            { pattern: "protos/push.proto", served: true, included: false },
            { pattern: "build/curve25519_compiled.wasm", served: true, included: false },
            { pattern: "dist/curve25519_compiled.wasm", served: true, included: false },
            // chai loaded as a global (v3 breaks in strict mode)
            "node_modules/chai/chai.js",
            // Inline setup: tell the WASM wrapper where to find the .wasm file
            { pattern: "test/support/karma-setup.js", included: true, served: true, watched: false },
            // All test files go through rollup preprocessor
            "test/**/*.js",
        ],

        exclude: ["test/*~", "test/integration.js"],

        preprocessors: {
            "test/**/*.js": ["rollup"],
        },

        rollupPreprocessor: {
            output: {
                format: "iife",
                globals: { chai: "chai" },
                sourcemap: "inline",
            },
            onwarn(warning, warn) {
                if (
                    warning.code === "CIRCULAR_DEPENDENCY" &&
                    warning.message.includes("node_modules/protobufjs")
                )
                    return;
                warn(warning);
            },
            plugins: [
                string({ include: "**/*.proto" }),
                resolve({ browser: true }),
                commonjs(),
            ],
            external: ["chai"],
        },

        reporters: ["progress"],

        customDebugFile: "test/debug.html",

        port: 9876,

        colors: true,

        logLevel: config.LOG_INFO,

        autoWatch: true,

        browsers: ["ChromeHeadless"],

        processKillTimeout: 2000,
        captureTimeout: 60000,
        browserDisconnectTimeout: 2000,
        browserDisconnectTolerance: 0,
        browserNoActivityTimeout: 30000,

        singleRun: false,

        concurrency: Infinity,
    });
}
