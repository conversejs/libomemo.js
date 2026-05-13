import path from "path";
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";
import esbuild from "rollup-plugin-esbuild";
import { onwarn } from "./rollup.config.js";
import fs from "fs";

function resolveTsFromJs() {
    return {
        name: "resolve-ts-from-js",
        resolveId(source, importer) {
            if (!source.endsWith(".js") || !importer) {
                return null;
            }
            if (source.startsWith("../src/") || source.startsWith("./src/")) {
                const tsPath = source.replace(/\.js$/, ".ts");
                return path.resolve(path.dirname(importer), tsPath);
            }
            // Also resolve .js imports within test/ directory to .ts files
            if (source.startsWith("./") || source.startsWith("../")) {
                const tsPath = source.replace(/\.js$/, ".ts");
                const resolved = path.resolve(path.dirname(importer), tsPath);
                if (fs.existsSync(resolved)) {
                    return resolved;
                }
            }
            return null;
        },
    };
}

export default function (config) {
    config.set({
        basePath: "",

        frameworks: ["mocha"],

        files: [
            { pattern: "protos/WhisperTextProtocol.proto", served: true, included: false },
            { pattern: "protos/push.proto", served: true, included: false },
            { pattern: "build/curve25519_compiled.wasm", served: true, included: false },
            { pattern: "dist/curve25519_compiled.wasm", served: true, included: false },
            "node_modules/chai/chai.js",
            "node_modules/mocha/mocha.js",
            "node_modules/mocha/mocha.css",
            {
                pattern: "test/support/karma-setup.ts",
                included: true,
                served: true,
                watched: false,
            },
            "test/**/*.ts",
        ],

        exclude: ["test/*~"],

        preprocessors: {
            "test/**/*.ts": ["rollup"],
        },

        rollupPreprocessor: {
            output: {
                format: "iife",
                globals: { chai: "chai" },
                sourcemap: "inline",
                dir: "build/test",
            },
            onwarn,
            plugins: [
                resolveTsFromJs(),
                string({ include: "**/*.proto" }),
                esbuild({
                    target: "es2020",
                    tsconfig: "./tsconfig.json",
                    sourcemap: "inline",
                }),
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
