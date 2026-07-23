import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";
import typescript from "@rollup/plugin-typescript";
import { dts } from "rollup-plugin-dts";
import esbuild from "rollup-plugin-esbuild";

export function onwarn(warning, warn) {
    if (
        warning.code === "CIRCULAR_DEPENDENCY" &&
        warning.message.includes("node_modules/protobufjs")
    )
        return;
    warn(warning);
}

/**
 * The Emscripten module is compiled with `-s SINGLE_FILE=1` (scripts/compile.js),
 * so the wasm is embedded as an in-JS data URI and needs no sibling asset or path
 * rewriting. One init-time hazard remains: emcc's Node branch runs
 * `scriptDirectory = __dirname + '/'` unconditionally, and `__dirname` does not
 * exist in an ES module, so importing the bundle under Node ESM would throw
 * `ReferenceError: __dirname is not defined` before any wasm work happens. This
 * plugin neutralises that single line with an environment-agnostic expression.
 * (scriptDirectory is unused for wasm loading once the binary is inlined.)
 */
function patchScriptDirectoryPlugin() {
    return {
        name: "patch-script-directory",
        transform(code, id) {
            if (!id.includes("curve25519_compiled")) return null;

            code = code.replace(
                /scriptDirectory = __dirname \+ '\/';/,
                `scriptDirectory = (typeof document !== 'undefined' && document.currentScript) ? document.currentScript.src.substring(0, document.currentScript.src.lastIndexOf('/') + 1) : '';`
            );

            return { code, map: { mappings: "", sources: [], names: [], version: 3 } };
        },
    };
}

export default [
    {
        input: "src/index.ts",
        output: [
            {
                file: "dist/libomemo.esm.js",
                format: "es",
                sourcemap: true,
            },
            {
                file: "dist/libomemo.umd.cjs",
                format: "umd",
                name: "libomemo",
                exports: "named",
                sourcemap: true,
            },
        ],
        plugins: [
            string({ include: "**/*.proto" }),
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
        ],
        external: [],
        onwarn,
    },
    {
        input: "src/index.ts",
        output: [
            {
                file: "dist/libomemo.esm.min.js",
                format: "es",
                sourcemap: true,
            },
            {
                file: "dist/libomemo.umd.min.cjs",
                format: "umd",
                name: "libomemo",
                exports: "named",
                sourcemap: true,
            },
        ],
        plugins: [
            string({ include: "**/*.proto" }),
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
            esbuild({ minify: true }),
        ],
        external: [],
        onwarn,
    },
    {
        input: "src/curve25519_worker.ts",
        output: {
            file: "dist/libomemo-worker.js",
            format: "iife",
            sourcemap: true,
            banner: "// Shim for Emscripten: provide document in worker context\nif (typeof document === 'undefined') { self.document = { baseURI: self.location.href }; }",
        },
        plugins: [
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
        ],
        onwarn,
    },
    {
        input: "src/curve25519_worker.ts",
        output: {
            file: "dist/libomemo-worker.min.js",
            format: "iife",
            sourcemap: true,
            banner: "// Shim for Emscripten: provide document in worker context\nif (typeof document === 'undefined') { self.document = { baseURI: self.location.href }; }",
        },
        plugins: [
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
            patchScriptDirectoryPlugin(),
            esbuild({ minify: true }),
        ],
        onwarn,
    },
    {
        input: "build/dts/index.d.ts",
        output: {
            file: "dist/index.d.ts",
            format: "es",
        },
        plugins: [dts()],
        onwarn,
    },
];
