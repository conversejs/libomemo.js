import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";
import typescript from "@rollup/plugin-typescript";
import { dts } from "rollup-plugin-dts";

export function onwarn(warning, warn) {
    if (
        warning.code === "CIRCULAR_DEPENDENCY" &&
        warning.message.includes("node_modules/protobufjs")
    )
        return;
    warn(warning);
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
                file: "dist/libomemo.umd.js",
                format: "umd",
                name: "libomemo",
                exports: "named",
                sourcemap: true,
            },
            {
                file: "dist/libomemo.umd.js",
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
        },
        plugins: [
            typescript({ tsconfig: "./tsconfig.json", declaration: false, sourceMap: true }),
            resolve({ browser: true }),
            commonjs(),
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
