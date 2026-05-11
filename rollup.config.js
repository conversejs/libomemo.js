import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";

function onwarn(warning, warn) {
    if (
        warning.code === "CIRCULAR_DEPENDENCY" &&
        warning.message.includes("node_modules/protobufjs")
    )
        return;
    warn(warning);
}

export default [
    {
        input: "src/index.js",
        output: [
            {
                file: "dist/libomemo.esm.js",
                format: "es",
            },
            {
                file: "dist/libomemo.umd.js",
                format: "umd",
                name: "libomemo",
                exports: "named",
            },
        ],
        plugins: [
            string({ include: "**/*.proto" }),
            resolve({ browser: true }),
            commonjs(),
        ],
        external: [],
        onwarn,
    },
    {
        input: "src/curve25519_worker.js",
        output: {
            file: "dist/libomemo-worker.js",
            format: "iife",
        },
        plugins: [resolve({ browser: true }), commonjs()],
        onwarn,
    },
];
