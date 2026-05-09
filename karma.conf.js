// Karma configuration
import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import { string } from "rollup-plugin-string";

export default function (config) {
    config.set({
        basePath: "",

        frameworks: ["mocha"],

        files: [
            "node_modules/mocha/mocha.css",
            "node_modules/chai/chai.js",

            {
                pattern: "protos/WhisperTextProtocol.proto",
                served: true,
                included: false,
            },
            {
                pattern: "protos/push.proto",
                served: true,
                included: false,
            },
            {
                pattern: "build/curve25519_compiled.wasm",
                served: true,
                included: false,
            },
            {
                pattern: "dist/curve25519_compiled.wasm",
                served: true,
                included: false,
            },
            {
                pattern: "dist/libomemo.umd.js",
                served: true,
                included: true,
            },
            "test/test-setup.js",
            "test/utils.js",
            "test/testvectors.js",
            "test/InMemorySignalProtocolStore.js",
            "test/KeyHelperTest.js",
            "test/NumericFingerprintTest.js",
            "test/SessionBuilderTest.js",
            "test/SessionCipherTest.js",
            "test/SignalProtocolAddressTest.js",
            "test/cryptoTest.js",
            "test/CurveTest.js",
            "test/helpersTest.js",
            "test/SessionRecordTest.js",
            "test/SessionLockTest.js",
            "test/SessionStore_test.js",
            "test/SignedPreKeyStore_test.js",
            "test/PreKeyStore_test.js",
            "test/IdentityKeyStore_test.js",
            "test/SignalProtocolStore_test.js",
        ],

        exclude: ["test/*~"],

        preprocessors: {},

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
