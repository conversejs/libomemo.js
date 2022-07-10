// Karma configuration
// Generated on Sat Jul 09 2022 11:32:08 GMT+0200 (Central European Summer Time)

module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',


    // frameworks to use
    // available frameworks: https://www.npmjs.com/search?q=keywords:karma-adapter
    frameworks: ['mocha'],


    // list of files / patterns to load in the browser
    files: [
      'node_modules/mocha/mocha.css',
      'node_modules/chai/chai.js',

      'test/utils.js',
      'test/testvectors.js',
      'test/InMemorySignalProtocolStore.js',

      { pattern: 'protos/WhisperTextProtocol.proto', served: true, type: 'proto', included: false },
      { pattern: 'protos/push.proto', served: true, type: 'proto', included: false },
      { pattern: 'build/curve25519_compiled.wasm', served: true, type: 'wasm', included: false },
      'build/curve25519_concat.js',
      'src/curve25519_worker_manager.js',
      'build/components_concat.js',

      "src/Curve.js",
      "src/crypto.js",
      "src/helpers.js",
      "src/KeyHelper.js",
      "src/SignalProtocolAddress.js",
      "src/SessionBuilder.js",
      "src/SessionCipher.js",
      "build/protobufs_concat.js",
      "src/SessionRecord.js",
      "src/SessionLock.js",
      "src/NumericFingerprint.js",

      'test/KeyHelperTest.js',
      'test/NumericFingerprintTest.js',
      'test/SessionBuilderTest.js',
      'test/SessionCipherTest.js',
      'test/SignalProtocolAddressTest.js',
      'test/cryptoTest.js',
      'test/helpersTest.js',

      'test/SessionStore_test.js',
      'test/SignedPreKeyStore_test.js',
      'test/PreKeyStore_test.js',
      'test/IdentityKeyStore_test.js',
      'test/SignalProtocolStore_test.js',
    ],


    // list of files / patterns to exclude
    exclude: [
      'test/*~'
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://www.npmjs.com/search?q=keywords:karma-preprocessor
    preprocessors: {
    },


    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://www.npmjs.com/search?q=keywords:karma-reporter
    reporters: ['progress'],

    customDebugFile: 'test/debug.html',


    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,


    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,


    // start these browsers
    // available browser launchers: https://www.npmjs.com/search?q=keywords:karma-launcher
    browsers: ['Chrome'],


    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: false,

    // Concurrency level
    // how many browser instances should be started simultaneously
    concurrency: Infinity
  })
}
