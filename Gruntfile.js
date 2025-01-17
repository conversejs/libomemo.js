const child_process = require('child_process');
const util = require('util');

module.exports = function(grunt) {
  'use strict';

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    concat: {
      components: {
        src: [
          'node_modules/long/dist/long.js',
          'node_modules/bytebuffer/dist/ByteBufferAB.js',
          'node_modules/protobufjs/dist/protobuf.js'
        ],
        dest: 'build/components_concat.js',
      },
      curve25519: {
        src: [
          'build/curve25519_compiled.js',
          'src/curve25519_wrapper.js',
        ],
        dest: 'build/curve25519_concat.js'
      },
      protos: {
        src: [
          'protos/WhisperTextProtocol.proto'
        ],
        dest: 'build/protoText.js',
        options: {
          banner: 'var Internal = Internal || {};\n\nInternal.protoText = function() {\n\tvar protoText = {};\n\n',
          footer: '\n\treturn protoText;\n}();',
          process: function(src, file) {
            let res = "\tprotoText['" + file + "'] = \n";
            const lines = src.match(/[^\r\n]+/g);
            for (const i in lines) {
              res += "\t\t'" + lines[i] + "\\n' +\n";
            }
            return res + "''\t;\n";
          }
        }
      },
      protos_concat: {
        src: [
          'build/protoText.js',
          'src/protobufs.js',
        ],
        dest: 'build/protobufs_concat.js'
      },

      worker: {
        src: [
          'build/curve25519_concat.js',
          'src/curve25519_worker.js',
        ],
        dest: 'dist/libsignal-protocol-worker.js',
        options: {
          banner: ';(function(){\nvar Internal = {};\nvar libsignal = {};\n',
          footer: '\n})();'
        }

      },
      libsignalprotocol: {
        src: [
          'build/curve25519_concat.js',
          'src/curve25519_worker_manager.js',
          'build/components_concat.js',

          'src/Curve.js',
          'src/crypto.js',
          'src/helpers.js',
          'src/KeyHelper.js',
          'build/protobufs_concat.js',
          'src/SessionRecord.js',
          'src/SignalProtocolAddress.js',
          'src/SessionBuilder.js',
          'src/SessionCipher.js',
          'src/SessionLock.js',
          'src/NumericFingerprint.js'
        ],
        dest: 'dist/libsignal-protocol.js',
        options: {
          banner: ';(function(){\nvar Internal = {};\nwindow.libsignal = {};\n',
          footer: '\n})();'
        }

      },
    },
    compile: {
        curve25519_compiled: {
            src_files: [
              'native/ed25519/*.c',
              'native/ed25519/additions/*.c',
              'native/ed25519/nacl_sha512/*.c',
              'native/curve25519-donna.c',
              'native/ed25519/sha512/sha2big.c'
            ],
            methods: [
              'curve25519_donna',
              'curve25519_sign',
              'curve25519_verify',
              'crypto_sign_ed25519_ref10_ge_scalarmult_base',
              'sph_sha512_init',
              'malloc',
              'free',
              'xed25519_sign',
            ]
        }
    },

    watch: {
      worker: {
        files: ['<%= concat.worker.src %>'],
        tasks: ['concat:worker']
      },
      libsignalprotocol: {
        files: ['<%= concat.libsignalprotocol.src %>'],
        tasks: ['concat:libsignalprotocol']
      },
      protos: {
        files: ['<%= concat.protos.src %>'],
        tasks: ['concat:protos_concat']
      },
      protos_concat: {
        files: ['<%= concat.protos_concat.src %>'],
        tasks: ['concat:protos_concat']
      }
    },
  });

  Object.keys(grunt.config.get('pkg').devDependencies).forEach(function(key) {
    if (/^grunt(?!(-cli)?$)/.test(key)) {  // ignore grunt and grunt-cli
      grunt.loadNpmTasks(key);
    }
  });

  grunt.registerMultiTask('compile', 'Compile the C libraries with emscripten.', function() {
      const callback = this.async();
      const outfile = 'build/' + this.target + '.js';

      const exported_functions = this.data.methods.map(function(name) {
        return "'_" + name + "'";
      });
      const flags = [
          '-O1',
          '-Qunused-arguments',
          '-o',  outfile,
          '-Inative/ed25519/nacl_includes -Inative/ed25519 -Inative/ed25519/sha512',
          '-s', "EXPORTED_FUNCTIONS=\"[" + exported_functions.join(',') + "]\""];

      const command = [].concat('emcc', this.data.src_files, flags).join(' ');
      grunt.log.writeln('Compiling via emscripten to ' + outfile);

      const exitCode = 0;
      grunt.verbose.subhead(command);
      grunt.verbose.writeln(util.format('Expecting exit code %d', exitCode));

      const child = child_process.exec(command);
      child.stdout.on('data', function (d) { grunt.log.write(d); });
      child.stderr.on('data', function (d) { grunt.log.error(d); });
      child.on('exit', function(code) {
        if (code !== exitCode) {
          grunt.log.error(util.format('Exited with code: %d.', code));
          return callback(false);
        }

        grunt.verbose.ok(util.format('Exited with code: %d.', code));
        callback(true);
      });
  });

  grunt.registerTask('dev', ['watch']);
  grunt.registerTask('default', ['concat']);
  grunt.registerTask('build', ['compile', 'concat']);

};
