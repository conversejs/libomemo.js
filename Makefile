ESLINT		?= ./node_modules/.bin/eslint
GRUNT 		?= ./node_modules/.bin/grunt
KARMA		?= ./node_modules/.bin/karma

.PHONY: clean
clean:
	rm -rf node_modules

node_modules: package.json package-lock.json
	npm i

.PHONY: eslint
eslint: node_modules
	$(ESLINT) src/**/*.js test/**/*.js Gruntfile.js

test: eslint
	$(KARMA) start karma.conf.js $(ARGS)

.PHONY: check
check: dist test

dist/libsignal-protocol.js:: node_modules
	$(GRUNT) build

dist: dist/libsignal-protocol.js

build/curve25519_compiled.js:: node_modules Gruntfile.js
	$(GRUNT) compile

compile: build/curve25519_compiled.js
