ESLINT		?= ./node_modules/.bin/eslint
GRUNT 		?= ./node_modules/.bin/grunt
KARMA			?= ./node_modules/.bin/karma

package-lock.json: package.json
	npm i

.PHONY: eslint
eslint: package-lock.json
	$(ESLINT) src/**/*.js test/**/*.js


.PHONY: check
check: eslint
	$(KARMA) start karma.conf.js $(ARGS)

dist/libsignal-protocol.js:: package-lock.json
	$(GRUNT) build

dist: dist/libsignal-protocol.js
