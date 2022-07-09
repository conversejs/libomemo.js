ESLINT		?= ./node_modules/.bin/eslint
GRUNT 		?= ./node_modules/.bin/grunt

package-lock.json: package.json
	npm i

.PHONY: eslint
eslint: package-lock.json
	$(ESLINT) src/**/*.js


.PHONY: check
check: eslint
	$(GRUNT) test

dist/libsignal-protocol.js:: package-lock.json
	$(GRUNT) build

dist: dist/libsignal-protocol.js
