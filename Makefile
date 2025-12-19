.PHONY: clean
clean:
	npm run clean

node_modules: package.json package-lock.json
	npm install

.PHONY: lint
lint: node_modules
	npm run lint

.PHONY: test
test: lint
	npm test -- $(ARGS)

.PHONY: check
check: lint dist test

dist/libsignal-protocol.js:: node_modules
	npm run build

dist: dist/libsignal-protocol.js

build/curve25519_compiled.js:: node_modules Gruntfile.js
	npm run compile

compile: build/curve25519_compiled.js
