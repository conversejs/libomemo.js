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

.PHONY: ci
ci: lint
	npm run test:node

.PHONY: check
check: lint dist test

dist/libomemo.js:: node_modules
	npm run build

dist: dist/libomemo.js

build/curve25519_compiled.js:: node_modules Gruntfile.js
	npm run compile

compile: build/curve25519_compiled.js
