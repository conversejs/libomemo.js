ESLINT			?= ./node_modules/.bin/eslint

package-lock.json: package.json
	npm i

.PHONY: eslint
eslint: package-lock.json
	$(ESLINT) src/**/*.js
