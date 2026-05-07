module.exports = {
    "env": {
        "browser": true,
        "es2021": true
    },
    "globals": {
        "module": true,
        "Internal": true,
        "Module": true,
        "chai": true,
        "dcodeIO": true,
        "describe": true,
        "it": true,
        "libomemo": true,
        "parseInt": true,
        "require": true,
        "util": true,
    },
    "extends": "eslint:recommended",
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module"
    },
    "rules": {
        "no-proto": "off",
        "no-var": "warn",
        "no-debugger": "warn",
   }
}
