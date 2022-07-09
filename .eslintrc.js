module.exports = {
    "env": {
        "browser": true,
        "es2021": true
    },
    "globals": {
        "Internal": true,
        "Module": true,
        "chai": true,
        "dcodeIO": true,
        "describe": true,
        "it": true,
        "libsignal": true,
        "parseInt": true,
        "util": true,
    },
    "extends": "eslint:recommended",
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module"
    },
    "rules": {
        "no-proto": "off",
    }
}
