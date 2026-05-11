/* vim: ts=4:sw=4:expandtab */

import Curve25519Module from "../build/curve25519_compiled.js";

let moduleInstance = null;

async function getModule() {
    if (!moduleInstance) {
        const opts = {};
        if (typeof globalThis.__WASM_BASE__ !== "undefined") {
            opts.locateFile = (path) => {
                if (path.endsWith(".wasm")) return globalThis.__WASM_BASE__ + path;
                return path;
            };
        }
        moduleInstance = await Curve25519Module(opts);
    }
    return moduleInstance;
}

function _allocate(Module, bytes) {
    const address = Module._malloc(bytes.length);
    Module.HEAPU8.set(bytes, address);
    return address;
}

function _readBytes(Module, address, length, array) {
    array.set(Module.HEAPU8.subarray(address, address + length));
}

const basepoint = new Uint8Array(32);
basepoint[0] = 9;

function createCurve25519(Module) {
    return {
        keyPair(privKey) {
            const priv = new Uint8Array(privKey);
            priv[0] &= 248;
            priv[31] &= 127;
            priv[31] |= 64;

            const publicKey_ptr = Module._malloc(32);
            const privateKey_ptr = _allocate(Module, priv);
            const basepoint_ptr = _allocate(Module, basepoint);

            const err = Module._curve25519_donna(publicKey_ptr, privateKey_ptr, basepoint_ptr);
            if (err) {
                console.log(err);
            }

            const res = new Uint8Array(32);
            _readBytes(Module, publicKey_ptr, 32, res);

            Module._free(publicKey_ptr);
            Module._free(privateKey_ptr);
            Module._free(basepoint_ptr);

            return { pubKey: res.buffer, privKey: priv.buffer };
        },

        sharedSecret(pubKey, privKey) {
            const sharedKey_ptr = Module._malloc(32);
            const privateKey_ptr = _allocate(Module, new Uint8Array(privKey));
            const basepoint_ptr = _allocate(Module, new Uint8Array(pubKey));

            const err = Module._curve25519_donna(sharedKey_ptr, privateKey_ptr, basepoint_ptr);
            if (err) {
                console.log(err);
            }

            const res = new Uint8Array(32);
            _readBytes(Module, sharedKey_ptr, 32, res);

            Module._free(sharedKey_ptr);
            Module._free(privateKey_ptr);
            Module._free(basepoint_ptr);

            return res.buffer;
        },

        sign(privKey, message) {
            const signature_ptr = Module._malloc(64);
            const privateKey_ptr = _allocate(Module, new Uint8Array(privKey));
            const message_ptr = _allocate(Module, new Uint8Array(message));

            const err = Module._xed25519_sign(
                signature_ptr,
                privateKey_ptr,
                message_ptr,
                message.byteLength
            );
            if (err) {
                console.log(err);
            }

            const res = new Uint8Array(64);
            _readBytes(Module, signature_ptr, 64, res);

            Module._free(signature_ptr);
            Module._free(privateKey_ptr);
            Module._free(message_ptr);

            return res.buffer;
        },

        verify(pubKey, message, sig) {
            const publicKey_ptr = _allocate(Module, new Uint8Array(pubKey));
            const signature_ptr = _allocate(Module, new Uint8Array(sig));
            const message_ptr = _allocate(Module, new Uint8Array(message));

            const res = Module._xed25519_verify(
                signature_ptr,
                publicKey_ptr,
                message_ptr,
                message.byteLength
            );

            Module._free(publicKey_ptr);
            Module._free(signature_ptr);
            Module._free(message_ptr);

            return res !== 0;
        },
    };
}

function createCurve25519Async(curve25519) {
    return {
        keyPair: (privKey) => Promise.resolve(curve25519.keyPair(privKey)),
        sharedSecret: (pubKey, privKey) => Promise.resolve(curve25519.sharedSecret(pubKey, privKey)),
        sign: (privKey, message) => Promise.resolve(curve25519.sign(privKey, message)),
        verify: (pubKey, message, sig) =>
            new Promise((resolve, reject) => {
                if (curve25519.verify(pubKey, message, sig)) {
                    reject(new Error("Invalid signature"));
                } else {
                    resolve();
                }
            }),
    };
}

export { createCurve25519, createCurve25519Async, getModule };
