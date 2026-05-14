import Curve25519Module, {
    Curve25519EmscriptenModule,
    Curve25519ModuleOptions,
} from "../build/curve25519_compiled";
import { KeyPair } from "./types";

declare const __WASM_BASE__: string | undefined;

const basepoint = new Uint8Array(32);
basepoint[0] = 9;

export class Curve25519 {
    #module: Promise<Curve25519EmscriptenModule>;

    constructor() {
        this.#module = this.#getModule();
    }

    async #getModule(): Promise<Curve25519EmscriptenModule> {
        const opts: Curve25519ModuleOptions = {};
        if (typeof __WASM_BASE__ !== "undefined") {
            opts.locateFile = (path: string): string => {
                if (path.endsWith(".wasm")) return __WASM_BASE__ + path;
                return path;
            };
        }
        return await Curve25519Module(opts);
    }

    #allocate(module: Curve25519EmscriptenModule, bytes: Uint8Array): number {
        const address = module._malloc(bytes.length);
        module.HEAPU8.set(bytes, address);
        return address;
    }

    #readBytes(
        module: Curve25519EmscriptenModule,
        address: number,
        length: number,
        array: Uint8Array
    ): void {
        array.set(module.HEAPU8.subarray(address, address + length));
    }

    #keyPair(module: Curve25519EmscriptenModule, privKey: ArrayBuffer): KeyPair {
        const priv = new Uint8Array(privKey);
        priv[0] &= 248;
        priv[31] &= 127;
        priv[31] |= 64;

        const publicKey_ptr = module._malloc(32);
        const privateKey_ptr = this.#allocate(module, priv);
        const basepoint_ptr = this.#allocate(module, basepoint);

        const err = module._curve25519_donna(publicKey_ptr, privateKey_ptr, basepoint_ptr);
        if (err) {
            console.log(err);
        }

        const res = new Uint8Array(32);
        this.#readBytes(module, publicKey_ptr, 32, res);

        module._free(publicKey_ptr);
        module._free(privateKey_ptr);
        module._free(basepoint_ptr);

        return { pubKey: res.buffer, privKey: priv.buffer };
    }

    #sharedSecret(
        module: Curve25519EmscriptenModule,
        pubKey: ArrayBuffer,
        privKey: ArrayBuffer
    ): ArrayBuffer {
        const sharedKey_ptr = module._malloc(32);
        const privateKey_ptr = this.#allocate(module, new Uint8Array(privKey));
        const basepoint_ptr = this.#allocate(module, new Uint8Array(pubKey));

        const err = module._curve25519_donna(sharedKey_ptr, privateKey_ptr, basepoint_ptr);
        if (err) {
            console.log(err);
        }

        const res = new Uint8Array(32);
        this.#readBytes(module, sharedKey_ptr, 32, res);

        module._free(sharedKey_ptr);
        module._free(privateKey_ptr);
        module._free(basepoint_ptr);

        return res.buffer;
    }

    #sign(
        module: Curve25519EmscriptenModule,
        privKey: ArrayBuffer,
        message: ArrayBuffer
    ): ArrayBuffer {
        const signature_ptr = module._malloc(64);
        const privateKey_ptr = this.#allocate(module, new Uint8Array(privKey));
        const message_ptr = this.#allocate(module, new Uint8Array(message));

        const err = module._xed25519_sign(
            signature_ptr,
            privateKey_ptr,
            message_ptr,
            message.byteLength
        );
        if (err) {
            console.log(err);
        }

        const res = new Uint8Array(64);
        this.#readBytes(module, signature_ptr, 64, res);

        module._free(signature_ptr);
        module._free(privateKey_ptr);
        module._free(message_ptr);

        return res.buffer;
    }

    #verify(
        module: Curve25519EmscriptenModule,
        pubKey: ArrayBuffer,
        message: ArrayBuffer,
        sig: ArrayBuffer
    ): boolean {
        const publicKey_ptr = this.#allocate(module, new Uint8Array(pubKey));
        const signature_ptr = this.#allocate(module, new Uint8Array(sig));
        const message_ptr = this.#allocate(module, new Uint8Array(message));

        const res = module._curve25519_verify(
            signature_ptr,
            publicKey_ptr,
            message_ptr,
            message.byteLength
        );

        module._free(publicKey_ptr);
        module._free(signature_ptr);
        module._free(message_ptr);

        return res === 0;
    }

    #processKeys(raw_keys: KeyPair): KeyPair {
        const origPub = new Uint8Array(raw_keys.pubKey);
        const pub = new Uint8Array(33);
        pub.set(origPub, 1);
        pub[0] = 5;
        return { pubKey: pub.buffer, privKey: raw_keys.privKey };
    }

    #generateRandomBytes(size: number): ArrayBuffer {
        const array = new Uint8Array(size);
        globalThis.crypto.getRandomValues(array);
        return array.buffer;
    }

    #validatePrivKey(privKey: unknown): void {
        if (!(privKey instanceof ArrayBuffer)) {
            throw new Error("Invalid private key: expected ArrayBuffer");
        }
        if (privKey.byteLength !== 32) {
            throw new Error("Invalid private key");
        }
    }

    #validatePubKeyFormat(pubKey: ArrayBuffer): ArrayBuffer | undefined {
        if (!(pubKey instanceof ArrayBuffer)) {
            throw new Error("Invalid public key: expected ArrayBuffer");
        }
        if (
            (pubKey.byteLength !== 33 || new Uint8Array(pubKey)[0] !== 5) &&
            pubKey.byteLength !== 32
        ) {
            throw new Error("Invalid public key");
        }
        if (pubKey.byteLength === 33) {
            return pubKey.slice(1);
        }
        console.error(
            "WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey"
        );
        return pubKey;
    }

    async ECDHE(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        pubKey = this.#validatePubKeyFormat(pubKey)!;
        this.#validatePrivKey(privKey);
        if (pubKey.byteLength !== 32) throw new Error("Invalid public key");

        return this.#sharedSecret(await this.#module, pubKey, privKey);
    }

    async Ed25519Sign(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        this.#validatePrivKey(privKey);
        if (message === undefined) throw new Error("Invalid message");

        return this.#sign(await this.#module, privKey, message);
    }

    async generateKeyPair(): Promise<KeyPair> {
        const privKey = this.#generateRandomBytes(32);
        return await this.createKeyPair(privKey);
    }

    async createKeyPair(privKey: ArrayBuffer): Promise<KeyPair> {
        this.#validatePrivKey(privKey);
        const raw_keys = this.#keyPair(await this.#module, privKey);
        return this.#processKeys(raw_keys);
    }

    async calculateAgreement(pubKey: ArrayBuffer, privKey: ArrayBuffer): Promise<ArrayBuffer> {
        this.#validatePubKeyFormat(pubKey);
        this.#validatePrivKey(privKey);
        return await this.ECDHE(pubKey, privKey);
    }

    async verifySignature(pubKey: ArrayBuffer, msg: ArrayBuffer, sig: ArrayBuffer): Promise<void> {
        pubKey = this.#validatePubKeyFormat(pubKey)!;
        if (pubKey.byteLength !== 32) {
            throw new Error("Invalid public key");
        }

        if (msg === undefined) {
            throw new Error("Invalid message");
        }

        if (sig === undefined || sig.byteLength !== 64) {
            throw new Error("Invalid signature");
        }

        if (!this.#verify(await this.#module, pubKey, msg, sig)) {
            throw new Error("Invalid signature");
        }
    }

    async calculateSignature(privKey: ArrayBuffer, message: ArrayBuffer): Promise<ArrayBuffer> {
        this.#validatePrivKey(privKey);
        if (message === undefined) {
            throw new Error("Invalid message");
        }
        return await this.Ed25519Sign(privKey, message);
    }
}
