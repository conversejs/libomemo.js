export class SignalProtocolAddress {
    #name;
    #deviceId;

    constructor(name, deviceId) {
        this.#name = name;
        this.#deviceId = deviceId;
    }

    getName() {
        return this.#name;
    }

    getDeviceId() {
        return this.#deviceId;
    }

    toString() {
        return `${this.#name}.${this.#deviceId}`;
    }

    equals(other) {
        if (!(other instanceof SignalProtocolAddress)) {
            return false;
        }
        return other.#name === this.#name && other.#deviceId === this.#deviceId;
    }
}

// Attach fromString as a regular function so it works with `new` (legacy compat)
SignalProtocolAddress.fromString = function (encodedAddress) {
    if (typeof encodedAddress !== "string" || !encodedAddress.match(/.*\.\d+/)) {
        throw new Error("Invalid SignalProtocolAddress string");
    }
    const parts = encodedAddress.split(".");
    return new SignalProtocolAddress(parts[0], parseInt(parts[1]));
};
