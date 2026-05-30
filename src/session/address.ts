/** Identifies a specific OMEMO device by name and device ID. */
export class OMEMOAddress {
    #name: string;
    #deviceId: number;

    constructor(name: string, deviceId: number) {
        this.#name = name;
        this.#deviceId = deviceId;
    }

    getName(): string {
        return this.#name;
    }

    getDeviceId(): number {
        return this.#deviceId;
    }

    toString(): string {
        return `${this.#name}.${this.#deviceId}`;
    }

    equals(other: unknown): boolean {
        if (!(other instanceof OMEMOAddress)) {
            return false;
        }
        return other.#name === this.#name && other.#deviceId === this.#deviceId;
    }

    static fromString(encodedAddress: string): OMEMOAddress {
        if (typeof encodedAddress !== "string" || !encodedAddress.match(/^.+\.\d+$/)) {
            throw new Error("Invalid OMEMOAddress string");
        }
        const lastDot = encodedAddress.lastIndexOf(".");
        const name = encodedAddress.substring(0, lastDot);
        const deviceId = parseInt(encodedAddress.substring(lastDot + 1));
        return new OMEMOAddress(name, deviceId);
    }
}
