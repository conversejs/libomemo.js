(function() {
    const VERSION = 0;

    function iterateHash(data, key, count) {
        const combinedData = new Uint8Array(data.byteLength + key.byteLength);
        combinedData.set(new Uint8Array(data), 0);
        combinedData.set(new Uint8Array(key), data.byteLength);
        return Internal.crypto.hash(combinedData.buffer).then((result) => {
            if (--count === 0) {
                return result;
            } else {
                return iterateHash(result, key, count);
            }
        });
    }

    function getEncodedChunk(hash, offset) {
        const chunk = ( hash[offset]   * Math.pow(2,32) +
                      hash[offset+1] * Math.pow(2,24) +
                      hash[offset+2] * Math.pow(2,16) +
                      hash[offset+3] * Math.pow(2,8) +
                      hash[offset+4] ) % 100000;
        let s = chunk.toString();
        while (s.length < 5) {
            s = '0' + s;
        }
        return s;
    }

    function getDisplayStringFor(identifier, key, iterations) {
        const versionUint16Array= new Uint16Array([VERSION]);
        const versionLength = versionUint16Array.buffer.byteLength;

        const keyUint8Array = new Uint8Array(key);
        const keyLength = keyUint8Array.buffer.byteLength;

        const identifierUint8Array = new TextEncoder().encode(identifier);
        const identifierLength = identifierUint8Array.buffer.byteLength;

        const combinedBuffer = new Uint8Array(
            versionLength +
            keyLength +
            identifierLength
        );
        combinedBuffer.set(versionUint16Array, 0);
        combinedBuffer.set(keyUint8Array, versionLength);
        combinedBuffer.set(identifierUint8Array, versionLength + keyLength);
        return iterateHash(combinedBuffer.buffer, key, iterations).then((output) => {
            output = new Uint8Array(output);
            return getEncodedChunk(output, 0) +
                getEncodedChunk(output, 5) +
                getEncodedChunk(output, 10) +
                getEncodedChunk(output, 15) +
                getEncodedChunk(output, 20) +
                getEncodedChunk(output, 25);
        });
    }

    libsignal.FingerprintGenerator = function(iterations) {
        this.iterations = iterations;
    };

    libsignal.FingerprintGenerator.prototype = {
        createFor(localIdentifier, localIdentityKey,
                            remoteIdentifier, remoteIdentityKey) {
            if (typeof localIdentifier !== 'string' ||
                typeof remoteIdentifier !== 'string' ||
                !(localIdentityKey instanceof ArrayBuffer) ||
                !(remoteIdentityKey instanceof ArrayBuffer)) {

              throw new Error('Invalid arguments');
            }

            return Promise.all([
                getDisplayStringFor(localIdentifier, localIdentityKey, this.iterations),
                getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this.iterations)
            ]).then(function(fingerprints) {
                return fingerprints.sort().join('');
            });
        }
    };

})();
