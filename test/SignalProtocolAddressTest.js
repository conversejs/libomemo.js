/* global SignalProtocolAddress */

describe('SignalProtocolAddress', function() {

  const  { assert } = chai;

  const name = 'name';
  const deviceId = 42;
  const string = 'name.42';
  describe('getName', function() {
    it('returns the name', function() {
      const address = new SignalProtocolAddress(name, 1);
      assert.strictEqual(name, address.getName());
    });
  });
  describe('getDeviceId', function() {
    it('returns the deviceId', function() {
      const address = new SignalProtocolAddress(name, deviceId);
      assert.strictEqual(deviceId, address.getDeviceId());
    });
  });
  describe('toString', function() {
    it('returns the address', function() {
      const address = new SignalProtocolAddress(name, deviceId);
      assert.strictEqual(string, address.toString());
    });
  });
  describe('fromString', function() {
    it('throws on a bad inputs', function() {
      [ '', null, {} ].forEach(function(input) {
        assert.throws(function() {
          libsignal.SignalProtocolAddress.fromString(input);
        });
      });
    });
    it('constructs the address', function() {
      const address = libsignal.SignalProtocolAddress.fromString(string);
      assert.strictEqual(deviceId, address.getDeviceId());
      assert.strictEqual(name, address.getName());
    });
  });
});
