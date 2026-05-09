// Test setup shim - maps libomemo UMD exports to legacy global names used by tests
(function () {
    "use strict";

    if (!window.libomemo) {
        throw new Error("libomemo UMD bundle did not load");
    }

    window.util = window.libomemo.util;
    window.Internal = window.libomemo.Internal;
    window.SignalProtocolAddress = window.libomemo.SignalProtocolAddress;
    window.SessionBuilder = window.libomemo.SessionBuilder;
    window.SessionCipher = window.libomemo.SessionCipher;
    window.KeyHelper = window.libomemo.KeyHelper;
    window.libomemo.worker = {
        startWorker: window.libomemo.startWorker,
        stopWorker: window.libomemo.stopWorker,
    };
})();
