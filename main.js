var _ = require('underscore');
var fs = require('fs');
var path = require('path');
var nconf = require('nconf');
var nukible = require('./nukible');
var sodium = require('sodium');

var config = new nconf.Provider({
    env: true,
    argv: true,
    store: {
        type: 'file',
        file: path.join(__dirname, 'config.json')
    }
});

var appId = config.get('appId');
var appType = config.get('appType');
var name = config.get('name');
var nukiLocks = config.get('nukiLocks');

if (isPaired()) {
    processCommands({
        appId: appId,
        appType: appType,
        name: name,
        nukiLocks: nukiLocks
    });
} else {
    var self = this;
    var appIdBuffer = new Buffer(4);
    sodium.api.randombytes_buf(appIdBuffer);

    appId = appIdBuffer.readUInt32LE();
    config.set("appId", appId);
    config.set("appType", 2);   // Nuki Fob
    config.set("name", "HB NFC Key " + appId);
    config.set("nukiLocks", {});
    config.save(function (err) {
        if (err) {
            console.log("Writing configuration failed", err);
        } else {
            reReadConfig.call(self);
            pairOrProcessCommands.call(self);
        }
    });
}

function reReadConfig() {
    appId = config.get('appId');
    appType = config.get('appType');
    name = config.get('name');
    nukiLocks = config.get('nukiLocks');
}

function isPaired() {
    if (_.isNumber(appId) && _.isNumber(appType) && _.isString(name)) {
        return !!(_.isObject(nukiLocks) && _.keys(nukiLocks).length > 0);
    } else {
        return false;
    }
}

function pairOrProcessCommands() {
    if (isPaired()) {
        processCommands({
            appId: appId,
            appType: appType,
            name: name,
            nukiLocks: nukiLocks
        });
    } else {
        var self = this;
        startPairing(
            {appId: appId, appType: appType, name: name, nukiLocks: nukiLocks},
            function (err, pairingData) {
                if (err) {
                    console.log("Pairing failed:", err);
                } else {
                    console.log("Paired successfully.");
                    nukiLocks[pairingData.peripheralId] = {
                        nukiUuid: pairingData.nukiUuid,
                        nukiAuthorizationId: pairingData.nukiAuthorizationId,
                        sharedSecret: pairingData.sharedSecret
                    };
                    config.set("nukiLocks", nukiLocks);
                    config.save(function (err) {
                        if (err) {
                            console.log("Writing configuration failed", err);
                        } else {
                            // let thread finish before starting new command
                            setTimeout(function () {
                                reReadConfig.call(self);
                                processCommands.call(self, {
                                    appId: appId,
                                    appType: appType,
                                    name: name,
                                    nukiLocks: nukiLocks
                                });
                            }, 1000);
                        }
                    });
                }
            });
    }
}

function startPairing(options, callback) {
    var nuki = new nukible();
    nuki.pair(options, callback);
}

function processCommands(options) {
    var nuki = new nukible();
    // todo
    nuki.unlock(options, function (err) {
        if (err) {
            console.log("unlocking failed", err);
        } else {
            console.log("Ready.");
        }
    });
}
