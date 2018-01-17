var _ = require('underscore');
var fs = require('fs');
var path = require('path');
var nconf = require('nconf');
var nukible = require('./../nukible');
var sodium = require('sodium');
var keypress = require('keypress');

var config = new nconf.Provider({
  env: true,
  argv: true,
  store: {
    type: 'file',
    file: path.join(__dirname, 'config.json')
  }
});

var nuki = new nukible();
var appId = config.get('appId');
var appType = config.get('appType');
var name = config.get('name');
var nukiLocks = config.get('nukiLocks');

if (_.isNumber(appId) && _.isNumber(appType) && _.isString(name)) {
  handleKeyboard();
} else {
  var self = this;
  var appIdBuffer = new Buffer(4);
  sodium.api.randombytes_buf(appIdBuffer);

  appId = appIdBuffer.readUInt32LE();
  config.set("appId", appId);
  config.set("appType", 2);   // Nuki Fob
  config.set("name", "HB Sample Key " + appId);
  config.set("nukiLocks", {});
  config.save(function (err) {
    if (err) {
      console.log("Writing configuration failed", err);
    } else {
      reReadConfig.call(self);
      console.log("initial configuration saved");
      handleKeyboard();
    }
  });
}

function handleKeyboard() {

  var peripheralId;
  var firstLock;

  var nukiLockUuids = _.keys(nukiLocks);
  if (nukiLockUuids.length > 0) {
    peripheralId = _.first(nukiLockUuids);
    firstLock = nukiLocks[peripheralId];
  }

  // make `process.stdin` begin emitting "keypress" events
  keypress(process.stdin);

  // listen for the "keypress" event
  var allowCommands = true;

  function showUsage() {
    console.log("q: exit");
    if (isPaired()) {
      console.log("l: lock");
      console.log("u: unlock");
      console.log("i: get nuki states");
      console.log("n: scan for nuki state change and get info if changed");
      console.log("s: stop scan for nuki state changes and allow other commands again")
    } else {
      console.log("p: pair");
    }
  }

  showUsage();
  process.stdin.on('keypress', function (ch, key) {
    //console.log('got "keypress"', key);
    if (key) {
      if (key.ctrl && key.name === 'c') {
        process.stdin.pause();
        process.exit();
      } else {
        if (allowCommands || key.name === 'q' || key.name === 's') {
          switch (key.name) {
          case 'p':
            if (!isPaired()) {
              console.log("Start pairing with NUKI lock. Make sure NUKI is in pairing mode.");
              allowCommands = false;
              startPairing(function (err, pairedLockData) {
                allowCommands = true;
                showUsage();
              });
            }
            break;
          case 'n':
            if (isPaired()) {
              allowCommands = false;
              options = {
                appId: appId,
                appType: appType,
                name: name,
                nukiLock: firstLock,
                peripheralId: peripheralId,
                bridgeReadsFirst: true // set to false if you don't have a nuki bridge
              };
              console.log("Start scanning for nuki state changes...");
              nuki.scanForLockStateChanges(options, function (err, data) {
                if (err) {
                  console.log("ERROR: scanning for nuki lock state change failed", err);
                  allowCommands = true;
                  showUsage();
                } else {
                  console.log("Got nuki states: ", data);
                }
              });
            }
            break;
          case 's':
            if (!allowCommands) {
              console.log("Stopping scan for nuki state changes...");
              nuki.stopScanForLockStateChanges();
              allowCommands = true;
            }
            showUsage();
            break;
          case 'i':
            if (isPaired()) {
              allowCommands = false;
              options = {
                appId: appId,
                appType: appType,
                name: name,
                nukiLock: firstLock,
                peripheralId: peripheralId
              };
              console.log("Getting nuki states...");
              nuki.getNukiStates(options, function (err, data) {
                if (err) {
                  console.log("ERROR: getNukiStates failed", err);
                } else {
                  console.log(data);
                }
                allowCommands = true;
                showUsage();
              });
            }
            break;
          case 'l':
            if (isPaired()) {
              allowCommands = false;
              options = {
                appId: appId,
                appType: appType,
                name: name,
                nukiLock: firstLock,
                peripheralId: peripheralId
              };
              console.log("Locking...");
              nuki.lock(options, function (err) {
                if (err) {
                  console.log("ERROR: locking the door failed", err);
                } else {
                  console.log("DOOR LOCKED.");
                }
                allowCommands = true;
                showUsage();
              });
            }
            break;
          case 'u':
            if (isPaired()) {
              allowCommands = false;
              options = {
                appId: appId,
                appType: appType,
                name: name,
                nukiLock: firstLock,
                peripheralId: peripheralId
              };
              console.log("Unlocking...");
              nuki.unlock(options, function (err) {
                if (err) {
                  console.log("ERROR: unlocking the door failed", err);
                } else {
                  console.log("DOOR UNLOCKED.");
                }
                allowCommands = true;
                showUsage();
              });
            }
            break;
          case 'q':
            process.exit();
            break;
          }
        } else {
          console.log("previous command not finished");
        }
      }

    }
  });

  process.stdin.setRawMode(true);
  process.stdin.resume();
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

function startPairing(callback) {
  var options = {
    appId: appId, appType: appType, name: name, nukiLocks: nukiLocks
  };

  nuki.pair(options, function (err, pairingData) {
    if (err) {
      console.log("Pairing failed:", err);
      callback(err);
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
          callback(err);
        } else {
          callback(null, nukiLocks[pairingData.peripheralId]);
        }
      });
    }
  });
}
