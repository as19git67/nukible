var noble = require('noble');
var _ = require('underscore');
var crc = require('crc');
var sodium = require('sodium');
var HSalsa20 = require('./hsalsa20');
var crypto = require('crypto');

var nukible = module.exports = function (options) {
  this.options = {};

  if (options) {
    this.options.nukiLocks = options.nukiLocks || {};
    this.options.name = options.name; // name of nuki client
    this.options.appId = options.appId; // id of this nuki client
    this.options.appType = options.appType; // type of this nuki client
  }

  this.state = nukible.prototype.STATE_PAIRING_IDLE;

  this.initialize.apply(this, arguments);
};

// Attach all inheritable methods to the nukible prototype.
_.extend(nukible.prototype, {

      // Initialize is an empty function by default. Override it with your own
      // initialization logic.
      initialize: function () {
      },

      pair: function (options, callback) {
        if (options) {
          _.defaults(this.options, options);
        }
        this.isPaired = false;
        this.isInPairing = true;
        this.peripheralQueue = [];
        this.knownPeripherals = [];
        this.pairedPeripheralsId = Object.keys(options.nukiLocks);
        var self = this;

        function discontinue(err, results) {
          clearInterval(i);
          clearTimeout(t);

          noble.stopScanning();
          noble.removeAllListeners('discover');
          noble.removeAllListeners('stateChange');

          self.isInPairing = false;
          delete self.peripheralInProgress;

          if (_.isFunction(callback)) {
            callback(err, results);
          }
        }

        var i = setInterval(function () {
          if (!self.peripheralInProgress && self.peripheralQueue.length > 0) {
            self.peripheralInProgress = self.peripheralQueue.shift();
            self.knownPeripherals.push(self.peripheralInProgress.id);
            self._pairingOnPeripheralDiscovered.call(self, self.peripheralInProgress, function (err, result) {
              if (err) {
                self.isPaired = false;
                discontinue(err);
              } else {
                if (result && result.status) {
                  switch (result.status) {
                  case 'notInPairingMode':
                    console.log(self.peripheralInProgress.advertisement.localName +
                                " is not in pairing mode. Ignoring it.");
                    delete self.peripheralInProgress;
                    break;
                  case 'paired':
                    self.isPaired = true;
                    discontinue(null, result.results);
                    break;
                  case 'disconnected':
                    if (self.isPaired || !self.isInPairing) {
                      console.log("Peripheral disconnected.");
                    } else {
                      console.log("ERROR: peripheral disconnected during pairing.");
                    }
                    delete self.peripheralInProgress;
                    break;
                  default:
                    discontinue("ERROR: pairing failed for unknown reason");
                  }
                }
              }
            });
          }
        }, 100);
        var t = setTimeout(function () {
          clearInterval(i);
          console.log("Timeout. Aborting pairing.");
          noble.stopScanning();
          noble.removeAllListeners('discover');
          noble.removeAllListeners('stateChange');
          if (_.isFunction(callback)) {
            self.isInPairing = false;
            callback("pairing timeout");
          }
        }, 60000);
        if (noble.state == 'poweredOn') {
          noble.startScanning();
        }
        noble.on('stateChange', this._pairingOnStateChanged);
        noble.on('discover', function (peripheral) {
          if (_.contains(self.pairedPeripheralsId, peripheral.id)) {
            console.log("Ignoring already paired peripheral " + peripheral.id);
            return;
          }
          if (!peripheral.connectable) {
            console.log("Ignoring not connectable peripheral " + peripheral.id);
            return;
          }
          if (peripheral.advertisement.localName) { // Nuki locks have a name
            if (!_.contains(self.knownPeripherals, peripheral.id)) {
              console.log("Adding peripheral " + peripheral.advertisement.localName + " to try-to-pair queue");
              self.peripheralQueue.push(peripheral);
            }
          }
        });
      },

      prepareEncryptedDataToSend: function (cmd, authorizationId, sharedSecret, payload) {
        var nonce = new Buffer(24);
        sodium.api.randombytes_buf(nonce);

        var authIdBuffer = new Buffer(4);
        authIdBuffer.writeUInt32LE(authorizationId);
        var cmdBuffer = new Buffer(2);
        cmdBuffer.writeUInt16LE(cmd);

        var pDataWithoutCrc = Buffer.concat([authIdBuffer, cmdBuffer, payload]);
        var checksum = crc.crc16ccitt(pDataWithoutCrc);
        var checksumBuffer = new Buffer(2);
        checksumBuffer.writeUInt16LE(checksum);
        var pData = Buffer.concat([pDataWithoutCrc, checksumBuffer]);

        var pDataEncrypted = sodium.api.crypto_secretbox(pData, nonce, sharedSecret).slice(16); // skip first 16 bytes
        // console.log("encrypted message: ", pDataEncrypted);

        var lenBuffer = new Buffer(2);
        lenBuffer.writeUInt16LE(pDataEncrypted.length);

        var aData = Buffer.concat([nonce, authIdBuffer, lenBuffer]);

        // console.log("aData: ", aData);
        // console.log("pData: ", pData);

        return Buffer.concat([aData, pDataEncrypted]);

      },

  scan: function (options, callback) {
    if (options) {
      _.defaults(this.options, options);
    }
        var self = this;

    // only scan for devices advertising these service UUID's (default or empty array => any peripherals
    var serviceUuids = [/*nukible.prototype.nukiServiceUuid*/];

    // allow duplicate peripheral to be returned (default false) on discovery event
    var allowDuplicates = true;

    if (noble.state === 'poweredOn') {
      console.log("start scanning");
      noble.startScanning(serviceUuids, allowDuplicates);
    }
    var previousStateBuffer = new Buffer(0);
    noble.on('stateChange', this._onStateChanged);
    noble.on('discover',
        function (peripheral) {
          var peripheralId = peripheral.uuid;
          var lockPeripheralId = self.options.peripheralId;
          if (lockPeripheralId === peripheralId) {

            if (peripheral.advertisement.manufacturerData.length >= 24) {
              var serviceUUidStr = peripheral.advertisement.manufacturerData.slice(4, 4 + 16).toString('hex');
              if (serviceUUidStr === nukible.prototype.nukiServiceUuid) {
                var stateBuffer = peripheral.advertisement.manufacturerData.slice(4 + 16);
                if (!previousStateBuffer.equals(stateBuffer)) {
                  console.log("===========================");
                  console.log("Peripheral: " + peripheral.id + " with rssi " + peripheral.rssi + " has state: " +
                              stateBuffer.toString('hex'));
                  previousStateBuffer = stateBuffer;
                }
              }
            }

            // noble.stopScanning();
            // noble.removeAllListeners('discover');
            // noble.removeAllListeners('stateChange');
            // self._onPeripheralDiscovered.call(self, "getLockState", peripheral, function (err, result) {
            //   clearTimeout(t);
            //   if (err) {
            //     if (_.isFunction(callback)) {
            //       callback(err);
            //     }
            //   } else {
            //     if (result && result.status === 'complete') {
            //       if (_.isFunction(callback)) {
            //         callback(null);
            //       }
            //     } else {
            //       if (_.isFunction(callback)) {
            //         callback("ERROR: unknown");
            //       }
            //     }
            //   }
            // });
          }
        });
      },

      getLockState: function (options, callback) {
        if (options) {
          _.defaults(this.options, options);
        }
        var self = this;

        // only scan for devices advertising these service UUID's (default or empty array => any peripherals
        var serviceUuids = [/*nukible.prototype.nukiServiceUuid*/];

        // allow duplicate peripheral to be returned (default false) on discovery event
        var allowDuplicates = true;

        var t = setTimeout(function () {
          console.log("Timeout. Aborting getLockState.");
          noble.stopScanning();
          noble.removeAllListeners('discover');
          noble.removeAllListeners('stateChange');
          if (_.isFunction(callback)) {
            callback("getLockState timeout");
          }
        }, 30000);
        if (noble.state === 'poweredOn') {
          console.log("start scanning");
          noble.startScanning(serviceUuids, allowDuplicates);
        }
        var previousStateBuffer = new Buffer(0);
        noble.on('stateChange', this._onStateChanged);
        noble.on('discover',
            function (peripheral) {
              var peripheralId = peripheral.uuid;
              var lockPeripheralId = self.options.peripheralId;
              if (lockPeripheralId === peripheralId) {

                noble.stopScanning();
                noble.removeAllListeners('discover');
                noble.removeAllListeners('stateChange');
                self._onPeripheralDiscovered.call(self, "getLockState", peripheral, function (err, result) {
                  clearTimeout(t);
                  if (err) {
                    if (_.isFunction(callback)) {
                      callback(err);
                    }
                  } else {
                    if (result && result.status === 'complete') {
                      if (_.isFunction(callback)) {
                        callback(null);
                      }
                    } else {
                      if (_.isFunction(callback)) {
                        callback("ERROR: unknown");
                      }
                    }
                  }
                });
              }
            });
      },

      lock: function (options, callback) {
        if (options) {
          _.defaults(this.options, options);
        }
        var self = this;
        var t = setTimeout(function () {
          console.log("Timeout. Aborting lock.");
          noble.stopScanning();
          noble.removeAllListeners('discover');
          noble.removeAllListeners('stateChange');
          if (_.isFunction(callback)) {
            callback("lock timeout");
          }
        }, 30000);
        if (noble.state == 'poweredOn') {
          console.log("start scanning");
          noble.startScanning();
        }
        noble.on('stateChange', this._onStateChanged);
        noble.on('discover',
            function (peripheral) {
              var peripheralId = peripheral.uuid;
              var lockPeripheralId = self.options.peripheralId;
              if (lockPeripheralId === peripheralId) {

                noble.stopScanning();
                noble.removeAllListeners('discover');
                noble.removeAllListeners('stateChange');
                self._onPeripheralDiscovered.call(self, "lock", peripheral, function (err, result) {
                  clearTimeout(t);
                  if (err) {
                    if (_.isFunction(callback)) {
                      callback(err);
                    }
                  } else {
                    if (result && result.status === 'complete') {
                      if (_.isFunction(callback)) {
                        callback(null);
                      }
                    } else {
                      if (_.isFunction(callback)) {
                        callback("ERROR: unknown");
                      }
                    }
                  }
                });
              } else {
                console.log("ignoring peripheral with id " + peripheralId);
              }
            });
      },

      unlock: function (options, callback) {
        if (options) {
          _.defaults(this.options, options);
        }
        var self = this;
        var t = setTimeout(function () {
          console.log("Timeout. Aborting unlock.");
          noble.stopScanning();
          noble.removeAllListeners('discover');
          noble.removeAllListeners('stateChange');
          if (_.isFunction(callback)) {
            callback("unlock timeout");
          }
        }, 30000);
        if (noble.state == 'poweredOn') {
          console.log("start scanning");
          noble.startScanning();
        }
        noble.on('stateChange', this._onStateChanged);
        noble.on('discover',
            function (peripheral) {
              var peripheralId = peripheral.uuid;
              var lockPeripheralId = self.options.peripheralId;
              if (lockPeripheralId === peripheralId) {

                noble.stopScanning();
                noble.removeAllListeners('discover');
                noble.removeAllListeners('stateChange');
                self._onPeripheralDiscovered.call(self, "unlock", peripheral, function (err, result) {
                  clearTimeout(t);
                  if (err) {
                    if (_.isFunction(callback)) {
                      callback(err);
                    }
                  } else {
                    if (result && result.status === 'complete') {
                      if (_.isFunction(callback)) {
                        callback(null);
                      }
                    } else {
                      if (_.isFunction(callback)) {
                        callback("ERROR: unknown");
                      }
                    }
                  }
                });
              } else {
                console.log("ignoring peripheral with id " + peripheralId);
              }
            });
      },

      _pairingOnStateChanged: function (bleState) {
        if (bleState === 'poweredOn') {
          console.log('scanning for nuki.io Bluetooth LE services...');
          //noble.startScanning([nukible.prototype.nukiPairingServiceUuid, nukible.prototype.nukiServiceUuid], true);
          noble.startScanning();
        } else {
          noble.stopScanning();
        }
      },

      _pairingOnPeripheralDiscovered: function (peripheral, callback) {
        var self = this;
        //
        // The advertisment data contains a name, power level (if available),
        // certain advertised service uuids, as well as manufacturer data,
        // which could be formatted as an iBeacon.
        //

        var peripheralName = peripheral.advertisement.localName;
        var peripheralId = peripheral.uuid;

        console.log('Try to pair with peripheral:', peripheralName);

        //
        // Once the peripheral has been discovered, then connect to it.
        // It can also be constructed if the uuid is already known.
        ///
        peripheral.connect(function (err) {
          if (err) {
            console.log("ERROR while connecting " + peripheral.advertisement.localName);
            callback(err);
          } else {
            //
            // Once the peripheral has been connected, then discover the
            // services and characteristics of interest.
            //
            peripheral.discoverServices(
                [nukible.prototype.nukiPairingServiceUuid, nukible.prototype.nukiServiceUuid], function (err, services) {
                  self._pairingOnPeripheralServiceDiscovered.call(self, err, services, function (err, result) {
                    peripheral.disconnect();
                    if (!err && result && result.status === 'paired') {
                      result.results.peripheralId = peripheralId;
                    }
                    callback(err, result);
                  })
                });
          }
        });

        peripheral.disconnect(function () {
          callback(null, {status: 'disconnected'})
        });
      },

      _pairingOnPeripheralServiceDiscovered: function (err, services, callback) {
        if (err) {
          // console.log("discoverServices failed", err);
          callback(err);
        } else {
          var self = this;
          this.nukiPairingGeneralDataIOCharacteristic = null;
          this.nukiServiceGeneralDataIOCharacteristic = null;
          this.nukiUserSpecificDataInputOutputCharacteristic = null;

          services.forEach(function (service) {
            //
            // This must be the service we were looking for.
            //
            console.log('found service:', service.uuid);

            //
            // So, discover its characteristics.
            //
            service.discoverCharacteristics([], function (err, characteristics) {

              characteristics.forEach(function (characteristic) {
                //
                // Loop through each characteristic and match them to the
                // UUIDs that we know about.
                //
                console.log('Found characteristic:', characteristic.uuid);

                if (nukible.prototype.nukiPairingGeneralDataIOCharacteristicUuid == characteristic.uuid) {
                  self.nukiPairingGeneralDataIOCharacteristic = characteristic;
                }
                else if (nukible.prototype.nukiServiceGeneralDataIOCharacteristicUuid == characteristic.uuid) {
                  self.nukiServiceGeneralDataIOCharacteristic = characteristic;
                }
                else if (nukible.prototype.nukiUserSpecificDataInputOutputCharacteristicUuid == characteristic.uuid) {
                  self.nukiUserSpecificDataInputOutputCharacteristic = characteristic;
                }
              });

              //
              // Check to see if we found all of our characteristics.
              //
              if (self.nukiPairingGeneralDataIOCharacteristic &&
                  self.nukiServiceGeneralDataIOCharacteristic &&
                  self.nukiUserSpecificDataInputOutputCharacteristic) {
                console.log("All nuki.io characteristics that are needed for pairing were found.");

                self.state = nukible.prototype.STATE_PAIRING_CL_REQ_PUBKEY;

                self.nukiPairingGeneralDataIOCharacteristic.subscribe(function () {
                  self.nukiPairingGeneralDataIOCharacteristic.on('read', function (data, isNotification) {
                    self._dataReceivedDuringPairing.call(self, data, isNotification, function (err, status) {
                      if (err && _.isString(err)) {
                        err += " State: " + self.state;

                      }
                      if (err || status) {
                        self.state = nukible.prototype.STATE_PAIRING_IDLE;
                        self.nukiPairingGeneralDataIOCharacteristic.removeListener.call(self, 'read',
                            self._dataReceivedDuringPairing);
                        self.nukiPairingGeneralDataIOCharacteristic.unsubscribe();
                        callback(err, status);
                      }
                    });
                  });

                  var d = new Buffer(2);
                  d.writeUInt16LE(nukible.prototype.CMD_ID_PUBLIC_KEY);
                  var wCmdWithChecksum = self._prepareDataToSend.call(self, nukible.prototype.CMD_REQUEST_DATA, d);
                  self.nukiPairingGeneralDataIOCharacteristic.write(wCmdWithChecksum, false, function (err) {
                    if (err) {
                      console.log("ERROR: write CMD_ID_PUBLIC_KEY to nukiPairingGeneralDataIOCharacteristic failed", err);
                      self.nukiPairingGeneralDataIOCharacteristic.removeListener('read', self._dataReceivedDuringPairing);
                      callback(err);
                      // } else {
                      //     console.log("CL sent command to request SL PK");
                    }
                  });

                });
              }
            });
          });
        }
      },

      _onStateChanged: function (bleState) {
        if (bleState === 'poweredOn') {
          console.log('scanning for nuki.io Bluetooth LE services...');
          //noble.startScanning([nukible.prototype.nukiServiceUuid], true);
          noble.startScanning();
        } else {
          noble.stopScanning();
        }
      },

      _onPeripheralDiscovered: function (command, peripheral, callback) {
        var self = this;

        var peripheralName = peripheral.advertisement.localName;

        console.log('found peripheral:', peripheralName);

        if (peripheral.connectable) {
          peripheral.connect(function (err) {
            console.log("connected to peripheral");

            peripheral.discoverServices(
                [nukible.prototype.nukiServiceUuid], function (err, services) {
                  if (err) {
                    callback(err);
                  } else {

                    self._onPeripheralServiceDiscovered.call(self, command, peripheral, services,
                        function (err, result) {
                          peripheral.disconnect();
                          callback(err, result);
                        })
                  }
                });

          });
        } else {
          callback(peripheralName + " is not connectable");
        }
      },

      _onPeripheralServiceDiscovered: function (command, peripheral, services, callback) {
        var self = this;
        this._currentCommand = command;
        this.nukiGeneralDataIOCharacteristic = null;
        this.nukiUserSpecificDataInputOutputCharacteristic = null;

        services.forEach(function (service) {
          //
          // This must be the service we were looking for.
          //
          console.log('found service:', service.uuid);

          //
          // So, discover its characteristics.
          //
          service.discoverCharacteristics([], function (err, characteristics) {

            characteristics.forEach(function (characteristic) {
              //
              // Loop through each characteristic and match them to the
              // UUIDs that we know about.
              //
              console.log('Found characteristic:', characteristic.uuid);

              if (nukible.prototype.nukiServiceGeneralDataIOCharacteristicUuid == characteristic.uuid) {
                self.nukiServiceGeneralDataIOCharacteristic = characteristic;
              }
              else if (nukible.prototype.nukiUserSpecificDataInputOutputCharacteristicUuid == characteristic.uuid) {
                self.nukiUserSpecificDataInputOutputCharacteristic = characteristic;
              }
            });

            //
            // Check to see if we found all of our characteristics.
            //
            if (self.nukiServiceGeneralDataIOCharacteristic &&
                self.nukiUserSpecificDataInputOutputCharacteristic) {
              console.log("All nuki.io characteristics that are needed were found.");

              // we found a peripheral, stop scanning
              noble.stopScanning();

              self.nukiUserSpecificDataInputOutputCharacteristic.subscribe(function () {
                self.nukiUserSpecificDataInputOutputCharacteristic.on('read', function (data, isNotification) {
                  self._dataReceived.call(self, peripheral, data, isNotification, function (err, status) {
                    if (err && _.isString(err)) {
                      err += " State: " + self.state;
                    }
                    // status is set when overall action is finished
                    // if !err && !status then further data is expected to be received
                    if (err || status) {
                      self.nukiUserSpecificDataInputOutputCharacteristic.removeListener.call(self, 'read',
                          self._dataReceived);
                      self.nukiUserSpecificDataInputOutputCharacteristic.unsubscribe();
                      callback(err, status);
                    }
                  });
                });

                switch (self._currentCommand) {
                case 'lock':
                  var peripheralId = peripheral.uuid;
                  var lock = self.options.nukiLock;
                  if (lock) {
                    var sharedSecret = new Buffer(lock.sharedSecret, 'hex');
                    self._requestNonceFromSL(lock.nukiAuthorizationId, sharedSecret, function (err, nonceK) {
                          if (err) {
                            peripheral.disconnect();
                            callback(err);
                          } else {

                            // console.log("Nonce received from SL:", nonceK);
                            var data1 = new Buffer(6);
                            data1.writeUInt8(2, 0); // 0x02 is lock
                            data1.writeUInt32LE(self.options.appId, 1);
                            data1.writeUInt8(0, 5); // no flags set
                            var wData = Buffer.concat([data1, nonceK]);
                            var wDataEncrypted = self.prepareEncryptedDataToSend(
                                nukible.prototype.CMD_LOCK_ACTION,
                                lock.nukiAuthorizationId,
                                sharedSecret,
                                wData);

                            self.nukiUserSpecificDataInputOutputCharacteristic.write(wDataEncrypted, false, function (err) {
                              if (err) {
                                console.log("ERROR: failed to send encrypted message for CMD_LOCK_ACTION");
                                peripheral.disconnect();
                                callback(err);
                              }
                            });

                            //                                                callback(null, {status: 'unlocked'});
                          }
                        }
                    );
                  } else {
                    callback("Not paired with this lock. Peripheral UUID is " + peripheralId);
                  }
                  break;
                case 'unlock':
                  var peripheralId = peripheral.uuid;
                  var lock = self.options.nukiLock;
                  if (lock) {
                    var sharedSecret = new Buffer(lock.sharedSecret, 'hex');
                    self._requestNonceFromSL(lock.nukiAuthorizationId, sharedSecret, function (err, nonceK) {
                          if (err) {
                            peripheral.disconnect();
                            callback(err);
                          } else {

                            // console.log("Nonce received from SL:", nonceK);
                            var data1 = new Buffer(6);
                            data1.writeUInt8(1, 0); // 0x01 is unlock
                            data1.writeUInt32LE(self.options.appId, 1);
                            data1.writeUInt8(0, 5); // no flags set
                            var wData = Buffer.concat([data1, nonceK]);
                            var wDataEncrypted = self.prepareEncryptedDataToSend(
                                nukible.prototype.CMD_LOCK_ACTION,
                                lock.nukiAuthorizationId,
                                sharedSecret,
                                wData);

                            self.nukiUserSpecificDataInputOutputCharacteristic.write(wDataEncrypted, false, function (err) {
                              if (err) {
                                console.log("ERROR: failed to send encrypted message for CMD_LOCK_ACTION");
                                peripheral.disconnect();
                                callback(err);
                              }
                            });

                            //                                                callback(null, {status: 'unlocked'});
                          }
                        }
                    );
                  } else {
                    callback("Not paired with this lock. Peripheral UUID is " + peripheralId);
                  }
                  break;
                case 'getLockState':
                  var lock = self.options.nukiLock;
                  if (lock) {
                    var sharedSecret = new Buffer(lock.sharedSecret, 'hex');
                    self._requestNonceFromSL(lock.nukiAuthorizationId, sharedSecret, function (err, nonceK) {
                          if (err) {
                            peripheral.disconnect();
                            callback(err);
                          } else {
                            var data1 = new Buffer(6);
                            data1.writeUInt8(2, 0); // 0x02 is lock
                            data1.writeUInt32LE(self.options.appId, 1);
                            data1.writeUInt8(0, 5); // no flags set
                            var wData = Buffer.concat([data1, nonceK]);
                            var wDataEncrypted = self.prepareEncryptedDataToSend(
                                nukible.prototype.CMD_NUKI_STATES,
                                lock.nukiAuthorizationId,
                                sharedSecret,
                                wData);

                            self.nukiUserSpecificDataInputOutputCharacteristic.write(wDataEncrypted, false, function (err) {
                              if (err) {
                                console.log("ERROR: failed to send encrypted message for CMD_NUKI_STATES");
                                peripheral.disconnect();
                                callback(err);
                              }
                            });
                          }
                        }
                    );
                  } else {
                    callback("Not paired with this lock. Peripheral UUID is " + peripheral.uuid);
                  }
                  break;
                default:
                  callback("Command (" + self._currentCommand + ") not implemented");
                  self._currentCommand = undefined;
                }

              });
            }
          });
        });
      },

      _requestNonceFromSL: function (authorizationId, sharedSecret, callback) {
        this.receivedData = new Buffer(0);
        var wData = new Buffer(2);
        wData.writeUInt16LE(nukible.prototype.CMD_CHALLENGE, 0); // request a challenge

        var wDataEncrypted = this.prepareEncryptedDataToSend(
            nukible.prototype.CMD_REQUEST_DATA,
            authorizationId,
            sharedSecret,
            wData);

        this.callbackForChallenge = callback;
        var self = this;
        // console.log("_requestNonceFromSL: encrypted data", wDataEncrypted);
        this.nukiUserSpecificDataInputOutputCharacteristic.write(wDataEncrypted, false, function (err) {
          if (err) {
            console.log("ERROR: failed to send encrypted message when requesting new challenge from SL");
            self.callbackForChallenge = undefined;
            callback(err);
          }
        });
      },

      _dataReceived: function (peripheral, data, isNotification, callback) {
        // console.log("DATA received", data);
        this.receivedData = Buffer.concat([this.receivedData, data]);

        if (data.length < 20) {     // hack
          if (this._crcOk(this.receivedData)) {
            var tmpCmdId = this.receivedData.readUInt16LE();
            switch (tmpCmdId) {
            case nukible.prototype.CMD_ERROR:
              var errorCode = this.receivedData.readUInt8(2);
              var errorCodeStr = errorCode.toString();
              switch (errorCode) {
              case nukible.prototype.K_ERROR_BAD_PIN:
                errorCodeStr = "K_ERROR_BAD_PIN";
                break;
              case nukible.prototype.K_ERROR_BAD_NONCE:
                errorCodeStr = "K_ERROR_BAD_NONCE";
                break;
              case nukible.prototype.K_ERROR_BAD_PARAMETER:
                errorCodeStr = "K_ERROR_BAD_PARAMETER";
                break;
              }
              this.receivedData = new Buffer(0);
              callback("ERROR reported from SL: " + errorCodeStr);
              return;
            case nukible.prototype.CMD_STATUS:
              var status = this.receivedData.readUInt8(2);
              switch (status) {
              case nukible.prototype.STATUS_ACCEPTED:
                console.log("SL sent STATUS_ACCEPTED");
                break;
              case nukible.prototype.STATUS_COMPLETE:
                console.log("SL sent STATUS_COMPLETE");
                callback(null, {status: 'complete'});
              }
              this.receivedData = new Buffer(0);
              return;
            }
          }
          var nonceK = this.receivedData.slice(0, 24);
          // var authorizationId = this.receivedData.readUInt32LE(24);
          // var messageLen = this.receivedData.readUInt16LE(28);
          var encryptedMessage = this.receivedData.slice(30);
          var peripheralId = peripheral.uuid;
          var lock = this.options.nukiLock;
          if (lock) {
            if (lock.sharedSecret) {
              var sharedSecret = new Buffer(lock.sharedSecret, 'hex');

              var prefixBuff = new Buffer(16);
              prefixBuff.fill(0);

              var decryptedMessge = sodium.api.crypto_secretbox_open(Buffer.concat([prefixBuff, encryptedMessage]), nonceK,
                  sharedSecret);

              if (this._crcOk(decryptedMessge)) {
                // console.log("CRC ok. Decrypted Message:", decryptedMessge);

                var authorizationId = decryptedMessge.readUInt32LE(0);
                if (authorizationId === lock.nukiAuthorizationId) {
                  var cmdId = decryptedMessge.readUInt16LE(4);
                  var payload = decryptedMessge.slice(6, decryptedMessge.length - 2);
                  switch (cmdId) {
                  case nukible.prototype.CMD_CHALLENGE:
                    // console.log("CHALLENGE received:", payload, payload.length);
                    if (this.callbackForChallenge) {
                      this.callbackForChallenge(null, payload);
                    }
                    break;
                  case nukible.prototype.CMD_NUKI_STATES:
                    // console.log("NUKI STATES", payload, payload.length);
                    var lockState = payload.readUInt8(1);
                    var lockStateStr = "unknown";
                    switch (lockState) {
                    case 1: // locked
                      lockStateStr = "locked";
                      break;
                    case 2: // unlocking
                      lockStateStr = "unlocking";
                      break;
                    case 3: // unlocked
                      lockStateStr = "unlocked";
                      break;
                    case 4: // locking
                      lockStateStr = "locking";
                      break;
                    case 5: //unlatched
                      lockStateStr = "unlatched";
                      break;
                    case 6: // unlocked (lock'n'go)
                      lockStateStr = "unlocked - lock'n'go";
                      break;
                    }
                    console.log("State of lock (" + lock.nukiUuid + ") is " + lockStateStr);
                    break;
                  case nukible.prototype.CMD_STATUS:
                    var status = payload.readUInt8(0);
                    console.log("SL sent status " + status.toString(16));
                    if (status === nukible.prototype.STATUS_COMPLETE) {
                      console.log("calling callback with status complete");
                      callback(null, {status: 'complete'});
                    } else {
                      if (status === nukible.prototype.STATUS_ACCEPTED) {
                        console.log("SL sent status accepted");
                      } else {
                        callback("ERROR: SL sent STATUS not complete");
                      }
                    }
                    break;
                  default:
                    console.log("UNKNOWN message:", decryptedMessge);
                    callback("ERROR: message received but not expected");
                  }
                } else {
                  console.log("ignoring data for other authorization-id (" + authorizationId + ")");
                }
              } else {
                callback("Wrong CRC.");
              }
            } else {
              callback("ERROR: don't have sharedSecret for lock with uuid " + lock.nukiUuid);
            }
          } else {
            callback("Not paired with this lock. Peripheral UUID is " + peripheralId);
          }
          this.receivedData = new Buffer(0);
        }
      },

      _makeKeyBuffer: function (inKey) {
        var keyAsBuffer = new Buffer(0);
        if (_.isString(inKey)) {
          keyAsBuffer = new Buffer(inKey, 'hex');
        } else {
          if (_.isArray(inKey)) {
            keyAsBuffer = new Buffer(inKey);
          }
        }
        return keyAsBuffer;
      },

      _prepareDataToSend: function (cmd, data) {
        var cmdBuffer = new Buffer(2);
        cmdBuffer.writeUInt16LE(cmd);
        var responseData = Buffer.concat([cmdBuffer, data]);
        var checksum = crc.crc16ccitt(responseData);
        var checksumBuffer = new Buffer(2);
        checksumBuffer.writeUInt16LE(checksum);
        var dataToSend = Buffer.concat([responseData, checksumBuffer]);
        return dataToSend;
      },

      _crcOk: function (dataTocheck) {
        if (dataTocheck) {
          var dataForCrc = dataTocheck.slice(0, dataTocheck.length - 2);
          var crcSumCalc = crc.crc16ccitt(dataForCrc);
          var crcSumRetrieved = dataTocheck.readUInt16LE(dataTocheck.length - 2);
          return crcSumCalc === crcSumRetrieved;
        } else {
          console.log("CRC check failed. DataToCheck is null");
          return false;
        }
      },

      _dataReceivedDuringPairing: function (data, isNotification, callback) {
        var rCmd, r, authenticator;
        var self = this;
        // console.log('response from nuki', data, isNotification);
        switch (this.state) {
        case nukible.prototype.STATE_PAIRING_CL_REQ_PUBKEY:
          // if (this._crcOk(data)) {
          rCmd = data.readUInt16LE(0);
          if (rCmd === nukible.prototype.CMD_ID_PUBLIC_KEY) {
            console.log("Step 4: SL sent first part of public key...");
            this.state = nukible.prototype.STATE_PAIRING_CL_REQ_PUBKEY_FIN;
            this.rData = data;
          } else {
            if (rCmd === nukible.prototype.CMD_ERROR) {
              var errorCode = data.readUInt8(2);
              var errorCommandId = data.readUInt16LE(3);
              switch (errorCode) {
              case nukible.prototype.P_ERROR_NOT_PAIRING:
                //callback("ERROR: public key is being requested via request data command, but keyturner is not in pairing mode");
                callback(null, {status: 'notInPairingMode'});
                break;
              default:
                callback("ERROR from SL: " + errorCode.toString(16));
              }
            } else {
              callback("ERROR: not expected command id " + rCmd);
            }
          }
          // } else {
          //     callback("ERROR: wrong CRC");
          // }
          break;
        case nukible.prototype.STATE_PAIRING_CL_REQ_PUBKEY_FIN:
          this.rData = Buffer.concat([this.rData, data]);
          if (this._crcOk(this.rData)) {
            rCmd = this.rData.readUInt16LE(0);
            if (rCmd === nukible.prototype.CMD_ID_PUBLIC_KEY) {
              this.slPubKey = this.rData.slice(2, this.rData.length - 2);
              console.log("Step 4: SL sent PK:");

              console.log("Step 5: creating new CL key pair...");

              var clKeys = new sodium.Key.ECDH();
              this.clSk = clKeys.sk().get();
              this.clPk = clKeys.pk().get();

              console.log("Step 7: creating diffie-hellman key...");
              // create a Diffie Hellman key out of the clients secret key and the nukis public key
              // crypto_scalarmult_curve25519(s,sk,pk)
              var k = sodium.api.crypto_scalarmult(self.clSk, self.slPubKey);
              // console.log("CL DH Key from CL SK and SL PK: ", k);

              console.log("Step 8: derive long term shared key...");
              // derive a longterm shared secret key s from k using function kdf1
              // static const unsigned char _0[16];
              // static const unsigned char sigma[16] = "expand 32-byte k";
              // crypto_core_hsalsa20(k,_0,s,sigma)
              var hsalsa20 = new HSalsa20();
              this.options.sharedSecret = new Buffer(32);
              var inv = new Buffer(16);
              inv.fill(0);
              var c = new Buffer("expand 32-byte k");
              hsalsa20.crypto_core(this.options.sharedSecret, inv, k, c);
              // console.log("derived shared key: ", this.options.sharedSecret);

              this.state = nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE;
              console.log("Step 6: CL sending PK...");

              var wDataWithCrc = this._prepareDataToSend(nukible.prototype.CMD_ID_PUBLIC_KEY, this.clPk);
              this.nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, callback);
            } else {
              callback("ERROR: not expected command id " + rCmd);
            }
          } else {
            callback("ERROR: wrong CRC");
          }
          break;
        case nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE:
          rCmd = data.readUInt16LE(0);
          if (rCmd === nukible.prototype.CMD_CHALLENGE) {
            console.log("Step 9: SL sent first part of challenge...");
            this.state = nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE_FIN;
            this.rData = data;
          } else {
            callback("ERROR: not expected command id " + rCmd + ".");
          }
          break;
        case nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE_FIN:
          this.rData = Buffer.concat([this.rData, data]);
          if (this._crcOk(this.rData)) {
            rCmd = this.rData.readUInt16LE(0);
            if (rCmd === nukible.prototype.CMD_CHALLENGE) {
              this.nonceK = this.rData.slice(2, this.rData.length - 2);
              console.log("Step 9: SL sent challenge.");

              console.log("Step 10: CL creates r from CL PK, SL PK and nonceK");
              r = Buffer.concat([this.clPk, this.slPubKey, this.nonceK]);

              console.log("Step 11: CL creates authenticator from r");
              // use HMAC-SHA256 to create the authenticator
              authenticator = crypto.createHmac('SHA256', this.options.sharedSecret).update(r).digest();
              console.log("Step 13: CL sends authorization authenticator...");

              this.state = nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE_2;

              wDataWithCrc = this._prepareDataToSend(nukible.prototype.CMD_AUTHORIZATION_AUTHENTICATOR, authenticator);
              this.nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, callback);
            } else {
              callback("ERROR: not expected command id " + rCmd + ".");
            }
          } else {
            callback("ERROR: wrong CRC.");
          }
          break;
        case nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE_2:
          rCmd = data.readUInt16LE(0);
          if (rCmd === nukible.prototype.CMD_CHALLENGE) {
            console.log("Step 15a: SL sent first part of challenge.");
            this.state = nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE_2_FIN;
            this.rData = data;
          } else {
            callback("ERROR: not expected command id " + rCmd + ".");
          }
          break;
        case nukible.prototype.STATE_PAIRING_CL_REQ_CHALLENGE_2_FIN:
          this.rData = Buffer.concat([this.rData, data]);
          if (this._crcOk(this.rData)) {
            rCmd = this.rData.readUInt16LE(0);
            if (rCmd === nukible.prototype.CMD_CHALLENGE) {
              this.nonceK = this.rData.slice(2, this.rData.length - 2);
              this.rData = new Buffer(0);
              console.log("Step 15b: SL sent challenge.");

              console.log("Step 16a: creating authorization data...");
              var ids = new Buffer(5);
              ids.writeUInt8(this.options.appType); // ID type: 2: Fob
              ids.writeUInt32LE(this.options.appId, 1);

              var nameBuffer = new Buffer(32).fill(' ');
              var name = new Buffer(this.options.name);
              if (name.length > nameBuffer.length) {
                name.copy(nameBuffer, 0, 0, nameBuffer.length);
              } else {
                name.copy(nameBuffer, 0, 0, name.length);
              }
              this.nonceABF = new Buffer(nukible.prototype.NUKI_NONCEBYTES);
              sodium.api.randombytes_buf(this.nonceABF);

              // create authenticator for the authorization data message
              r = Buffer.concat([ids, nameBuffer, this.nonceABF, this.nonceK]);
              // use HMAC-SHA256 to create the authenticator
              authenticator = crypto.createHmac('SHA256', this.options.sharedSecret).update(r).digest();

              var wData = Buffer.concat([authenticator, ids, nameBuffer, this.nonceABF]);
              wDataWithCrc = this._prepareDataToSend(nukible.prototype.CMD_AUTHORIZATION_DATA, wData);
              // console.log("CL sending authorization data", wDataWithCrc);
              console.log("Step 16b: sending authorization data...");
              this.state = nukible.prototype.STATE_PAIRING_SL_SEND_AUTH_ID;
              this.nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, callback);
            } else {
              callback("ERROR: not expected command id " + rCmd + ".");
            }
          } else {
            callback("ERROR: wrong CRC.");
          }
          break;
        case nukible.prototype.STATE_PAIRING_SL_SEND_AUTH_ID:
          this.rData = Buffer.concat([this.rData, data]);
          if (this.rData.length >= 88) {
            if (this._crcOk(this.rData)) {
              rCmd = this.rData.readUInt16LE(0);
              if (rCmd === nukible.prototype.CMD_AUTHORIZATION_ID) {
                console.log("Step 19: SL sent authorization id");
                this.rData = this.rData.slice(2, this.rData.length - 2);
                var slAuthenticator = this.rData.slice(0, 32);
                var authorizationIdBuffer = this.rData.slice(32, 32 + 4);
                var authorizationId = authorizationIdBuffer.readUInt32LE();
                var slUuid = this.rData.slice(36, 36 + 16);
                this.nonceK = this.rData.slice(36 + 16, 36 + 16 + 32);

                // console.log("SL sent authenticator", slAuthenticator);
                console.log("SL sent authorization-id " + authorizationId);
                console.log("SL sent slUuid", slUuid.toString('hex'));

                this.results = {
                  nukiUuid: slUuid.toString('hex'),
                  nukiAuthorizationId: authorizationId,
                  sharedSecret: this.options.sharedSecret.toString('hex')
                };

                console.log("Step 20: verifying authenticator...");
                r = Buffer.concat([authorizationIdBuffer, slUuid, this.nonceK, this.nonceABF]);
                // use HMAC-SHA256 to create the authenticator
                var cr = crypto.createHmac('SHA256', this.options.sharedSecret).update(r).digest();

                if (Buffer.compare(slAuthenticator, cr) === 0) {
                  console.log("Step 20: authenticator verified ok.");

                  console.log("Step 21: CL creating authorization-id confirmation message...");
                  r = Buffer.concat([authorizationIdBuffer, this.nonceK]);
                  // use HMAC-SHA256 to create the authenticator
                  authenticator = crypto.createHmac('SHA256', this.options.sharedSecret).update(r).digest();

                  wData = Buffer.concat([authenticator, authorizationIdBuffer]);
                  wDataWithCrc = this._prepareDataToSend(nukible.prototype.CMD_AUTHORIZATION_ID_CONFIRMATION, wData);
                  console.log("Step 21: sending authorization-id confirmation...");
                  this.state = nukible.prototype.STATE_PAIRING_SL_SEND_STATUS_COMLETE;
                  this.nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, function (err) {
                    if (err) {
                      callback(err);
                    } else {
                      self.rData = new Buffer(0);
                      // console.log("CL Authorization-ID confirmation sent");
                    }
                  });
                } else {
                  callback("CL and SL authenticators are not equal. Possible man in the middle attack.");
                }

              } else {
                callback("ERROR: not expected command id " + rCmd + ".");
              }
            } else {
              callback("ERROR: wrong CRC.");
            }
          }
          break;
        case nukible.prototype.STATE_PAIRING_SL_SEND_STATUS_COMLETE:
          if (this._crcOk(data)) {
            rCmd = data.readUInt16LE(0);
            if (rCmd === nukible.prototype.CMD_STATUS) {
              console.log("Step 22: SL sent status complete.");
              callback(null, {status: 'paired', results: this.results});
            } else {
              callback("ERROR: not expected command id " + rCmd + ".");
            }
          } else {
            callback("ERROR: wrong CRC.");
          }
          break;
        default:
          callback("ERROR: undefined state " + this.state);
        }
      },

      // Nuki protocol constants
      CMD_REQUEST_DATA: 0x01,
      CMD_ID_PUBLIC_KEY: 0x03,
      CMD_CHALLENGE: 0x04,
      CMD_AUTHORIZATION_AUTHENTICATOR: 0x05,
      CMD_AUTHORIZATION_DATA: 0x06,
      CMD_AUTHORIZATION_ID: 0x07,
      CMD_AUTHORIZATION_ID_CONFIRMATION: 0x1E,
      CMD_REMOVE_AUTHORIZATION_ENTRY: 0x08,
      CMD_AUTHORIZATION_DATA_INVITE: 0x0B,
      CMD_NUKI_STATES: 0x0C,
      CMD_LOCK_ACTION: 0x0D,
      CMD_STATUS: 0x0E,
      CMD_ERROR: 0x12,
      CMD_SET_CONFIG: 0x13,
      CMD_REQUEST_CONFIG: 0x14,
      CMD_CONFIG: 0x15,
      CMD_REQUEST_CALIBRATION: 0x1A,
      CMD_VERIFY_PIN: 0x20,
      CMD_UPDATE_TIME: 0x21,

      STATUS_COMPLETE: 0x00,
      STATUS_ACCEPTED: 0x01,

      P_ERROR_NOT_PAIRING: 0x10,
      P_ERROR_BAD_AUTHENTICATOR: 0x11,
      P_ERROR_BAD_PARAMETER: 0x12,
      P_ERROR_MAX_USER: 0x13,

      K_ERROR_BAD_PIN: 0x21,
      K_ERROR_BAD_NONCE: 0x22,
      K_ERROR_BAD_PARAMETER: 0x23,

      ERROR_BAD_CRC: 0xFD,
      ERROR_BAD_LENGTH: 0xFE,
      ERROR_UNKNOWN: 0xFF,
      NUKI_NONCEBYTES: 32,

      nukiPairingServiceUuid: 'a92ee100550111e4916c0800200c9a66',
      nukiServiceUuid: 'a92ee200550111e4916c0800200c9a66',
      nukiPairingGeneralDataIOCharacteristicUuid: 'a92ee101550111e4916c0800200c9a66',
      nukiServiceGeneralDataIOCharacteristicUuid: 'a92ee201550111e4916c0800200c9a66',
      nukiUserSpecificDataInputOutputCharacteristicUuid: 'a92ee202550111e4916c0800200c9a66',

      STATE_PAIRING_IDLE: 0,
      STATE_PAIRING_CL_REQ_PUBKEY: 1,
      STATE_PAIRING_CL_REQ_PUBKEY_FIN: 2,
      STATE_PAIRING_CL_REQ_CHALLENGE: 3,
      STATE_PAIRING_CL_REQ_CHALLENGE_FIN: 4,
      STATE_PAIRING_CL_REQ_CHALLENGE_2: 5,
      STATE_PAIRING_CL_REQ_CHALLENGE_2_FIN: 6,
      STATE_PAIRING_SL_SEND_AUTH_ID: 7,
      STATE_PAIRING_SL_SEND_STATUS_COMLETE: 8
    }
);

// Helpers
// -------

// Helper function to correctly set up the prototype chain, for subclasses.
// Similar to `goog.inherits`, but uses a hash of prototype properties and
// class properties to be extended.
var extend = function (protoProps, staticProps) {
  var parent = this;
  var child;

  // The constructor function for the new subclass is either defined by you
  // (the "constructor" property in your `extend` definition), or defaulted
  // by us to simply call the parent's constructor.
  if (protoProps && _.has(protoProps, 'constructor')) {
    child = protoProps.constructor;
  } else {
    child = function () {
      return parent.apply(this, arguments);
    };
  }

  // Add static properties to the constructor function, if supplied.
  _.extend(child, parent, staticProps);

  // Set the prototype chain to inherit from `parent`, without calling
  // `parent`'s constructor function.
  var Surrogate = function () {
    this.constructor = child;
  };
  Surrogate.prototype = parent.prototype;
  child.prototype = new Surrogate();

  // Add prototype properties (instance properties) to the subclass,
  // if supplied.
  if (protoProps) {
    _.extend(child.prototype, protoProps);
  }

  // Set a convenience property in case the parent's prototype is needed
  // later.
  child.__super__ = parent.prototype;

  return child;
};

nukible.extend = extend;
