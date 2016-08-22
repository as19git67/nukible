var fs = require('fs');
var path = require('path');
var nconf = require('nconf');
var noble = require('noble');
var _ = require('underscore');
var crc = require('crc');
var sodium = require('sodium');
var HSalsa20 = require('./hsalsa20');
var crypto = require('crypto');

var config = new nconf.Provider({
    env: true,
    argv: true,
    store: {
        type: 'file',
        file: path.join(__dirname, 'config.json')
    }
});

var FobId = config.get('FobId');
if (!FobId) {
    FobId = 19670901;
    config.set("FobId", FobId);
    config.set("name", "HB NFC Key");
    config.set("useSampleKeys", false);
    config.save(function (err) {
        if (err) {
            console.log("Writing configuration failed", err);
        } else {
            // intial configuration saved
        }
    });
}
var useSampleKeys = config.get('useSampleKeys', false);

// Nuki protocol constants
var CMD_REQUEST_DATA = 0x01;
var CMD_ID_PUBLIC_KEY = 0x03;
var CMD_CHALLENGE = 0x04;
var CMD_AUTHORIZATION_AUTHENTICATOR = 0x05;
var CMD_AUTHORIZATION_DATA = 0x06;
var CMD_AUTHORIZATION_ID = 0x07;
var CMD_AUTHORIZATION_ID_CONFIRMATION = 0x1E;
var CMD_STATUS = 0x0E;

var STATUS_COMPLETE = 0x00;
var STATUS_ACCEPTED = 0x01;

var NUKI_NONCEBYTES = 32;


var nukiPairingServiceUuid = 'a92ee100550111e4916c0800200c9a66';
var nukiServiceUuid = 'a92ee200550111e4916c0800200c9a66';
var nukiPairingGeneralDataIOCharacteristicUuid = 'a92ee101550111e4916c0800200c9a66';
var nukiServiceGeneralDataIOCharacteristicUuid = 'a92ee201550111e4916c0800200c9a66';
var nukiUserSpecificDataInputOutputCharacteristicUuid = 'a92ee202550111e4916c0800200c9a66';

var nukiPairingGeneralDataIOCharacteristic;
var nukiServiceGeneralDataIOCharacteristic;
var nukiUserSpecificDataInputOutputCharacteristic;

var STATE_PAIRING_IDLE = 0;
var STATE_PAIRING_CL_REQ_PUBKEY = 1;
var STATE_PAIRING_CL_REQ_PUBKEY_FIN = 2;
var STATE_PAIRING_CL_REQ_CHALLENGE = 3;
var STATE_PAIRING_CL_REQ_CHALLENGE_FIN = 4;
var STATE_PAIRING_CL_REQ_CHALLENGE_2 = 5;
var STATE_PAIRING_CL_REQ_CHALLENGE_2_FIN = 6;
var STATE_PAIRING_SL_SEND_AUTH_ID = 7;
var STATE_PAIRING_SL_SEND_STATUS_COMLETE = 8;

var state = STATE_PAIRING_IDLE;

var clSk;
var clPk;
var slPubKey;
var sharedSecret;
var authenticator;
var nonceK; // nonce sent from SL
var nonceABF; // nonce created at CL

noble.on('stateChange', function (state) {
    if (state === 'poweredOn') {
        console.log('scanning...');
        noble.startScanning([nukiPairingServiceUuid, nukiServiceUuid], true);
//         noble.startScanning();
        noble.startScanning();
    } else {
        noble.stopScanning();
    }
});

function prepareDataToSend(cmd, data) {
    var cmdBuffer = new Buffer(2);
    cmdBuffer.writeUInt16LE(cmd);
    var responseData = Buffer.concat([cmdBuffer, data]);
    var checksum = crc.crc16ccitt(responseData);
    var checksumBuffer = new Buffer(2);
    checksumBuffer.writeUInt16LE(checksum);
    var dataToSend = Buffer.concat([responseData, checksumBuffer]);
    return dataToSend;
}

function crcOk(dataTocheck) {
    var dataForCrc = dataTocheck.slice(0, dataTocheck.length - 2);
    var crcSumCalc = crc.crc16ccitt(dataForCrc);
    var crcSumRetrieved = dataTocheck.readUInt16LE(dataTocheck.length - 2);
    return crcSumCalc === crcSumRetrieved;
}

function dataReceived(data, isNotification, peripheral) {
    var rCmd, r;
    // console.log('response from nuki', data, isNotification);
    switch (state) {
        case STATE_PAIRING_CL_REQ_PUBKEY:
            rCmd = data.readUInt16LE(0);
            if (rCmd === CMD_ID_PUBLIC_KEY) {
                console.log("Step 4: SL sent first part of public key...");
                state = STATE_PAIRING_CL_REQ_PUBKEY_FIN;
                rData = data;
            } else {
                console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                state = STATE_PAIRING_IDLE;
                peripheral.disconnect();
            }
            break;
        case STATE_PAIRING_CL_REQ_PUBKEY_FIN:
            rData = Buffer.concat([rData, data]);
            if (crcOk(rData)) {
                rCmd = rData.readUInt16LE(0);
                if (rCmd === CMD_ID_PUBLIC_KEY) {
                    slPubKey = rData.slice(2, rData.length - 2);
                    console.log("Step 4: SL sent PK:");

                    console.log("Step 5: creating new CL key pair...");

                    if (useSampleKeys) {
                        clSk = makeKeyBuffer("8CAA54672307BFFDF5EA183FC607158D2011D008ECA6A1088614FF0853A5AA07");
                        clPk = makeKeyBuffer("F88127CCF48023B5CBE9101D24BAA8A368DA94E8C2E3CDE2DED29CE96AB50C15");
                    } else {
                        var strPk = config.get("pk");
                        var strSk = config.get("sk");
                        if (_.isString(strPk) && strPk.length === 32 && _.isString(strSk) && strSk.length === 32) {
                            clPk = new Buffer(strPk, 'hex');
                            clSk = new Buffer(strSk, 'hex');
                            console.log("Step 5: keypair read from config file.");
                        }
                    }

                    if (!(Buffer.isBuffer(clPk) && Buffer.isBuffer(clSk) && clPk.length === 32 && clSk === 32)) {
                        var clKeys = new sodium.Key.ECDH();
                        clSk = clKeys.sk().get();
                        clPk = clKeys.pk().get();
                        console.log("Step 5: created.");
                    }


                    state = STATE_PAIRING_CL_REQ_CHALLENGE;
                    console.log("Step 6: CL sending PK...");

                    var wDataWithCrc = prepareDataToSend(CMD_ID_PUBLIC_KEY, clPk);
                    nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, function (err) {
                        if (err) {
                            console.log("write to nukiPairingGeneralDataIOCharacteristic failed", err);
                            state = STATE_PAIRING_IDLE;
                            peripheral.disconnect();
                        } else {
                            console.log("CL PUBKEY sending...");


                            // console.log("clSK", clSk);
                            // console.log("clPK", clPk);
                            // console.log("slPK", slPubKey);

                            // create a Diffie Hellman key out of the clients secret key and the nukis public key
                            // crypto_scalarmult_curve25519(s,sk,pk)
                            var k = sodium.api.crypto_scalarmult(clSk, slPubKey);
                            console.log("CL DH Key from CL SK and SL PK: ", k);

                            // derive a longterm shared secret key s from k using function kdf1
                            // static const unsigned char _0[16];
                            // static const unsigned char sigma[16] = "expand 32-byte k";
                            // crypto_core_hsalsa20(k,_0,s,sigma)
                            var hsalsa20 = new HSalsa20();
                            sharedSecret = new Buffer(32);
                            var inv = new Buffer(16);
                            inv.fill(0);
                            var c = new Buffer("expand 32-byte k");
                            hsalsa20.crypto_core(sharedSecret, inv, k, c);
                            console.log("derived shared key: ", sharedSecret);
                        }

                    });
                } else {
                    console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                    state = STATE_PAIRING_IDLE;
                    peripheral.disconnect();
                }
            } else {
                console.log("ERROR: wrong CRC");
                state = STATE_PAIRING_IDLE;
                peripheral.disconnect();
            }
            break;
        case STATE_PAIRING_CL_REQ_CHALLENGE:
            rCmd = data.readUInt16LE(0);
            if (rCmd === CMD_CHALLENGE) {
                console.log("Step 9: SL sent first part of challenge...");
                state = STATE_PAIRING_CL_REQ_CHALLENGE_FIN;
                rData = data;
            } else {
                console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                state = STATE_PAIRING_IDLE;
                peripheral.disconnect();
            }
            break;
        case STATE_PAIRING_CL_REQ_CHALLENGE_FIN:
            rData = Buffer.concat([rData, data]);
            if (crcOk(rData)) {
                rCmd = rData.readUInt16LE(0);
                if (rCmd === CMD_CHALLENGE) {
                    nonceK = rData.slice(2, rData.length - 2);
                    console.log("Step 9: SL sent challenge.");

                    console.log("Step 10: CL creates r from CL PK, SL PK and nonceK");
                    r = Buffer.concat([clPk, slPubKey, nonceK]);

                    console.log("Step 11: CL creates authenticator from r");
                    // use HMAC-SHA256 to create the authenticator
                    authenticator = crypto.createHmac('SHA256', sharedSecret).update(r).digest();
                    console.log("Step 13: CL sends authorization authenticator...");

                    state = STATE_PAIRING_CL_REQ_CHALLENGE_2;

                    wDataWithCrc = prepareDataToSend(CMD_AUTHORIZATION_AUTHENTICATOR, authenticator);
                    nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, function (err) {
                        if (err) {
                            console.log("Writing authenticator failed", err);
                            state = STATE_PAIRING_IDLE;
                            peripheral.disconnect();
                            // } else {
                            //     console.log("CL Authorization Authenticator sending...");
                        }
                    });
                } else {
                    console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                    state = STATE_PAIRING_IDLE;
                    peripheral.disconnect();
                }
            } else {
                console.log("ERROR: wrong CRC in state " + state);
                state = STATE_PAIRING_IDLE;
                peripheral.disconnect();
            }
            break;
        case STATE_PAIRING_CL_REQ_CHALLENGE_2:
            rCmd = data.readUInt16LE(0);
            if (rCmd === CMD_CHALLENGE) {
                console.log("Step 15a: SL sent first part of challenge.");
                state = STATE_PAIRING_CL_REQ_CHALLENGE_2_FIN;
                rData = data;
            } else {
                console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                state = STATE_PAIRING_IDLE;
                peripheral.disconnect();
            }
            break;
        case STATE_PAIRING_CL_REQ_CHALLENGE_2_FIN:
            rData = Buffer.concat([rData, data]);
            if (crcOk(rData)) {
                rCmd = rData.readUInt16LE(0);
                if (rCmd === CMD_CHALLENGE) {
                    nonceK = rData.slice(2, rData.length - 2);
                    rData = new Buffer(0);
                    console.log("Step 15b: SL sent challenge.");

                    console.log("Step 16a: creating authorization data...");
                    var ids = new Buffer(5);
                    ids.writeUInt8(2); // ID type: 2: Fob
                    ids.writeUInt32LE(FobId, 1);

                    var nameBuffer = new Buffer(32).fill(' ');
                    var name = new Buffer(config.get("name"));
                    if (name.length > nameBuffer.length) {
                        name.copy(nameBuffer, 0, 0, nameBuffer.length);
                    } else {
                        name.copy(nameBuffer, 0, 0, name.length);
                    }
                    nonceABF = new Buffer(NUKI_NONCEBYTES);
                    sodium.api.randombytes_buf(nonceABF);

                    // create authenticator for the authorization data message
                    r = Buffer.concat([ids, nameBuffer, nonceABF, nonceK]);
                    // use HMAC-SHA256 to create the authenticator
                    authenticator = crypto.createHmac('SHA256', sharedSecret).update(r).digest();

                    var wData = Buffer.concat([authenticator, ids, nameBuffer, nonceABF]);
                    wDataWithCrc = prepareDataToSend(CMD_AUTHORIZATION_DATA, wData);
                    // console.log("CL sending authorization data", wDataWithCrc);
                    console.log("Step 16b: sending authorization data...");
                    state = STATE_PAIRING_SL_SEND_AUTH_ID;
                    nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, function (err) {
                        if (err) {
                            console.log("Writing authenticator data failed", err);
                            state = STATE_PAIRING_IDLE;
                            peripheral.disconnect();
                        } else {
                            state = STATE_PAIRING_SL_SEND_AUTH_ID;
                            // console.log("CL Authorization Data sent");
                        }
                    });
                } else {
                    console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                    state = STATE_PAIRING_IDLE;
                    peripheral.disconnect();
                }
            } else {
                console.log("ERROR: wrong CRC in state " + state);
                state = STATE_PAIRING_IDLE;
                peripheral.disconnect();
            }
            break;
        case STATE_PAIRING_SL_SEND_AUTH_ID:
            rData = Buffer.concat([rData, data]);
            if (rData.length >= 88) {
                if (crcOk(rData)) {
                    rCmd = rData.readUInt16LE(0);
                    if (rCmd === CMD_AUTHORIZATION_ID) {
                        console.log("Step 19: SL sent authorization id");
                        rData = rData.slice(2, rData.length - 2);
                        var slAuthenticator = rData.slice(0, 32);
                        var authorizationIdBuffer = rData.slice(32, 32 + 4);
                        var authorizationId = authorizationIdBuffer.readUInt32LE();
                        var slUuid = rData.slice(36, 36 + 16);
                        nonceK = rData.slice(36 + 16, 36 + 16 + 32);

                        // console.log("SL sent authenticator", slAuthenticator);
                        console.log("SL sent authorization-id " + authorizationId);
                        console.log("SL sent slUuid", slUuid.toString('hex'));

                        config.set("nuki-uuid", slUuid.toString('hex'));
                        config.set("nuki-authorization-id", authorizationId);
                        // config.set("pk", clPk.toString('hex'));
                        // config.set("sk", clSk.toString('hex'));
                        config.set("sharedSecret", sharedSecret.toString('hex'));

                        config.save(function (err) {
                            if (err) {
                                console.log("ERROR: writing configuration failed", err);
                                state = STATE_PAIRING_IDLE;
                                peripheral.disconnect();
                            } else {
                                console.log("Step 20: verifying authenticator...");
                                r = Buffer.concat([authorizationIdBuffer, slUuid, nonceK, nonceABF]);
                                // use HMAC-SHA256 to create the authenticator
                                cr = crypto.createHmac('SHA256', sharedSecret).update(r).digest();

                                if (Buffer.compare(slAuthenticator, cr) === 0) {
                                    console.log("Step 20: authenticator verified ok.");


                                    console.log("Step 21: CL creating authorization-id confirmation message...");
                                    r = Buffer.concat([authorizationIdBuffer, nonceK]);
                                    // use HMAC-SHA256 to create the authenticator
                                    authenticator = crypto.createHmac('SHA256', sharedSecret).update(r).digest();

                                    wData = Buffer.concat([authenticator, authorizationIdBuffer]);
                                    wDataWithCrc = prepareDataToSend(CMD_AUTHORIZATION_ID_CONFIRMATION, wData);
                                    console.log("Step 21: sending authorization-id confirmation...");
                                    state = STATE_PAIRING_SL_SEND_STATUS_COMLETE;
                                    nukiPairingGeneralDataIOCharacteristic.write(wDataWithCrc, false, function (err) {
                                        if (err) {
                                            console.log("Writing Authorization-ID Confirmation failed", err);
                                            state = STATE_PAIRING_IDLE;
                                            peripheral.disconnect();
                                        } else {
                                            rData = new Buffer(0);
                                            // console.log("CL Authorization-ID confirmation sent");
                                        }
                                    });

                                } else {
                                    console.log("CL and SL authenticators are not equal. Possible man in the middle attack. Exiting.");
                                    console.log("CL Authenticator:", cr, cr.length);
                                    console.log("SL Authenticator:", slAuthenticator, slAuthenticator.length);
                                    state = STATE_PAIRING_IDLE;
                                    peripheral.disconnect();
                                }
                            }
                        });

                    } else {
                        console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                        state = STATE_PAIRING_IDLE;
                        peripheral.disconnect();
                    }
                } else {
                    console.log("ERROR: wrong CRC in state " + state);
                    state = STATE_PAIRING_IDLE;
                    peripheral.disconnect();
                }
            }
            break;
        case STATE_PAIRING_SL_SEND_STATUS_COMLETE:
            if (crcOk(data)) {
                rCmd = data.readUInt16LE(0);
                if (rCmd === CMD_STATUS) {
                    console.log("Step 22: SL sent status complete.");
                    setTimeout(function () {
                        console.log("===> This client is now paired with the nuki smartlock");
                        state = STATE_PAIRING_IDLE;
                        peripheral.disconnect();
                    }, 1000);
                } else {
                    console.log("ERROR: not expected command id " + rCmd + " received in state " + state);
                    state = STATE_PAIRING_IDLE;
                    peripheral.disconnect();
                }
            } else {
                console.log("ERROR: wrong CRC in state " + state);
                state = STATE_PAIRING_IDLE;
                peripheral.disconnect();
            }
            break;
        default:
            console.log("ERROR: undefined state " + state);
    }
}

noble.on('discover', function (peripheral) {

    //
    // The advertisment data contains a name, power level (if available),
    // certain advertised service uuids, as well as manufacturer data,
    // which could be formatted as an iBeacon.
    //

    console.log('found peripheral:', peripheral.advertisement);
    var peripheralName = 'peripheral';
    if (peripheral.advertisement.localName) {
        peripheralName = peripheral.advertisement.localName;
    }
    console.log(peripheralName + " is " + peripheral.connectable ? "" : "not" + " connectable");

    //
    // Once the peripheral has been discovered, then connect to it.
    // It can also be constructed if the uuid is already known.
    ///
    peripheral.connect(function (err) {
        if (err) {
            concole.log("ERROR while connecting " + peripheral.advertisement.localName);
        } else {
            //
            // Once the peripheral has been connected, then discover the
            // services and characteristics of interest.
            //
            peripheral.discoverServices([nukiPairingServiceUuid, nukiServiceUuid], function (err, services) {
                if (err) {
                    console.log("discoverServices failed", err);
                } else {
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
                                console.log('found characteristic:', characteristic.uuid);

                                if (nukiPairingGeneralDataIOCharacteristicUuid == characteristic.uuid) {
                                    nukiPairingGeneralDataIOCharacteristic = characteristic;
                                }
                                else if (nukiServiceGeneralDataIOCharacteristicUuid == characteristic.uuid) {
                                    nukiServiceGeneralDataIOCharacteristic = characteristic;
                                }
                                else if (nukiUserSpecificDataInputOutputCharacteristicUuid == characteristic.uuid) {
                                    nukiUserSpecificDataInputOutputCharacteristic = characteristic;
                                }
                            });

                            //
                            // Check to see if we found all of our characteristics.
                            //
                            if (nukiPairingGeneralDataIOCharacteristic &&
                                nukiServiceGeneralDataIOCharacteristic &&
                                nukiUserSpecificDataInputOutputCharacteristic) {
                                console.log("all characteristics found");

                                state = STATE_PAIRING_CL_REQ_PUBKEY;

                                // we found a peripheral, stop scanning
                                noble.stopScanning();


                                nukiPairingGeneralDataIOCharacteristic.subscribe();

                                nukiPairingGeneralDataIOCharacteristic.on('read', function (data, isNotification) {
                                    dataReceived(data, isNotification, peripheral);
                                });

                                var d = new Buffer(2);
                                d.writeUInt16LE(CMD_ID_PUBLIC_KEY);
                                var wCmdWithChecksum = prepareDataToSend(CMD_REQUEST_DATA, d);
                                nukiPairingGeneralDataIOCharacteristic.write(wCmdWithChecksum, false, function (err) {
                                    if (err) {
                                        console.log("write to nukiPairingGeneralDataIOCharacteristic failed", err);
                                    } else {
                                        console.log("CL sent command to request SL PK");
                                    }
                                });
                            }
                        });
                    });
                }
            });
        }
    });

    peripheral.disconnect(function () {
        console.log("Peripheral disconnected.");
        process.exit();
    });

});

function makeKeyBuffer(inKey) {
    var keyAsBuffer = new Buffer(0);
    if (_.isString(inKey)) {
        keyAsBuffer = new Buffer(inKey, 'hex');
    } else {
        if (_.isArray(inKey)) {
            keyAsBuffer = new Buffer(inKey);
        }
    }
    return keyAsBuffer;
}
