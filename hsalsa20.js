var _ = require('underscore');

var hsalsa20 = module.exports = function () {
};


// near clone of Java's casting of integers to bytes
// warning: doesn't handle negative integers properly
function toByte(i) {
    return ((i + 128) % 256) - 128;
}

_.extend(hsalsa20.prototype, {

    ROUNDS: 20,

    rotate: function (u, c) {
        return (u << c) | (u >>> (32 - c));
    },

    load_littleendian: function (x, offset) {
        return (parseInt(x[offset]) & 0xff) |
            (((parseInt(x[offset + 1]) & 0xff)) << 8) |
            (((parseInt(x[offset + 2]) & 0xff)) << 16) |
            (((parseInt(x[offset + 3]) & 0xff)) << 24);
    },

    store_littleendian: function (x, offset, u) {
        x[offset] = toByte(u);
        u >>>= 8;
        x[offset + 1] = toByte(u);
        u >>>= 8;
        x[offset + 2] = toByte(u);
        u >>>= 8;
        x[offset + 3] = toByte(u);
    },

    crypto_core: function (outv, inv, k, c) {
        var x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
        var j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
        var i;

        j0 = x0 = this.load_littleendian(c, 0);
        j1 = x1 = this.load_littleendian(k, 0);
        j2 = x2 = this.load_littleendian(k, 4);
        j3 = x3 = this.load_littleendian(k, 8);
        j4 = x4 = this.load_littleendian(k, 12);
        j5 = x5 = this.load_littleendian(c, 4);

        if (inv != null) {
            j6 = x6 = this.load_littleendian(inv, 0);
            j7 = x7 = this.load_littleendian(inv, 4);
            j8 = x8 = this.load_littleendian(inv, 8);
            j9 = x9 = this.load_littleendian(inv, 12);
        }
        else {
            j6 = x6 = j7 = x7 = j8 = x8 = j9 = x9 = 0;
        }

        j10 = x10 = this.load_littleendian(c, 8);
        j11 = x11 = this.load_littleendian(k, 16);
        j12 = x12 = this.load_littleendian(k, 20);
        j13 = x13 = this.load_littleendian(k, 24);
        j14 = x14 = this.load_littleendian(k, 28);
        j15 = x15 = this.load_littleendian(c, 12);

        for (i = this.ROUNDS; i > 0; i -= 2) {
            x4 ^= this.rotate(x0 + x12, 7);
            x8 ^= this.rotate(x4 + x0, 9);
            x12 ^= this.rotate(x8 + x4, 13);
            x0 ^= this.rotate(x12 + x8, 18);
            x9 ^= this.rotate(x5 + x1, 7);
            x13 ^= this.rotate(x9 + x5, 9);
            x1 ^= this.rotate(x13 + x9, 13);
            x5 ^= this.rotate(x1 + x13, 18);
            x14 ^= this.rotate(x10 + x6, 7);
            x2 ^= this.rotate(x14 + x10, 9);
            x6 ^= this.rotate(x2 + x14, 13);
            x10 ^= this.rotate(x6 + x2, 18);
            x3 ^= this.rotate(x15 + x11, 7);
            x7 ^= this.rotate(x3 + x15, 9);
            x11 ^= this.rotate(x7 + x3, 13);
            x15 ^= this.rotate(x11 + x7, 18);
            x1 ^= this.rotate(x0 + x3, 7);
            x2 ^= this.rotate(x1 + x0, 9);
            x3 ^= this.rotate(x2 + x1, 13);
            x0 ^= this.rotate(x3 + x2, 18);
            x6 ^= this.rotate(x5 + x4, 7);
            x7 ^= this.rotate(x6 + x5, 9);
            x4 ^= this.rotate(x7 + x6, 13);
            x5 ^= this.rotate(x4 + x7, 18);
            x11 ^= this.rotate(x10 + x9, 7);
            x8 ^= this.rotate(x11 + x10, 9);
            x9 ^= this.rotate(x8 + x11, 13);
            x10 ^= this.rotate(x9 + x8, 18);
            x12 ^= this.rotate(x15 + x14, 7);
            x13 ^= this.rotate(x12 + x15, 9);
            x14 ^= this.rotate(x13 + x12, 13);
            x15 ^= this.rotate(x14 + x13, 18);
        }

        x0 += j0;
        x1 += j1;
        x2 += j2;
        x3 += j3;
        x4 += j4;
        x5 += j5;
        x6 += j6;
        x7 += j7;
        x8 += j8;
        x9 += j9;
        x10 += j10;
        x11 += j11;
        x12 += j12;
        x13 += j13;
        x14 += j14;
        x15 += j15;

        x0 -= this.load_littleendian(c, 0);
        x5 -= this.load_littleendian(c, 4);
        x10 -= this.load_littleendian(c, 8);
        x15 -= this.load_littleendian(c, 12);

        if (inv !== undefined /* null*/) {
            x6 -= this.load_littleendian(inv, 0);
            x7 -= this.load_littleendian(inv, 4);
            x8 -= this.load_littleendian(inv, 8);
            x9 -= this.load_littleendian(inv, 12);
        }

        this.store_littleendian(outv, 0, x0);
        this.store_littleendian(outv, 4, x5);
        this.store_littleendian(outv, 8, x10);
        this.store_littleendian(outv, 12, x15);
        this.store_littleendian(outv, 16, x6);
        this.store_littleendian(outv, 20, x7);
        this.store_littleendian(outv, 24, x8);
        this.store_littleendian(outv, 28, x9);

        return 0;
    }

});

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

hsalsa20.extend = extend;

