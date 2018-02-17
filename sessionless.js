/* 
 * Sessionless : javascript browser session using WebCrypto API.
 * https://github.com/joannesource/sessionless
 */

window.Sessionless = {
    name: 'Sessionless',
    pubkey: null,
    privkey: null,
    loaded: 0,
    
    init: function () {
		if (!this.Sessionless.exists()) {
			return window.Sessionless.create();
		} else {
			return window.Sessionless.load();
		}
    },
    exists: function () {
        return this.getStoredPublicKey() !== null && this.getStoredPrivateKey() !== null;
    },
    getStoredPublicKey: function () {
        return localStorage.getItem(this.name + 'Public');
    },
    getStoredPrivateKey: function () {
        return localStorage.getItem(this.name + 'Private');
    },
    setStoredPublicKey: function (key) {
        localStorage.setItem(this.name + 'Public', key);
    },
    setStoredPrivateKey: function (key) {
        localStorage.setItem(this.name + 'Private', key);
    },
    isLoaded: function () {
        return this.loaded;
    },
    load: function () {
        var self = this;
        if (!this.exists()) {
            console.log('Sessionless init error: keypair doesn\'t exist');
            return;
        }
        var p1 = window.crypto.subtle.importKey(
                "pkcs8",
                this.stringToArrayBuffer(this.getStoredPrivateKey()),
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {name: "SHA-512"},
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["sign"] //"verify" for public key import, "sign" for private key imports
                )
                .then(function (privateKey) {
                    self.privkey = privateKey;
                })
                .catch(function (err) {
                    console.error(err);
                });
        var p2 = window.crypto.subtle.importKey(
                "spki",
                this.stringToArrayBuffer(this.getStoredPublicKey()),
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {name: "SHA-512"},
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["verify"] //"verify" for public key import, "sign" for private key imports
                )
                .then(function (publicKey) {
                    self.pubkey = publicKey;
                })
                .catch(function (err) {
                    console.error(err);
                });
        return Promise.all([p1, p2]).then(function () {
            self.loaded = 1;
        });
    },
    create: function () {
        var self = this;
        return window.crypto.subtle.generateKey(
                {
                    name: "RSASSA-PKCS1-v1_5",
                    modulusLength: 2048, //can be 1024, 2048, or 4096
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: {name: "SHA-512"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["sign", "verify"] //can be any combination of "sign" and "verify"
                )
                .then(function (key) {
                    self.privkey = key.privateKey;
                    self.pubkey = key.publicKey;

                    window.crypto.subtle.exportKey(
                            "pkcs8", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                            key.privateKey //can be a publicKey or privateKey, as long as extractable was true
                            )
                            .then(function (keydata) {
                                self.setStoredPrivateKey(self.arrayBufferToString(keydata));
                            })
                            .catch(function (err) {
                                console.error(err);
                            });

                    window.crypto.subtle.exportKey(
                            "spki", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                            key.publicKey //can be a publicKey or privateKey, as long as extractable was true
                            )
                            .then(function (keydata) {
                                self.setStoredPublicKey(self.arrayBufferToString(keydata));
                            })
                            .catch(function (err) {
                                console.error(err);
                            });
                })
                .catch(function (err) {
                    console.error(err);
                });
    },
    spkiToPEM: function (keydata) {
        var keydataS = this.arrayBufferToString(keydata);
        var keydataB64 = window.btoa(keydataS);
        var keydataB64Pem = this.formatAsPem(keydataB64);
        return keydataB64Pem;
    },

    arrayBufferToString: function (buffer) {
        var binary = '';
        var bytes = new Uint8Array(buffer);
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[ i ]);
        }
        return binary;
    },
    stringToArrayBuffer: function (string) {
        var len = string.length;
        var buffer = new ArrayBuffer(len);
        var bytes = new Uint8Array(buffer);
        for (var i = 0; i < len; i++) {
            bytes[i] = string.charCodeAt(i);
        }
        return bytes;
    },
    formatAsPem: function (str) {
        var finalString = '-----BEGIN PUBLIC KEY-----\n';
        while (str.length > 0) {
            finalString += str.substring(0, 64) + '\n';
            str = str.substring(64);
        }
        finalString = finalString + "-----END PUBLIC KEY-----";
        return finalString;
    },
    export: function () {
        return {
            public: btoa(this.getStoredPublicKey()),
            private: btoa(this.getStoredPrivateKey())
        }
    },
    import: function (access) {
        var self = this;

        var p1 = window.crypto.subtle.importKey(
                "pkcs8", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                self.stringToArrayBuffer(atob(access.private)),
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {name: "SHA-512"},
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["sign"] //"verify" for public key import, "sign" for private key imports
                )
                .then(function (privateKey) {
                    //returns a publicKey (or privateKey if you are importing a private key)
                    window.crypto.subtle.exportKey(
                            "pkcs8", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                            privateKey //can be a publicKey or privateKey, as long as extractable was true
                            )
                            .then(function (keydata) {
                                var keyChanged = self.getStoredPrivateKey() != self.arrayBufferToString(keydata);
                                if (keyChanged) {
                                    self.setStoredPrivateKey(self.arrayBufferToString(keydata));
                                }
                            })
                            .catch(function (err) {
                                console.error(err);
                            });
                })
                .catch(function (err) {
                    console.error(err);
                });

        var p2 = window.crypto.subtle.importKey(
                "spki", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                self.stringToArrayBuffer(atob(access.public)),
                {
                    name: "RSASSA-PKCS1-v1_5",
                    hash: {name: "SHA-512"},
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["verify"] //"verify" for public key import, "sign" for private key imports
                )
                .then(function (publicKey) {
                    window.crypto.subtle.exportKey(
                            "spki", //can be "jwk" (public or private), "spki" (public only), or "pkcs8" (private only)
                            publicKey //can be a publicKey or privateKey, as long as extractable was true
                            )
                            .then(function (keydata) {
                                var keyChanged = self.getStoredPublicKey() != self.arrayBufferToString(keydata);
                                if (keyChanged) {
                                    self.setStoredPublicKey(self.arrayBufferToString(keydata));
                                }
                            })
                            .catch(function (err) {
                                console.error(err);
                            });
                })
                .catch(function (err) {
                    console.error(err);
                });

        return Promise.all([p1, p2]).then(function () {
            console.log('privkey and pubkey imported');
        });
    },
    arrayBufferToBase64: function (buffer) {
        var binary = '';
        var bytes = new Uint8Array(buffer);
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[ i ]);
        }
        return window.btoa(binary);
    },
    getPublicPem: function () {
        return this.spkiToPEM(this.stringToArrayBuffer(this.getStoredPublicKey()));
    },
    sign: function (messageString) {
        var self = this;
        var message = new TextEncoder("utf-8").encode(messageString);
        return window.crypto.subtle.sign(
                {
                    name: "RSASSA-PKCS1-v1_5",
                },
                self.privkey,
                message
                )
                .then(function (_signature) {// ArrayBuffer
                    var signature = self.arrayBufferToBase64(_signature);
                    return signature;
                });
    }
};

