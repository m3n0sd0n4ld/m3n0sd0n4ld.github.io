<html>
<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Protected Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <!-- do not cache this page -->
        <meta http-equiv="cache-control" content="max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />

        <style>
            .staticrypt-hr {
                margin-top: 20px;
                margin-bottom: 20px;
                border: 0;
                border-top: 1px solid #eee;
            }

            .staticrypt-page {
                width: 360px;
                padding: 8% 0 0;
                margin: auto;
                box-sizing: border-box;
            }

            .staticrypt-form {
                position: relative;
                z-index: 1;
                background: #bbbbbb;
                max-width: 360px;
                margin: 0 auto 100px;
                padding: 45px;
                text-align: center;
                box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
            }

            .staticrypt-form input[type="password"] {
                outline: 0;
                background: #f2f2f2;
                width: 100%;
                border: 0;
                margin: 0 0 15px;
                padding: 15px;
                box-sizing: border-box;
                font-size: 14px;
            }

            .staticrypt-form .staticrypt-decrypt-button {
                text-transform: uppercase;
                outline: 0;
                background: #17191A;
                width: 100%;
                border: 0;
                padding: 15px;
                color: #ffffff;
                font-size: 14px;
                cursor: pointer;
            }

            .staticrypt-form .staticrypt-decrypt-button:hover,
            .staticrypt-form .staticrypt-decrypt-button:active,
            .staticrypt-form .staticrypt-decrypt-button:focus {
                background: #17191A;
                filter: brightness(92%);
            }

            .staticrypt-html {
                height: 100%;
            }

            .staticrypt-body {
                height: 100%;
                margin: 0;
            }

            .staticrypt-content {
                height: 100%;
                margin-bottom: 1em;
                background: transparent;
                font-family: "Arial", sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            .staticrypt-instructions {
                margin-top: -1em;
                margin-bottom: 1em;
            }

            .staticrypt-title {
                font-size: 1.5em;
            }

            label.staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 1em;
            }

            .staticrypt-remember input[type="checkbox"] {
                transform: scale(1.5);
                margin-right: 1em;
            }

            .hidden {
                display: none !important;
            }

            .staticrypt-spinner-container {
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .staticrypt-spinner {
                display: inline-block;
                width: 2rem;
                height: 2rem;
                vertical-align: text-bottom;
                border: 0.25em solid gray;
                border-right-color: transparent;
                border-radius: 50%;
                -webkit-animation: spinner-border 0.75s linear infinite;
                animation: spinner-border 0.75s linear infinite;
                animation-duration: 0.75s;
                animation-timing-function: linear;
                animation-delay: 0s;
                animation-iteration-count: infinite;
                animation-direction: normal;
                animation-fill-mode: none;
                animation-play-state: running;
                animation-name: spinner-border;
            }

            @keyframes spinner-border {
                100% {
                    transform: rotate(360deg);
                }
            }
        </style>
    </head>

    <body class="staticrypt-body">
        <div id="staticrypt_loading" class="staticrypt-spinner-container">
            <div class="staticrypt-spinner"></div>
        </div>

        <div id="staticrypt_content" class="staticrypt-content hidden">
            <div class="staticrypt-page">
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">Protected Page</p>
                        <p><p>The flag is the password.</p>
</p>
                    </div>

                    <hr class="staticrypt-hr" />

                    <form id="staticrypt-form" action="#" method="post">
                        <input
                            id="staticrypt-password"
                            type="password"
                            name="password"
                            placeholder="Password"
                            autofocus
                        />

                        <label id="staticrypt-remember-label" class="staticrypt-remember hidden">
                            <input id="staticrypt-remember" type="checkbox" name="remember" />
                            Remember me
                        </label>

                        <input type="submit" class="staticrypt-decrypt-button" value="DECRYPT" />
                    </form>
                </div>
            </div>
        </div>

        <script>
            // these variables will be filled when generating the file - the template format is 'variable_name'
            const staticryptInitiator = 
            ((function(){
  const exports = {};
  const cryptoEngine = ((function(){
  const exports = {};
  const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
 * Translates between utf8 encoded hexadecimal strings
 * and Uint8Array bytes.
 */
const HexEncoder = {
    /**
     * hex string -> bytes
     * @param {string} hexString
     * @returns {Uint8Array}
     */
    parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },

    /**
     * bytes -> hex string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};

/**
 * Translates between utf8 strings and Uint8Array bytes.
 */
const UTF8Encoder = {
    parse: function (str) {
        return new TextEncoder().encode(str);
    },

    stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
    },
};

/**
 * Salt and encrypt a msg with a password.
 */
async function encrypt(msg, hashedPassword) {
    // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

    const encrypted = await subtle.encrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
    );

    // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
    return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
 * Decrypt a salted msg using a password.
 *
 * @param {string} encryptedMsg
 * @param {string} hashedPassword
 * @returns {Promise<string>}
 */
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

    const outBuffer = await subtle.decrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
    );

    return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
async function hashPassword(password, salt) {
    // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
    // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
    let hashedPassword = await hashLegacyRound(password, salt);

    hashedPassword = await hashSecondRound(hashedPassword, salt);

    return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
 * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
 * compatibility.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
 * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
 * remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
 * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
 * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @param {int} iterations
 * @param {string} hashAlgorithm
 * @returns {Promise<string>}
 */
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

    const keyBytes = await subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: hashAlgorithm,
            iterations,
            salt: UTF8Encoder.parse(salt),
        },
        key,
        256
    );

    return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

    return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
    const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

    return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
    const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let byteArray;
    let parsedInt;

    // Keep generating new random bytes until we get a value that falls
    // within a range that can be evenly divided by possibleCharacters.length
    do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
    } while (parsedInt >= 256 - (256 % possibleCharacters.length));

    // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
    const randomIndex = parsedInt % possibleCharacters.length;

    return possibleCharacters[randomIndex];
}

/**
 * Generate a random string of a given length.
 *
 * @param {int} length
 * @returns {string}
 */
function generateRandomString(length) {
    let randomString = "";

    for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
    }

    return randomString;
}
exports.generateRandomString = generateRandomString;

  return exports;
})());
const codec = ((function(){
  const exports = {};
  /**
 * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
 *
 * @param cryptoEngine - the engine to use for encryption / decryption
 */
function init(cryptoEngine) {
    const exports = {};

    /**
     * Top-level function for encoding a message.
     * Includes password hashing, encryption, and signing.
     *
     * @param {string} msg
     * @param {string} password
     * @param {string} salt
     *
     * @returns {string} The encoded text
     */
    async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encode = encode;

    /**
     * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
     * we don't need to hash the password multiple times.
     *
     * @param {string} msg
     * @param {string} hashedPassword
     *
     * @returns {string} The encoded text
     */
    async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encodeWithHashedPassword = encodeWithHashedPassword;

    /**
     * Top-level function for decoding a message.
     * Includes signature check and decryption.
     *
     * @param {string} signedMsg
     * @param {string} hashedPassword
     * @param {string} salt
     * @param {int} backwardCompatibleAttempt
     * @param {string} originalPassword
     *
     * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
     */
    async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
            // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
            // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
            originalPassword = originalPassword || hashedPassword;
            if (backwardCompatibleAttempt === 0) {
                const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }
            if (backwardCompatibleAttempt === 1) {
                let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
                updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }

            return { success: false, message: "Signature mismatch" };
        }

        return {
            success: true,
            decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
    }
    exports.decode = decode;

    return exports;
}
exports.init = init;

  return exports;
})());
const decode = codec.init(cryptoEngine).decode;

/**
 * Initialize the staticrypt module, that exposes functions callbable by the password_template.
 *
 * @param {{
 *  staticryptEncryptedMsgUniqueVariableName: string,
 *  isRememberEnabled: boolean,
 *  rememberDurationInDays: number,
 *  staticryptSaltUniqueVariableName: string,
 * }} staticryptConfig - object of data that is stored on the password_template at encryption time.
 *
 * @param {{
 *  rememberExpirationKey: string,
 *  rememberPassphraseKey: string,
 *  replaceHtmlCallback: function,
 *  clearLocalStorageCallback: function,
 * }} templateConfig - object of data that can be configured by a custom password_template.
 */
function init(staticryptConfig, templateConfig) {
    const exports = {};

    /**
     * Decrypt our encrypted page, replace the whole HTML.
     *
     * @param {string} hashedPassword
     * @returns {Promise<boolean>}
     */
    async function decryptAndReplaceHtml(hashedPassword) {
        const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { replaceHtmlCallback } = templateConfig;

        const result = await decode(
            staticryptEncryptedMsgUniqueVariableName,
            hashedPassword,
            staticryptSaltUniqueVariableName
        );
        if (!result.success) {
            return false;
        }
        const plainHTML = result.decoded;

        // if the user configured a callback call it, otherwise just replace the whole HTML
        if (typeof replaceHtmlCallback === "function") {
            replaceHtmlCallback(plainHTML);
        } else {
            document.write(plainHTML);
            document.close();
        }

        return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     * @param {boolean} isRememberChecked
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password, isRememberChecked) {
        const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // decrypt and replace the whole page
        const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

        const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

        if (!isDecryptionSuccessful) {
            return {
                isSuccessful: false,
                hashedPassword,
            };
        }

        // remember the hashedPassword and set its expiration if necessary
        if (isRememberEnabled && isRememberChecked) {
            window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

            // set the expiration if the duration isn't 0 (meaning no expiration)
            if (rememberDurationInDays > 0) {
                window.localStorage.setItem(
                    rememberExpirationKey,
                    (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                );
            }
        }

        return {
            isSuccessful: true,
            hashedPassword,
        };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
        const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        if (typeof clearLocalStorageCallback === "function") {
            clearLocalStorageCallback();
        } else {
            localStorage.removeItem(rememberPassphraseKey);
            localStorage.removeItem(rememberExpirationKey);
        }
    }

    async function handleDecryptOnLoad() {
        let isSuccessful = await decryptOnLoadFromUrl();

        if (!isSuccessful) {
            isSuccessful = await decryptOnLoadFromRememberMe();
        }

        return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
        const logoutKey = "staticrypt_logout";

        // handle logout through query param
        const queryParams = new URLSearchParams(window.location.search);
        if (queryParams.has(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        // handle logout through URL fragment
        const hash = window.location.hash.substring(1);
        if (hash.includes(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
        const { rememberDurationInDays } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // if we are login out, terminate
        if (logoutIfNeeded()) {
            return false;
        }

        // if there is expiration configured, check if we're not beyond the expiration
        if (rememberDurationInDays && rememberDurationInDays > 0) {
            const expiration = localStorage.getItem(rememberExpirationKey),
                isExpired = expiration && new Date().getTime() > parseInt(expiration);

            if (isExpired) {
                clearLocalStorage();
                return false;
            }
        }

        const hashedPassword = localStorage.getItem(rememberPassphraseKey);

        if (hashedPassword) {
            // try to decrypt
            const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

            // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
            // the user fill the password form again
            if (!isDecryptionSuccessful) {
                clearLocalStorage();
                return false;
            }

            return true;
        }

        return false;
    }

    function decryptOnLoadFromUrl() {
        const passwordKey = "staticrypt_pwd";

        // get the password from the query param
        const queryParams = new URLSearchParams(window.location.search);
        const hashedPasswordQuery = queryParams.get(passwordKey);

        // get the password from the url fragment
        const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
        const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

        const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

        if (hashedPassword) {
            return decryptAndReplaceHtml(hashedPassword);
        }

        return false;
    }

    return exports;
}
exports.init = init;

  return exports;
})());
        ;
            const templateError = "template_error",
                isRememberEnabled = false,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"ac78d0755bbe6478c92e44ef2f422bd525e9bdc14fb76f821f132195b7a56401792671a7293c90f479e3a8311b9e189de1b42e3280e355c86a7db3afa4e07e1c4a39ed74d61883abf29cb8e99640e2a5651d12d7de43d6169ef8348fb8d003cef2d947c5a85f2ccef80bd6fd44d7149e6a944ad3f41dfd633afe01b37923f885fad62071ae11c02e075dc2d94305a3ff355e8ac5b7eb7b1373c35bfc5abd1faa6d30d5b51d270e5cd9ceb36dc131ba2d3c6b2de77f649d48c0774ce53dae36bf9ef772ca5a34ad9a3a1530d45058130cce98bf10c90d4ce524d1db947f9f3415f27338fa1f6ec56c20b1b7dc3d92411bce1e47a3d425cd0220dd5cf0ed8a8a36c1477e75f66cdde47f1c7d9b6414fdcd4119a721e1b5171c196179778c0c52e2f02d543b7c7470f1f8796dc7422d016cacb4d781188ab221b18362ace9e30827bb7447053ae62e75332bad2796913a00c44122095bdd5a6d8b3d1114927eacfeb47e504aca79e7dec08308e46cb2061784e71ad3fab1fd033951496eef1d6e23f31cbacece9a36bb55026abca76858ec6691ab8ce26a4cf370f236585907177bd9178692a5ab0e4bd4e8ae671e04db2151170a282635864cad6f6d8fce0141f61f04d3ee0b1ec60c269c120de618d69771c01201542e2b7f006bdc7068441dee4f133e7b9ff98ba1cf91282883454b3cd438a268fe8d5710911962b12bc94a92773025105a652e3a3eb4711a7658b65bb42a67625b8afbaefbf86eda3c0d8610da30370f4d142295512e7597a76aceb6daf6204373ce086250d97adeb9edbd215ac952ab4233a2de183c6524e966631b0d3def4c8ab065a2f69035e6c84b9482d1fd3dcfa49e98c6b249af325f3cb117723a3dbb05ad3b5d9ca03249d95b6d6681f8c4280dfd09da1632d26f306d617cbf2468179f1928761e48f2a588b26097768466c8962702260c4e764fe0e9a25fcb834afaf62082231df6d5a1de992bd1c288fe23242399d84fce3efeea17806d6aa5c999b48be3fc8e0b69169232ecc4d2ccaebf1a7293d59f78e8cf09403ac5756012028f3028b9c5909c440ab9e9fc084fdd21b43990db8f39f9347f42d3d39c38b8c26fe8f7b1b3d88dece853055c0a621f47e589e1e49c0a9c3ad2e201e4bdbb9bac60ebdb1f3c09f16f29ccce42b2684ef34e77d4c8ca6469a2a989ef361bd8cc8dedd29171202d1d7cd25e92d454bc43d41c24cc77cd8fd67544a649cbe9fa5a24cae5b1758df3cb2d8ddc42dd24a28f1b2f8ce9cbeceedb2a13218a44939413ba292a17845f880b922e15a5f783fc1915d274dd787329d852c89d59912d4c64fb522e1c19b24411bdbd3855f1391717bcaeee57cbb0e6a9099234fb5875a92938f9ca5a4585763316e14bc3571d2474402101cc3e478f4a94d598241ae4c561d3e944d58976cf600d44caf8e1fdf181e086eb943892d26c71194d74b1c9237be07a3fa2dcc699e08624ade51b8dca2f6a514ae5d54cd61b8b7db0bbcd151dca3747512c11b424f2af9f0f783752ec32a54902a7c33a889f28793884bed0e559b9edd6fef61aaffcbeba08f6fe5636fe1de60027a81df111584e4bd53acb0909b259d09fc33fce57425f10410f7f211e4c5ebbb5f515b6f40c4e6233cb4f99fa5eb01a33975afa70d29b790964ba7ea7a30371ee108a434a221a0543e66ea49a3c13ce8f4434403fd6196be2354131f2769d997b0ed29afd8f108c07d8225339535de5379194e5cecc31a233868c978bfde4d5d219c73788957733601f44755ac8a914c5e3a050360a846e5c3c3ac86b7dfb412a55035ff38a913aa033548bcd22b064f9277a0d95acf04da22a093f2f8d9f4a83d8f1547033a5e9de445ed629b72fa5a8c2d5b2e1646e1723338c9a42ce42ddd0680c6c64b234553b4485f1fbe9f43051ebdc63276855fbde75516a7484b507c63a1e2d396c0b3dd16545953812284135611f3064263d537e8aa465871640ab4a81dcf70b35fd58ecd15af006bd5bd0a50124547e5f7ba0707a6beb5ccc19a1bd59cb97ffca01e3e52eeb3101ae8fee33aa6706496875c3fcd9c586e0abcf69bbe6e18803f1f9c1ff5f8bab6fa4bfabf64f08e97037770a0827f9a5b553ca00dac0526fddb5dc9bb54cfd2f7386b9d452b6adfe70151f9a7b944649b164cc894cdca844f06be66641f544c519775010973153762ffa24a5e1beaeb4785b0a1795b4041dceeeeab1fbe183107fa38aecc70662bfdfd27d37a109204f653558f3cb11b87eab29668e066eea3d5c159bc83dff5f6a289ae9d3074d2f6a88519a4f53c2fdb6bfab3b066d268c214d149cc82155c840dbe4e093140c85fa0f2a54ecd35bc4be6fe1c7b3c39c83d20469b94a152aaf4876f264dd0fc8806d54410fe534592d02a0278ffdf4381b651e46026962663dc7c3a1f7baa2cad4defe82b7689a92ef6258993d8401bfc4101007bc8caa5361a56330db2c297be94f993b0cf394d8aa4563e68d49641128407dfad3f6225efa004e72f447b20203f21aa89876258ede7d7e67255e894800998e9bc1c59bb44cb38b44e40e14693ea8f0cdee8f0194ba10478d2c46488c9d024b75f1c51bc3f1934a5154cc133f86d015579834feea81962365a810cb4a8f4a0e08e5e4a70f814df8570848f605f7218c8dfc4c746e1d76d602fe8dc8f317ebab4f3838cb5efa1c2b67fbe452ecf7b564a42f3217d55023fa59f784ee5b664ebe33b2505c8794ba437a4db7d284c3a7c3357498b829507e1f8deecec094295dc71504db0bd0cae0f5a24eaa29fe7735d871b98f050290c7fafdaa2aac3a943e25e69a7f41bd12dd0682b9947e4fa7d3fd2743714e4f656f2e289448625adca6d146507a059a39f7a6dfc9c37530a8dd138200da8d1f0e01cdbb4e15d7af182a6ed0d1913ff19dca1c2afff40ffe7d80cf15369b7b25c6df4cad6313a1ec5ee2072d19f753281dcd438d23f1c66f4eb0831f193eb259c388433d670557d285229e436e52b51b57ca47ac989efdf56f8c19a8b1fcbb16f52d7354fba5d0a5e146fbf9ed551830fe22102ee3c6a821b4a72c3f9fa3ae03647bb466b04a710723356813cfd850fe6934938d39562e442286d82059a5de896a7f3f2c313a8f28a8dc72fed26fa3564a7ec68f4ff23887c106e7f7366356b6069caa62427c151ac88b45b47b69a6830d172c7feba9b2149198899558e95ef0a38ca40a8e6080c8e36909ed0b8df2f181c4156738af63f0915ab280a3c0113505f0e148b2bcc5345c88083029584d6390d58932d0364ed2674d0971cc242f1139ab516e697b07cf1c68ee9763a570a403dffba90c05805e3eeadb497750dc44999691c14776183fceee015a2ffc138b87242b2ed05cf0e024581a43fb0fe3b0463a437bc1b20fc57f6c94758dbb683b6d99a3527ecafc10e647d2e3b17915bffd60c91137d975136cdaba4c2f017b5d9eeb0545993b8c6fd814ef490b4c85d9680ef083acd2012af25b37530c765c5987fc806e1a1b2526782c7ea9cff8c393f5b8ff09fe66b6a0710ee8a4576a752579c8ea56c8b84ab4681266aa868a04f326cb1d89bd68c02d3004c1008042a201b0227591a2e5e0db0227a627a95635ac8048eb793c6d187de688364c615cfe9edfe35d25bf1b2ab98d541a8e0939e16e3b733030d55fb03ee5d59d0afeecd02460284060b9213845c94c9b65753a2854fb17f77bd325c1d2a074b6557f7f0f6698d45b56416f6d000a40982d6b0acb0b8a025ea149b5f9a55bcc96a5509ddcacc1a0a8e15abfc1e3088f1e23709d707f048c494686d25eff38350c8e704234104b05b255995ce87e759eca18df631096e0fb4bc249de2864db93c92d1a278be596520b288e178cbea2747acc9f4077416ed8ed8fa65e09fa676803213b83957883c12c9b188ee7b5a3c2afb6ee7c127986d434b1da469c33030e2a631eefbf6eafe11170d3f964e15655492ee6a0d5d74e51323fdfd272ccf3de7fe0f1ab2c904d19a3cb72f58dd7d765b4f2e64d4ff1221eed892434a532008b66c1d4e15507ae0c382934c798b97d2c276b39ab011c73a005686940d8c681f96a50d4e77d20a2c09a540be86e0e4d86577508cc8db737aae0f657f145180d0ef27a0bcdd0e67233626cabbd78e73d8b899db6ee7612171d2845816a9f9ae6946da7a20857889c7f0ab88844f7a225a311cc6cf333fcac311ab8709b1bdef25574dc967eaf83b7892feced646f15eb17c7d2aca0569c8b0771fc9b3cf7376ca444eb3a62bc60fa6e50d0deb6f1eede43d64f569dfb23c04ed172fccd0831f54fe966daf4a87e2e5b5b914ed026e7ce5cfc6dc140806515186d2539716eaf8a4ba325674ce2ca9baa44e09e1675ac02a16a112abaaa9d1417752c2d6d901f6bd9b0dbe60d17f1848a795218927ece754eadcefd948940037eabeb8a28112472bee4f85db09df9e564453443aaf334e223282856c831e6c3155b32934c74f369b9d30d9e2d85c125ed55b3ca8b85cd5e8a7283bf98cf023240d22cb52fb2784552a9dac66a2b9a7af662b12029ba533dca5e24bbd2784a080759b516f84233d45dbc75148813c2a4ef83696a0c11e9869a28095b6c81fdc5dc5552721e3ca0757f37e667edeaf5d563388e7442aabf042627a025091433699f189be7541ec416d7ed391efc1f88b1b01c00d8cd18aaeaa5c640d4eda14fd5866100995d30c04e3deee71bd642233bf052e146b64d1c21253797b5fbe670e14ad3bff5ddbac56fdfac3cfc929de695efe9a9f915762eb3b26dd0d8220aaf3dc7c9c128d88a0442a6bf1cf9cbf73b4cbd1aa6d17eb97d92ba7b5970d3d8cd8073ccaf1f4b6d202992c2575bf73d000e4a03886594a5d90fed6fe71821b593e1002407249f2667d5eeafd92f98f2debaa3e11fc21cc3875e309d13c43b4bec05ce1e405174802a642c4f58cbc7f86b61b2dcdf0f2c12454c560e65715b549a34ef5bcb6f3eb1373277a35b9fddb7df8032b9247fdb3bd3d3726ac28c7fbadd9d375968fef89e66bab52e76eb43cb958bb4e108641194782307283493ea07acba47c0c6d6f555cbac8fb6c1ab3b5f1a8084b6cec8760da670e5febc0e759d5604258c329cdca488bf0cff0769c3131ff647c1f0301d052a01b77a875d40d0b23b2ef94d8d2d165ce7c110ab937f55a0fc9d5c9d87537b829aa7fbf37a8594d95f2ae7e37dc24c385215598415c82d7d95020e4b6297a8cd4fc371c1298e984c9f78db05ec8d4ff70b7f569743393896223001d64761f8bedf40b8bfb9c76b7e53e35b3c8412ac99515b8f947379fff279b045141594195ccc493da558d6e1e604abcb1bb75c8848556f4eac6b531a7cb7a8545cad781ea979f8266d1457bd72d2c21814b833cb2bbc52ad08c0e8808185a32bb66a4db7528a5e24dfed7f16e6977cad9ef9c6fb8fe39791349f3930384b00c9951f6f96dc5366a82d6e9878e79002507907ba1d648658f28a34c2e03a2cae7f2e3640a9fac41e124cb698e217868bf06637903a7f386206cbac5cbf9f7cfb30e90d84116153f75379c39e2f7985506d6da0ee3c0dea7ba2bbc7fdb00020587ca35a74f2ec40c4659c3800edcaf5b94abd6ff10ab59d41b53decdad094cf0955e03b4a7b5177ee54fbb35a353aa88bcdb54585cdcc6820f63def7b1b005d8212fe0c3623a848757207d57c65f7067ae4dbfdc4f13bf2f80c81754727265a16bb3538740acd258b93e16ef8678e2985a631aa2797db7d8fdbebc182a557eb645ff367460ee06accd3be8200b81a773abee5fe484996d2fa0b7e62e0ab808695356a1c3c495ddfadea92037d296a382ccd81e5ae4de07e1e0bbbd9e41df931a14b31d36d85ca9c3e4ae26a89629af2b0883685e09447ccefa2ac1cb0272a3da6c2886e8f51d2a3d24a5c82c08dbc929259ee5d801258ef5d07eb36ff804c7f5404614ab63a3e946ff4680d7be1d85453afcff788197005c6c57711b1c3e9aabeb8722a7efdc8e7ddd8b634bbb34ae13f8b41e6733138718c493bcb4dd56f14cd238c0a2acaaf4e498b93f21924bd994e9ea856ade7d84308666ecf3af3cd9e39cbd62fcee74dce89d26135cc2fc82fa1515306ef6252927ea693179a22d3ef5328bce6170733f211db466e8039dc966b9f79e75dabaf8cb15d317a798f35a16803f79394795255ebe76548580b581c4ac5f76664cca56f659bd56fa43031720cb019ac80230f50b7a94565df545b0925ef253206e7f636f1cc9d67b56356c60887c4fa5720db05ed9bfe9e5287f2241eb1fc3c2900a0d494b4c1dc366e4392a13730531f1cea122ac8eb157e83f8620211e9417cc88cb609453ccc4c0bfe44560b8a27dbbee4965e0bdf2672ddd2f2e9f48fcda02ea8698f23bb4f6c3b5abd0ec682cc63fa7014562950625dd660e69cf0e485c5f62efc58d1822d56c0f73d125acf9b9e74b1c412aae89cac6ddd35c5c270f63eca5bf02158e049af44def87a481cc02e2f05a7480e739bd0f5ebb62cc70cdac552fb2e581596ecf09ca7d15b6fdce81552105e8dc6ebaf1b9351ceddd829de3dc959e1655bcabc7ee0d5030b756babbf1d80a9d3ffaf3101c5842f1ae870233eba5e2654ba7b870cf190a8d416688f2de8fecffd5763f17f685ac6ad2a0aff9ef2f40d782b2d119bfcbe8dd1d5aafa99b0fb4f1d8d0838b0a2d78c7e5317b51ddff070a5b2276abfb1fb785bdd154fde229d155f3549f5c0375184b3f264883df5bdef2f9706eb2acc241b34245c02ef3d61d573d3df20fd51ef5d53b82e1e706e7f0a7fc7ed5bee7bdd272b3c575709e5d812da8e3c9f8571add6ed3708241227ff0980ab88bc0a93969d0874961e86dc3c7aff0ac5f200914342217df73e51314e226539ddf5908cedefc8d7d6ae7ede455f11e5c39f042226f4ed0a4f8e4fa162df04b205819c6698120f717cd8e49acf5d2501d0e3f6062019bb61d7bfc7ce72406d0e0a849e7c486b96f0e5c59546c57b220a07ce648c138936e5249fc0af73fa5da630e3c6a7ba56d82a7c3e87d7f03db62024c11178608e6b815f4a01d19a953ad627dc163aaa7b53dae5a6bc30372f9ef4c45644d36fb6724958358296891576cc4b90564cbc17a6d15a4fee898811f42dfbae354fbc00a9ad4f7a9e3fca79ae03cfec674fdf9e67f689f5750799e8a7ad4434f011a0959164f54460d2a7efcc5d41deacec3bbae99e036e0287bf395ebf74a92a97e7eb8e5706eb453f275fc351e659793a2b816b6cdb7beeab46e596656323e80605c72e4832c63c6bb48be9dcbdccc433b54a957f7f9777b20655940c88edd47c32e089c062a7ae85ff7f363eaded500cbde33626ca064dc82f1b3868ff57274ad0329555cb5ae197f5a949cd43103d73d983025343c574306afa4f864cd7ba3943c5c08d01478040c3256490fa8dbe538d7ebdf8fffabc034cf32ee774c7a1c8becbb24f4bce00e41b87c99bfbe26dcf08ed8022dedaf96041c1137b6ddcbbb39b32d92a3d8d75e3f15a60c96089ce9a6fa86728dc65fe8d6126e359a1e59c7bb89de0dde3f9f10db0c39e2933d4805602a60629b0a656cac113ef69d1f0aab946a86f53df1cf8416c3bde2b6d8d293044ba18a38c714861aae1204a493ffcee99d28b288af8db42ad99debe7c563b3e3a75aa2cc53d0a635faeefb9c096390769dc048a723318de02fc5b0a937df913c2961d4cc4ae732ffc0e516da534ad74031e2e29ca84de52ed210668c0fa330d09893e87eacc53b9b38de9ec778c4d342eb5647fd04b70699c95436b732159fcf8c065889d14d62170232e46faf7880834b908c99fcf6bfa3a5e57647b3c9928e0e4e72e6a51ffc665ed7bf3d3e3a63100ec56355b4afed1a5507272dc14416d962cd6c45ec03d139534573047d6cc18f12d8fd67a3838f06ec37335df90d4214b6ff58e670a2fc72ec268a47b9e25357b90110d8f8153d02df6714edb639b094439e53660df2ca293b7d2d9d896fdda56e8c17db291825547e45eea3c940f6eff60d5781807ccb2069b5f3f7684a7d224fa381a4eaab0ca73a2c351aca4b69c21d04c13ea0ca124633dbb3ba5fab71fef90154a649c041223b240e20a2ab09042cecd37df7bf0c9e4b6921deeaae4db44bd7767e246dc41f7fc5809097c6738113a5c82a7959cb445be1d94e3f987c0c32375c03612322c99fa6f7e9db226efd31d21c18ff839122cfd3174829af3cf94b5b824c5bc4e655eb9d9b3f80ab5187cab5486f206d9db17dbaefcd568ffe02a579ea59ba0dce1e48bb4f38235e3cc1a8fdd21857bc03374b8881419aea7c46a7a4b517b612fbdc8d67f83c32f3cecdaa9eb5562a5c26a1534b2f0b49e6206e7edc9346e3acdd0efc077de76cd241f67c1600e8114498b9e7e8b608654c10039ee0bec2368c623ba4d9b1dfbf05745c836e771482e091675ff4258ec1d40cde7d130473bee1e38d82b0eff4f3fc7cbef9269eb9b63d5f65d2ab2b6ecbc8ef3447c0dfaf5a1ebcdd8098e8d2b1e18b3f020c68c8c6199cfe2a5ab68a7106d2970c8527217add09decaf9c314dc8e1eb13a785488ba30710ec1811665758a675973d58602da1e4f46012a974ac74c6e746fdce597a84b92337b69347aac8d0771db3c41a25a8b2c3797690c38a93b3a4032019bbe91f645e35769ab61adf96c5e0d3f4d0e255a75831676623aa7a39e706df62976d149da2bb409c2056e5f41b647d018327c2cdbe46b5a3808b387d89e868a421f81f59dcd92661d1ccff73851930e631a3678a814c4ad317a4123a3038dbd32ea6f0798be25cf8ec074a4eb0a83ae434a5423c9729b95181af392672b7ed7146087479320bd6fb61a0f1e84bb4e9db3c3b36b400dc242fdff06ec00f78217a151acefc8aad449f3c0793e37757153c21f99510b4904f24ebb7dbb559b75685e6e8d9d89c180dad3f27f4b26a68c4b3d3c043447ad523ff7a20f930adecb04b75b1a750c689f1f6da36d53e93bf6b0e418b4bca9c00d78fb4d8e69d69ce1797eb23868c549a61aaddd59645d13d0cdc3e934467296669189401bf9e90018f030c46a57c4c01131e8d897078f6df465c0e41bbaa2b3f91f182e1949c758ede3aa51cc7bec628ecc281d16e09803ba178dff3637506ab286d8b2bea626693f48242cca4a5223e9e5e337c452e3344a4427f0f7ad0aa33f975fea909c4d7c0e480963135648d5e936afae74e68e0f6583bad8edadb7e03ad4e516ddf7464b96d15c7a9151cc4792c468b029a9aaef2d3d1ea963257d01488fd812f2843fb986c39b5af2e3e9d4d0f4c0a62f3dac53581df85948c642e9a573ac3b5bfdc96b850609a9e3c52b5299ccd38f47e7a25a6233242e499e211f75a61c0db6361254972c8f23917e0c74103bd2c5a04b959d80b3f53f9b8b95d5c86548922fa8dc9e8751411ed2d6201c1185df90292408e23df37ecc9f64d303cc914fb34456d3e9926093f919f866772263ec81a19ccdee23a51862dc403830d7f61e44af1d211a4a134b49026375879b00bbed6e0b65f14e4b31a777e4689eabc03963727bdae34af43a7066d56a648a5a30cb630158cae015d923633266eb89646cf5e480db58d17c12b0fd81c12cee89999c43f3da237140d75b99ab3d774ef1aaa8f1a35081d44a2a616f07648c38cb82e87eceb648591756b534e6de464113a7981e7f551ce6a3b8be37e847de30eede2ed7216091a20f9b57282942ae110aa08ff859200b7010c05724bbdd536fc2647ae254b7483c324dc13e9fa50e901adc23efd2c4ae591f91b2460a74555559e3facf7c98259e5adeb84953ba62d749b7eeb966fe1dd87e8c465070efd78c95c6dfbb3b3c12a1d7889b12787fca16ac35e8a828a4a858ac64506705a8af209bb6dd2432e5a7dd12a3e40ea6cbda60da8441fbd735163101d6e5a4475b12d69149a22a2b2a4d1167302d3252c496855cf7e972057a59cf6a0087885e848fb14ea89083765e6674431e391f4292379f4c125b04b027f9fc581b63dbec147cd6d5cfc1e4469974dd3476f5ac7cbf1d02eddd08e8168e0bd2c811cb2830ea7baf564fdb084d306fd30a0386a42786b08252e6d49be622420216d9f08287959fe84ca4f081571d6f78a357cb83cea14aa767aecd3ecd41428ecdd007f8e6fc5598b5f0b655148924e3d420d39a7e344fdaf4b0dde5ef09a2e679c92a60f3f3e564b2a091b7d0272efd01267aa4ce5cd08ae64ef0bdb31aa4c4d83eec2cb5f82986d73178cef5af19428891a1a578945abc06e963294874fe5de212181441b0bccc170bcd5ff13afa15dfc1716cca0b195a529c90cc52e4c4630461a1ed90ab1cb12f2032545f3f39cc4df3f153ffd452c969a72ceb0097c1c8b164611de752f6f0f7d73d27e3d523e6806dbcd0e7b4c2eb13c4ec5cb319769bbb2d18a90113ba84dbb5f3b21a806f2e95accbbd538f29523c447b595e869a16a12e5390b7ed5a74ba768ce79203111dbfa4b96bf5bcd987221e4449449d6ce4a35fe1ae88ace9ee1432466598347f399e2b731ad56af6cb022985a83aa8d77decd7cef80eac0055c82256e2f40e3a086d9d038202d4b8ebc12251047660551236f35db0e959dcac5c83a123c8a9e435b2c5ef0edaa044881d65f2e34690ec9cf15561f811fe596f01b620d06b4d5eac98f0a96ddd4b09a861569093a0bfb5be5422682225ccf293bbae50e6a8458fda9fe020a9c8639132b3fe0fe2332184d758916ae99d26ec0bcfb9a9cb81e7ab91cb909c1d566b44ac39964a39d991e236ad193fac9482866d9a5beb46e1800b623223285394843732deebc6114481fba51f05b9b06217d6ad202a50ddba2b2b0e381c54978aec2fc3413ead6e139a222482360aeb459eeff0937e5f2865e90a2b186c927ca76ea5c78a1ce356521910772f665a2d2f167f44c0da8247e8ef0cb61a3a21032261b056a780c88ffea6e5167eb336b513d32f1d29a9fcb5af48996f1762e2c9f0ae026640a4f35f3cc2affa3481d5825b7281ba4d7f5f2cfbefb6d7f49efd3af6d97cbf94f26a4e595a0a9e16a4ceb04d94684025db6d343a21a8aa14816cec0adec15b3d0f4e980539eb5bc8ca65400f3127b31e1ca6271bdc08dd8a517be85dc1f46ffc826f584c5f7a149582b6b18716319ade2d9bebb92ae6b610e8e772f82bdbd9de2f570b5a0dc29a0f8e3fe75375e7b2bb7b08f4c771f0671e672a61a623d7352be7472ab2817d1f8022d0a4270215edcd033668fefa39dbcb25bc3478e47b9f1648685384d2b9b2eb7fccf40b8ea294afd51b0c5f1ba3853c4b3207e562bf69f26be959310dc22d9327ddbbbe966ac58e289d5ddd5aff5f5242619f8c50cda28c479d6f76bbedba2e6ae09ab2906f51fdbd6feea517e6c6db1e702f062d3bbbfc8c446f1119cc42a286339b53b0dcf12b94bf36b0d8c3241f197edd8b72db0e2a4687fb23304272aba11340c8317250c3ab3b7175fef040e1d7209f8ccc46638ed3c3c427699f9292045c8aff62e852df4fb534bda17d4901498d947cfabb6e7be41af29cc23b15c35af76a9201f832b03d363f6e3e6c12ff362a12337594bb49c98e0b1d4328e7e10d00fad5f5ae2c0888e76cc32674f7cba15bcb44ece269927e2ac98fb4acb70cc40f2dc2843554fbb1ef10b58638f823be2efd0b0461b29d71235640bd6dbbb2b2f83654da4d70f226e5d0ac79b39955d6f73b163e285ec6a877ccb4cd54cf80cf2fbe1368c687637301ac95e95d4742400da52f2246122ab1a41a45ad08f1320c28ef5f0e9cce72b0aec9141c04c46d40e9eb2ca38fd864e5507e515685c199ac3203ea1e469973681809910a402f2e5578b33002523198dbe9663a7f82a72ad739bdb44fcc98adbdf976c8a6f36800baa34a6c5260d40b47a7c2cffca251a9aa250556df67569f7cb922cf68fbc7e32daa4120ed0cd308d69217c34c3842988da426f9df708312259a65b496d4b203b68636aafbe26a770372873546a2bf8d6a077d318d9705c626a6f8491efd3de0f2cac12f8daca4f027410c3889375c7ca9ba089350ba71bb3f275c2f0e0e427d594d4fe65732ca0da29e369ef6e0ff4e7de9469568849bd19e935f54ca90634da68d0c300a7bdd2ae00428a19048d83c7f9f8b4fb9a7b44cb506754656a6dec3aab475724d4354ae9ca2ad0fd113fab69d9518eaf829a2780b4346593cf5d53c5210050b98232fcf54d2cdd8b106d912be5ab298b63bf2f159a5d14024100c50e8c5c3b840ed6b9d6e0a15779eb551efb6e0c472a0035550d7059b813c300e36658ae76ce22f8b566cca2cef1c6a7a3c3bad3ed7cc2e6fe3b3a5d28fa1184a9e909af595cb53d2c6dc5b61ff8b52170f41a500dcad85fc8ac697a820812bf8913b79978c88b36a49924239a10adce8aa56cb3b384763e78e3ed2c9e2817b272d518fda6eb80412901014a1d677b3e0197bdd181bd4a68583a13636431b7bea0e511c2077cb0ec301872f4182fd1032d2ca9162543ec603f1ba7cca3326217494164d7e00d306708995c73d15955b7ea4b721142fb93f01c5ac04c5b0b491b10ee4fb5aebaaefb1b26b2b2f065f062242d0055ff1a2e4224a7603d862bbe04670276eb4487b82fdeddeb3df18d2ada674590a1f4e74621b1088cac667ebd507ab3dc41006345fe9b2d570d3fbcfffce1d809e587af2d9a7e3dc0def5729a30895cd843898dbf20fb21eee40a4f5e0fb176cb4fb046e37bfd76b784186035d6a084a0529d067eca20c52c78077ab6dba90feb63eb8b80a0cc183bd440f110cf5abda500a5a9c2cd076289256ea47b63519c9cada020f208bf25a7b442abc214f2e16bf9532f4a160d36c9badfe062991655a482637857c1d2b40cbec1ffbdbef5b0588768e9653233913df37f43ea02019e3efa674186381785484eda99e5905ecd3cbd09731e724b627ba4bd4615b99b36d2a41861ee6a1c8efe534f0b5bc7b392e19509ef663e347122db8a7905eb1e42458772278a40bc2a70fd36d45c22d1f76aa6b6e1c7beb0a9540170d648a444002e39b9a7b1cb8e48bb09476301485c9e8027cc0299318c1d4685d7acd6ad4de3ac6c68cca31742beb9bde45955b83ebc482849094e8c64827021edffa302590dc79f1805c888962fc213c219786587c9c4acc4e2c9015f1d833518005fc7852fa7b4c493c694fede31076290956a6abf8dc8d64b4a965a00d8cbcfdd0d0fa1ef0213e520c1567e6386540a63f6740d9a18aa1ad32343d02fa0e88c63834ab034321bd16730eb5e4cad3e385a22509bb5ab72954cc42e0123c9b85e07dcee830c259819a534514b65a7c7c55273ea58915c8744ada15bb1a42fc7d05972ff8a890fd1139925434f6d206cb3fdf7c9c836c49b2586d8981f3278ee3d07787d0fc6ac04fecba62fa58d75a9ff935d6da79a376df167fd1bbd361faabcb07338903cdca36ec71023ddf0397e72ea4bb7885a440ef85ff2cc55cea09badd01cff211d3f3c90b3989c388f1783d1b010d8f9e25cb01874ad0f9eedd8baf26916c51726b2a9eca85dfcfc35b90b3dbe92e14e29ef70980219bd78d2267c6111e502afbfa5bb5be86ba1f9f8410e28b51f98d6c06ed552c92c71bc60114398eae2e4a037cc8c596b3ed89f3c61af110e4fca63d622a0778d9752e7c28dbfd1f1d889a2aa4d691307b07fe09d005952967178bd1ddae5475f9042f08452835a57812a0b50554818db12305fb5dc3926350aab193d8f8a91749ff663b98b9a4306b2df4a09957c85266d307bb3069e49b5512379dcf9be245b7ac9d0772d9f47ddd8e1d55095f8b1b15a5e36e0c450e2fb0823a9fb0df2d15d0a7b07311c7210ef1127fccdb2f1b9cc6824ba77490ac505767d222d5650896d1f32a2335226df84322d53589fb51d800d80caee5081005f7e20055be2efa59487b1415dd0bad6548b055e3b22d36c9a2c7436cef84cec9faecd4fade345872505100fdaf4a79757d7810cd6b3f096ae0e82739e7a7ed8f2f47704cee3e0ab9b7dfaf3107d6f8b80a8eed394ad120c45fdcb8745529d4426eb042ae36ef64180847a39d2c9a34beb9630a2b87767de53104894dd994dafb290d7fee7eeaec6171786288826dac247d236079929e0b1ac4dbff4587d640cf996378f1b5cec03f4cbbad1ed0704339a6a35fd0d37277f2003162e21e80f6c96375c4b3f6130599cc535309390df39706f5bf619ec2ced5dbc9a20311c50fdb8796685e98a5c99df0da40139d76c49067facbbf32612c092a70cbff6c9df66e6ecbe70b811e7bee38b2e9d82e4126d8c98ceeb0bf08250fd9d44a06287085cb54af57d88bb53a077107547eda346a81df96fdea38c2422b06f5136d31a3ba147521ee68586b2f1bc72d899f5fad5ddc8597d286231aba806c47221fadd36e37d0c5a21f878577bdced59eddd72a03ec3358d4eed5b761163f12f2fc9b6eff9277f2b89614ea60aa0f1ebc7dd42b9d7209e398e619d95ed9ebb31dbead1a09a73e639d04a1cdbdd356a0e26def0c4b97c5c4a24f42e1cb535cc1477bb0cd957054bbf816ec5a2437712a80b850023ec0d270a234e5035f1694feb1f6f35fc770e221a22b4693a6265f1ebb961a81dd2698b3b0d3ec79e5c1d32c1a1ef5fc7d02414b97c292dc8e5455048eabd7cbf5d4d1122d335fa124011afacc5c5a5a3b1b70c065d16ac630ce80edd48a394bdd514b87cf20b677da45a05b9ce1d96e9b4fce5c95e7efe0a5c77ffda330d70b500184d6e14b48a7e8328fba50894a51a5e0310c3e0a344501d0abb626ac9ac649b4d97d90f26855ec3ccd3d3e643bace423cfc63f9b67b3c8fa391cfc986597fed48595b6af17e5ce304814f88a09696e84b1dbd816aac77f8cc2a2774992063be618959bfdf644258530365908f1c58c7f1881c0c324cb98e8136475bd93bc9c9cda7bb33058b32f457cf817b3fccab8a3798e6396e0976175b51da670bf3bfe5372a871558061b0042b8f790e7e5fc21cc82f99976df7493b6fdae3df5e4308da68fede826ca26b9dcba0a4bdd385baaf54e753a636ab7441c9da49dd0ec1617a572be75a1d019379d188721485ae38a56d8d0501497877ba9eaea3c853058c64d17671d0bd0c74110986efc0c8af28d04cfa2f1fd1a07bd9f2d8e08c40be5508274cb7b59dc1372b6918cc2137ebe193759180532d807dce4ec2c43825d7b61f5f294f20c13f4e82df4aee1f48296d21d97336f9c3c988764306be0d166cf17c80f1e72248f994e1b8c922da9d0caec469c1ea24f99349f2a1aa8c2a88ec29db35a7a75ede2ace0757ade78dcb74d3525f550a808d27f0293f6ef3ae5f2e23edaf1665ea47916a1d7f4b56f8c232c9aae3547e08f3d5a560db91d7366640a8d3554377f92aa15a6e1f2df70aeef39678bcdb06bf8cbe03fa257ed804aade860933f4803102daecb0848757148950a79d0e5d8fef97bc60da868f78b6f74b6e4ff2a6be63dbf7c6cbc534ba81d1146e2f339796691d9a60166175b7aa0e3c025b90851d5ed8807c3335f519b4481c0064ad2d1fa8852d5b01fed57dde79ba74fb652786dec248b9326199084f02b012177766efc5b3bf28afc7bea41d6cef6f04a784faf488beecc6d7285b2db3d353e2c1c0ae617e9982428c4cdeac2951643a94ff810f64893151f44c6cb9dbb7e3c69b7e01ee9f1da58b13827ebaf79bd252afa04d11afc3da3d3c018eeaf62d02fd3369f5d2ba35b305b42badb561af26549da226c0a751ca08238ad78acf1806ac4409c2d52a46bc146ebee2883002f9931fec05bb500654549ffe6a8ab7d14773596cd9e00b4b1e246b6fb6551f4306dd7be3271c675d343762a6f2d37bca8d91784f5c6936e680a4d85a82eacb21b9ffd9684db1896ffe29c3e44d6b3b301906d8b440d14c80a21fa838a39e971122c2745cd3a84f2ab36d744b2c672b6bbe12363132b4e7bee6e4965693dce583d32cc39c6cec415489451d2faca45675f1aeeeab076da974e129476f5464b8411157beff9830902ddd29d804546072e9484dc85c5a496cabc752dd0fa9a51bc3371bf08033dcc661d0ee0b5731c090d5959d82727235d51402437bcc3d5822b43d21b4d1bbb8a1582b0536edef9dde2346fa7203a550a55dd16f1d84c1929625a2590c8c6d8e93988ee4c8f937c91eba85e51d461d9fe0dc98a51c1453c2a8126daff85932e602ab861e7d23c010a20ec7b6e7e7c265cea6a0e7f7bb4cd9fb24875236c51a8b02a4564eb0d825b5174a613bccd5c81f1abcc5d106f9379cf91a2485c283fb315e3ad050c7b3202c797e18ef347e7a1ed94645318bf297883e1e8f3e764280e4b7227ac9ac656a5f94e45450ce79e4bff4c9c9b2c37eb4c00118c65678aa0115f4a56804fbfb5400cb703ad16f3b22fe09d5b63ee13188cb69e0deec8fb00cedd8a938afb6ab2880841e6e1e187ef94d399c4a3efd0434ffed9bfb17a59898fb2cfa1aa72a557c2a335f447269d5dfc8bcec3e62374a7a4ed239e4883498c9117518be644686225c44ab9d90861185f3b0b1fc40a0969b9cfab6a20c30826eae1fadbfdbf7537d5b8a842f46c10c32ce7c48df75033b199f6fe19747fec1407230622b921229ce90d0c705eafa470e34c25fc5969d7b00604fc8d4b9d5bde02a70e6f8cf0936a18d1e8616bb1d9d7faa64ab44f3474c5625f587af5c872159034f9bf52b0bef483ac28819017cf4238fb99fae53f25d4dba4422f81814bd19ef20d1aa0ee87b7c0b2cec539bf9d18772fa68de007835938a572be2c2ec668299e89ce3db6166f174426899d34599b69c3715a564284716b6c7d784be1b47d0ffa7f7ef4ab3fff2ecb8281fe920f4abbffb1b5eb17ca79cac3c7107e0e8816a7f33eb778b268a8357ec252198a35c1257d6baba7ce7ff57c9e0db8fef414f030e47454127f992312f01aa2a2a0a40cdbbf0ad31a31eff800ca1b10112224001908be23d680fc7c75446f42e61e09ab4dd0f89fca5d3ec018e78a4182f21f8ecd02e0745d8764fecb45e0f82b51c65a86b1c803852aea03df9f0443843a9afc8f5cc5dbc75a7b39f71f0ec124e506c878ddc0d640117cb5819da33feb8f48735a69c6c19386b912afcb674cc513f91056aed68bd0031248af74d6bed8547ce73c49a557188ecf14bdbcfcf791a8ec210d6cf239d8f3347fa7321839bca98a3c620e6a35b975195c9217165adaffce96001c55dec8b24292150379df87e9186d1bdcfaa4bd6157408f35c234f887a8fbf8a62bea6df3e44fe2b87c4f2577a878fc0655d0ff6fdcc8ee8c24305444c98082773c53f967c3c7e35b6d67837c2431e4d10ef2a551a0a945d954b2d9f051afce62a3afa9e09975fb09221d9e32bead756ccc17a64fe809b79aa91040493739e9e5208c4519e4dcef18077dd26435467d58af049eee3c642a9c466436af27a0ef74756db78a0e0a92f585ebf9637be916ca44481a3b0a8b0dbc76045cac7ac43f8b22e6f3e2684407804a01b4acc5529f397fb9800793c537e0fad0672cdbd8595ad4f0a7efbac7eb14b1853e62227f33c878865ff114c62e1154e86dd8f4aa004a812ac374703e2b55460f86fb26ddf6b71d7d06c7afc9b20441f1398729c3ba8671138db4aa0920b8c3b027600f3b83eca208f957e658a52210afb6574d9edc653d4b4cc24e57da58d0fd6bc7c5cb826b7d2e885c234e7d2e61c4c63f751709e813bf2c5be994812b6714c8da975e2b082656919f3d63ff5d4e86d34f58f4db36eb6fb88df4ae2f9abcc753bb2c0f9d52b8d820c0b26b339bc78f599f6dceaf7216c851796a92fa7e1152a67ff8674ee278b527a8c55e66554515a09086887183866ad55c864c7c7af92c2991e53f6e50aca54c57a22c1d3bc88fe108274b4198d315815eeb703c2066f5fa3f7c161330598688ac280a8744521614af833fb6339d265d371bfaa796ca06aee542a2ba18202621c327660366684e512aaef7da4e44465f0dda1b74d95f3a5e7f5cfd47df933db721a776dd124bc8989471c842f636c6df2c8c9fa7624723781f9eb1ae23aecae343346c619247e06bc8c941ce0fed80e7fb0c2944e8048acb2b3fd7c239885ca4eb4e094bc14418c87ab2d20822b5d7da3fb0368797e480fc130d39ee276b11c81b4ea568b5cda3e9196aebdf29cfbf6faecf1951d020c027f8933bc00f4a68c5cd9b1b4910440429d430fa70f4193e9806f899b7430fba92d36ba3073939f26cd6817887e9872e500dd75f62637ddb84e6443247db35dab3f8b48b995c79bbf7926c2dd8099ada56f949ca286d195c7913865ea618ebb348d9370a9858e2e1033ec8bbcf0b519f14c3388f198de6c7c8c9a3a1a2f4e4de4f404fc68f026e02d58840db0f2a59bd150c8dac3ca52b5aa0e6688e387a24b73bc8fb2168deea00edbefe2732a238e834c58ef7c65273c983bc9f461846b482420f6fbc075a171f6786d8d2fbe1cd68a5ca9930c13a2bc3224fb5ca48cb5ea671fb74b63d7f01016a137310d9b5b92d93aded60c88635757ae00a71501a9827d0f06a39d3162641bb8218cedf86806954ae67ae9f5710f7f655851491b4f8923e66232800f207f1111e51913b9f3727694ac5ef3afe55eff07816e36e0bc030b74ddec0283121d7a9218629b1bc46d0b3b0ea014284511139402b6035c3f5072fa59fa9c5eec7618add7d58ecd919d55efbbca427a951d5f557fea10ef01d9aca61b5ac15791f681262ba244d19826a291ecfd9b5be7190671115366f91f3445d68f76950eba992be62af0ea34c99c04bd1bc6ea7b4f54962388fdb862f8ff9729284586db15d5b027747fea6df9d3f9a18c20424e00265286238bca8319e31985c3d729ee32cb5ada5efd601e3160ae452064b87f0294d1f962dcc163b030410fababfc79a830725cbce6f07dad5706be784575edc517ca07d215f7a407d5e96124f2024a102b0ca92e8c2b8161c74fe557d6afb41473c0823950cde5e61e138ca4b828854711a91136722dae634b2acb74a95bb2a9f2a720f06d247f40c981bf304cc1e28f3ee15c736c593a9b8f40f310ece06b8f71cee4293ef940f3c7014ee5c15ea940d556b910ba979244a3973da21213be483cba240df432abe38738853ad88edd857db14f81e353d57127f682a08fe39db77058a57f695747c0771c433de0d0cb90c9a40ea60739c4557bf088adbdc5bbaa6a34b4b372777c951b56aa989310be2b05e7d4a24de725ed16e8b1baebb5fc1ec3b23ef6ae9f1fa14bd34f372f37c4791f3fff39d3e6c4d223f6effbb341df6af741039bdb665c1de600bcafe1b5d5b81370b66570a945998761236ec75832e479ec9686eefcaf63821d2576f18e503e4f429f70211a37124623fc1dbce40373cd97bdf8ec2cdcf751eb10828b5916fbaa5420bc13745dfd9e1bc70eb205e165c244030dcdd6d247c4904f5a438d969ce1c331741b9bfbddd2f2acaed0f510163335093f920c1e56dcd7347cd21921573535f4e2a128204f1645ab670fa1c10251b2a1f9c2de708101fec95c1f9a6200b899bd377cca8428b28d3ed8f5da261f4637f1f0e4707020bda613cb689e667bba760dfd3641f948bca81c80677ec8494e4b7569b03aaa4723a562aeb3e9f60ccf77a5f6a35239b239034ce6dae085b94e4bbab180015346338bc2f283b28b3295f94eb4b7b03066989609078b85366e97a2e14832a9d7b1527aa810db55e9f15ede23e04e65cee9936c52d397b746d9575173822df55c4bd5b97bcee3e856d382b45384ff75e3cc0455bd6e6417b1f261e19d955dcdbbdb8d3c004673b2505035db55f01f07c91e88c1fbf93838b0ce4a2374d72c1f9381f40ba569c2eca70b32685e6ee5f3065f8a81b2958336085ae4c77f5acba6f99d745e4cd6e7b01817a695f51b646861714b28ecdd44bb36e670553aea7c17f2bfda800ca7417963653f78e07b9d3e6de77cf7c98f7e41ec394f68da5cbe1c2e93feb9271de2f5c3d53fc6d6138fd22f38a2d73fb0ef91b4b1f8b2041ecc6daf0a84bf38e4382cf07e1bb38fe4c052bc9358fe0f8b63908112a2b797d17515b537b43997e536e5b97b439d49e7ff1ef6e898542ab1e9776129a855f98dd03b9efd6331794d19bd41c1cd47e916171ca1711fe6d5b1b48d1a28c0af243e2d56c7810d267d0e7a44026bdb412c70277f94a75db1ae36e159fb953b4e75d7cd9f5a1ca848f5fb197a8c3b67c5bfc664a8393a2529b7ffddac3a8d8b0123cbb14dc56e87950966e3e3db2df262f87c39698bec3884020211c4fafb52f6a541105e4f7ae89b05d32a680e515fb51fd7ea236c74e178c7497ff38488855c9656bd14edd878a74ad79da31ff769f25d13dabbcfed490e9ebdbd140a389de6d1f5fa3ed5037342e3b1419b7d7ec53411099aa5b483d82aa73f7392053d75291914a972faa40fac6cbcd9480546b065b80bb77f61c552b4e88395114aa5b1ff74baef6ad0ce164ea46d1bc1e7992a3ef8296e8c17ec6bb18fb4edc44a2d00906750785f08b65e4149dfc08ce6431ffe33c9ce4a3f84983a996f27ee2767fc037d427a31c4f5868abb6d9db019fc7ba324f6bbf0d5a2d3f8c5b6e89b33cbabae091323fda339731fa19bb8e377867dd2c276f3bd12b99a79854530c9da90df16772a986b55b493a61e86660845c48ac5c0851ba3ddd0588e074a39193e8b95c06965fb6476f20ee97bc60ae41fcb9a504de9f5f194db5242987baee32222ef89e6cb0616f91474a3600c577a76ddcf9a2eee5c8cd70399a825030c83cdb88405d4e71d6b3b4d8e177a5d8b6514a2ae51cf6d3d8c9ea678ffc7993340ea3c372bb0e1b5ffb9555c9df1bcf34f89257cbea6e998cbbd883bac8e9fc24f4292f082b4803012760515eed6c8fe4cb4d06f6c6dabf708e558dd9922615bb030284bb9af3ea9fc88e549875b568d51f92b884771f8f76977ff1c95f30caed0ed6c3325e53a29280b75fa4560cdfa5d2be8f83767600a4f762d620c2317387aeece3e09b71a4a90f94a492ae0796743e79b967561ac4935c99ebf9db67453b15d02272492c6c58a2e22e9b5679273f3af20f009bea33567dbf5905328cbeaa5ca0b8fce00cd187546036ddd8d96970947f5e6d853d66dbe61daa8ed29de4f10078085c7ba34723ad5f900f7504780cc16e4d98e9ef26df5e62ab1423928c5dbb4e033b8ac1dc8254ab34c697447b06d2ff38b678aabaf70469993222b4ec6dbd7e5e3fd80b8b082dc81867f0b327f2f5472d5933ba407808f65af1c9960d2cb4f60814af02558362a1c728d207fad01996ee7cc53aa865f43f0d7a2d35307c1b0b8a8c84f2180ecb32029b13767025c2fa4da06aa961f554fe8c2f6b06616c3529115628459c60468a75b3c81188390a91f1eb0d1c6a2601839a031ba1c63ec1284e53498cadb9d920fd0acb2ef7a8a1f2fb433eda5014a1c064d1dcc7461eb32a393f2ff5839c5da4e6e0417c33248ba40063f3dbf16230a42a0a0a6ad54123e1a1b4fdcc42b3819371521915086a970aa0a4b0e1ef22b34346ea910d7466621d90b58b7759579311fb66721ab1cabf7dac09b718fb1775f3a8f01794b76df1a28a7dc184dc4c783e5ee61044ec0235a6c5d51e439f13fcaf06dd5911edd9a55b234e9cfd6612fb1752d249678e56cbf05a56e4941586888717d8abd697eda5b78f9ba4c8e3c63a43bbd3971182ab0c571b9fd253dd7f4aacf39b28b140f01a44f7b5fd26fc8bb93d5a3047a0d51f1419ff5375dc6f6e67e66136fe6a44e1fae4bd551e6b63e72cc86f93a1269b331c0c98952744b49d9bc787aab00c810e2e50633844ead1957370ea00b70e0a31b97992a3b8f577522b9b8e1a21a8ad4450d46efcb0db4a70f53182caf124e5ad2d92b6d8142d38814a6d88679681631edb1699f4ccd86b19f7cb8ef77a23258f29724e5bb58ae6aef3eb81e2af36fc9210011c14d6e70eab852cfb02b53cf02cc8ea49cdd0c5732a52d0788e017e71858feb5abe9fa94bd5bbf91b861bd8ebf8349a136a06285ae9a6516c3cd67c00438c97047116d108bd88d6f7bede743acbe430a775906e02319d7c818ef29ab7bf1b5e4de07848d63c0a6a546d7e0b42fc5a700de6104170cb689998b191915f37c6d72f4ff008ac460268c882df4760f010fe131f0c394d50d528c1ea6ad08669f6f75e4aab0fe9ac407eb44e489a049a8cd2515197df93610c8e87f9b3f6d7dedb85f7ceaed329396a7530429ca618853e38bef028a6ca2031a384953ad77a8309384376aea877716d940c42bad2c0147f00b50fe837a416c7f07619a5b4c1f5463b2563c206362f0ca798f873b666c2dfb367ea3702f7e0de583fd146e95d6747f324089a92ef0284f13bcae868317f0f31c1738079d816a12e9eef74160107c9834b6b60357a0cfef44d6dbad39b83f899f396537ff445c8321e75040bfa6a7f31de3265c79ac4ce12c6fa21053901bb34f63791b6c069d576897e58ed1c050537ccc719472726ec451835e3bfca21de0ea0064cf1288ec05f3f0d460ab2b5c85a030f3857480416cbbce9c1f11f8207dec4ccc3516af577f4c017e6e73edc756de0c2bbe9da874546cec4aaa75d697679f1cca743057dd849c8002930d3b25178255bc8df427011eca7adcc9b1c5f1d9d2f61dced6a89d4575a5e3be4576ec3aea7eab0493e17db5fec86afc6c2ca5474da49293474c850f923edd983146fc12c4df6bb7dada948e429bddf43fc96ae4fe83fdec356f023dae998e73f71ad587104c097d4b8f44a4286bf782a063b531620b2f9a7d42da9663ee7793104dded551293d17c2cc03c07a14932caba532e9024e14da36ba0b888bf8ffb60f1fd6348dbb8c235705b8606501eb504b589f0b836728568ad6e27cf216f07117b9f3192e63ff1e0b18a1c359479882eeb82d149c4c9b2728615d77fbe6aee905195fbf7a7b238d3d0a51dca345973aab5575435b4d727ae0373b138d2217b9f75dd243b5d716883e7d451b3c61939ee8854ef429af1acd8d053701266a10f575694c998524600ef23a121ea5b572d796c3a0faec8434d92383da0f717b5345c3c53c7209b0c8161c87abb616d7b8e1f5a3e461cdf6779be74bfb93c2dec1c72bc0a918ee95dbca9ab17befd1e4032b81af47b7d733a122c418cd52748a77ddf36e52d87bccfa10354ae2cb772037738884b852e3e187ef98bc1b4caab7819814650ebb9fdeb102c69c425787dc9ff25d43938808d9708aa5f2d40ae7f748ac08b5bd37e8b9527541ed71895d4153322c30bf4201949db290d829c63c3feb6311ae280d01306e47a8ed590c1492606ca8c8d81c3ba98d42ff64d2c95cc35b239fc55ae507be8ba891c567702da699f4e8d54c01f157ca3e37a6af86c643980c57174a96ca4ce0875c883728e0ab842ed37ab436c8e67148ea92ab7db6f077060ef6481676ce4198fbb3eb93e5e1f7e939b401659df3d18dcd1e4d0850ec9b33ffbd0666347b9f90a53474b74b611c0b0611a5fa642981fcdb963f6ab881fe1a571350b4eed6944f9cc4a5cd946efa2dfbd67b3f6cf383c27ec53243435c50d01a800a7b47cfd08b1e7e88f3850ee5e62a115af06b7be5a16a9adbb437cbfbee22c42c9d077bf708ba0c2602699f61deb3368de25b68b8d864b9b0bbf0112f32484a2b89481807410370664620f154f1617b9b67f5404456b5bd25abc542119d5e76ae7bb19bd6fea2055ba89c3b0b530178d5e1d1a8a831fea20475888857d552d5fda04e0335aab6bdf106792ea13dd27b2c26985453f3bb0911f4bc5928bc729fde5e96245bdecc1a0","isRememberEnabled":false,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"604f4d487796b8f244cc8516078a19b4"};

            // you can edit these values to customize some of the behavior of StatiCrypt
            const templateConfig = {
                rememberExpirationKey: "staticrypt_expiration",
                rememberPassphraseKey: "staticrypt_passphrase",
                replaceHtmlCallback: null,
                clearLocalStorageCallback: null,
            };

            // init the staticrypt engine
            const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

            // try to automatically decrypt on load if there is a saved password
            window.onload = async function () {
                const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

                // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
                // replaced, no need to do anything
                if (!isSuccessful) {
                    // hide loading screen
                    document.getElementById("staticrypt_loading").classList.add("hidden");
                    document.getElementById("staticrypt_content").classList.remove("hidden");
                    document.getElementById("staticrypt-password").focus();

                    // show the remember me checkbox
                    if (isRememberEnabled) {
                        document.getElementById("staticrypt-remember-label").classList.remove("hidden");
                    }
                }
            };

            // handle password form submission
            document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
                e.preventDefault();

                const password = document.getElementById("staticrypt-password").value,
                    isRememberChecked = document.getElementById("staticrypt-remember").checked;

                const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

                if (!isSuccessful) {
                    alert(templateError);
                }
            });
        </script>
    </body>
</html>
