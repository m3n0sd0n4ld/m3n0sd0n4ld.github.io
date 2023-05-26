<!DOCTYPE html>
<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Weasel TryHackMe Writeup</title>
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
                background: #ffffff;
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
                background: #17191A;
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
                        <p class="staticrypt-title">Weasel TryHackMe Writeup</p>
                        <p></p>
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
                isRememberEnabled = true,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"3c6de3c27af46929c408a42b692f6254ea733d65d2001f83b8b9c756d13c6c48014ee8c8e59ff44881704b4eabb3aaaae0b13c4f3e3f3e8747094df6642c32fe615695d1a4e8819ad356a362dc5bc57bf3317a257f2dae26aab84e29bb8a141d631ec133f3d15b69abc37d4255c003a87e48ad168a879f2affd8143bf4bfb911a377417126599a5367b1695da02671570712779fec48d559b2341e45d8dac3cd4370160d2268e9889b61cf50de78b9c72883add89ba60821b03de4275961a1c99eb0c81fe5671869cf562ae9f808134f867384b81dbeb2e2818ee1a4ebd0f8672aab0ddc34d7ad663ab17760349e9fccbfd629176c0f15ba43e96b0e0f3e6e952eba965498f2039987bb4a6accb08f4360c99fd450dcf6d6394d2fe4ac2d5b1a100c90afa211d9a9f6b903e687db350b40e46fd511bda3f9ed0253dcdeb7799dcc5b1210ead651921e0945fc10f992b4832b258879bed6c17fb59b86b2b219b061e36501ad498039d86b754f5e5234933b930fca6de78cf79de7c704c7414d9564f5cf287d07b0667db40bad866b05f011e3cc60ba1e879deb19d332fe7fb1698b552b2cf8f55c4bce97b188e19935afbcd2787bb993928e3503a411931e9247664f38596b476ce0499db444534c7cbd27612605bd1369682d65e00c4fe01dedba8f7b36e655614f3e4730f40256bdfee7fe924ef490ebf6911bd8c14f9453da3f0dd682c7551e345f41e22a60ddb3b213b6146fdf5ab8ca1ee2b1f6a95578d5e4719e019024f5c229383cc4cce16258f6bc0f66347e189580187c968e8f02739aa85466c828bd1fbf467f6309ba7b7e07215ffe95358544731ecff95bc838d35d2ac8686e33312e1534f2e50628518e35f51b40f1230b5896abed3d774ba17d1448fd13188deba096ef35a5e5ac8a870bb90978bcbc271dabe044ac71fd9b418d909660517c3d773ebc6ffde8dea98945aeebb5f0d72fec39254924589261536376ced9815179a0646800ec6241829442dc56a209b1ad14ecc1cad50e2185f33ca87bae1107a9e40f235e5c2eca8640b8f34313ab044f22d94933d29517811c7dbaa7a9344995b4f6c90c52e1d9628e85246ec17f83757704efe02694485be8b0897e6cbec714ccae3fc6115500c55aa59371cab916001f0191ad84f14a56a56847dd7fd2b8e3a13b287a678d569580576476a6831b0a54e4252e5d2fe30d6a99c3b619aab99d197100685327c7b6ec4656bf154d8fcee9a893d10aa2a322d54d8374c8fdb2c492af341cd4859a81673dba20c6db32386dcb129a3e8b55058039a06c27e7eac5e5d813916b14867ed99c19e43e2c83a30aa7df65c94711cb8c7485978b21b85b68f08b8bca48915ac5a93b5bacff20cbe4ba91a7f4ac4533af5302b536c7c93af56f2a0338141fd190621699a080a934da0e8dbcb673ccb84e105da2b5df0a020ec138deeb635bfc38c1dd1a1d2866bbfb1c2e68f20c8310f7aba437f1cec969362d38337543952ea9209f6bdf89c13261f222bc517f801019acc1e10d0ff0592a7f0fbbf2f48bdf330d6590ce8c3768dfe5c1a1861bf43fb90a966362356dc43abd68653eeba85c05ce1290cd058d7f0c67bc8da0883d55ff166b6fa540d190273b09f8b1b5bb813d728c6b9bb48b190b1c4e647c347dd5d1f75e7f017a2bc687cf0c317a87bbf1a41aa4bee9fc9a482dd6767d3a2d89396678d7caf630b0bd5d9265ee699ba9be35c1c92538ddd7e622ae068f515c3e43f635340b43e9da4f7b38375a0bc5a18a500affc23ec75e157c94478ae8543b73a408f2454125e58097c1d51ac2b00d42d5061676e843d50be73f92a36973f6b599a1e450c4877d835b41e11f7c1e56f4817cefbdffb5a4440396c48209e45136528c4dbd284bae9cce28d4435434d03ed01121b9e1f798753448ccc575f57a80508849e9b46dbc2fcf5d064c98eeb9317a4a95a5c3ff872ea39f62df0234bcff609a953387257559e4c30c5616c6e5e046ffd67a5cd29af60ebc839ca6e85ad221b1b67dc43ead98472b15b544dd392e3490ae1b49cf59084f5faf91cf4bf07f478dfe24aafe6ef0639dce2e731af96ee10def48904920978e74c8320f31d8b3ef8d5e661f274182b3fbb189fd592ee4e7d76a3534bfad9da52d6c8ec6960f2727b36ac3e8cd01bafc30200bbb2437d603aed2a05a5d6501d79606ea356044c61e8b1092709d79bccce3d6dfd7a2ae2fbf8a8f000560a9a18b1add9c531d3f04462cef26b8874526ae5074178e45fe5b559dd6b26da25c039ab61c121da14c085657f93ba2ce5158cc5f74e8c2e643e14076be6d26e529b001bb761d6c35674ea3e04e2504fef4eee677a7dec6dfc9daf105f72b1e8028fabf9bb17a39bc40c8d9129b8709a3d0c27f0f4da703f06cd1f146aff3393bce59beac492eb25dac4383b178284f32766679ca9d5b99945152705fab59ca4b3167a7c5addcb1763ca7c8e3d05bcd51e908cc435bed1d07bc789b48bc94bb99b61a5fa6e884fb6dfb6cdbc02ba1eec01d1178e02d04728e4bc62ec89c258c020f07f98e310a7f9a290bae0d2d659da2e9a7eb1b0f657fa14eb47531fb8ad25fb510007dd35f0205e8f878c10f1c17a905475be03eafb194e8a606175b16c0ecf66cc546c038b7a799cfa7df02b42f5d3a9dab35ef6858f05e209546ff2f38868f3bc3e1987ea77a8c2c085767a499587a6bc368a6c0b1f2cda303102b3335936ce5edfce41985a0ec9fbcf2e7daa55ffbe7408c4cf700d288e63bb9015590e78d42b483d44864a38ac477cb9643e5eee7878870b1902c99614a5187136bc0338670085ad53610ca5610385a66405caccd4e395f1cfc87c20d5f1045de8fb03b1b673864a705a4a924c61b176eb2e77c8230708e8c546c16b273e7aff823ed4fbd6d2e3c6da576a8fe3bafcc04e56371ec4a7e0311b0866c44bda8328a0fecb1e9636204b364820447d82479bb475e0d716c82bc3c1571c1785032c92340605e2156440a69853e6748d01e7f7300c19739e55cf169033c69842b2f52e6fe8bf8d244a7738e8f7c006dce4c8a0f6c3b477dfb47086ee04576b04853b4552b6e166ff2d2cc49ad063574e15c0fa49099c0c9af8caab8a779008f6a431b12e8a4595a68ee01b451de1e9ca31718abfdbcdfd343f41c4551a8b1e09cd39c0fc09241bc97c9f0acd4266e2983203b6dac3ac53ee5beadfe6931079fe79e600f4189d950e3389b413c5bbcc9c922fdf40a2014b4c564d2b985101560a02a6960e92a947fec0c5d14616967932fb5281e1a617961d4ed04e2902515bcedcc5d119971189788d72861c171cae144054703c02eb6ecc18302df685e221ee94822ebe06a0f745c295f61afdcb14c0b94f4b24a8e9e26151d02a3449a99b8e2b4728f3d9bd46a2e04603baa529e6424a2106efe73d864abb7031302adb1ef6db9c583c69d0bde49887b57210facd82dcd8b3c417496a78305681fa2873f8a7ffda04fe7add2272a217f735b044e0404cc2089f92d4b4c5bb2c96bda56abbda8f7b37138317ce4796cf5c9f06c3b0cfdf9c6a42b347879b2a2feec639b4f72e308f514e744ee87d7d34a5cd6b259ed89f0a18250f777aaef96116f9143d7c6650f8313edcc48eab3c0f5fc1aa447c2467d5b9bc9bd3fd9dd0b9e1ce84002e092133224b69fee91775e396f20272570dd609aeda2b34d6821acd50714034e2747366f7ad59bc2667e74fde7294531aa076fea00b6aab52cc86f3b243117f8341db33adf05a2d2ad722819f2d0dfd547bed35babb3a7ecd8d08b237f63e5893e1a1abc6403b57b58424cc90093f4cdc569badd69ae808903d953b985facf33599e6f8f6fb48da015d955d02e1660369457cb7c67c419b0cfa06fba738f97cc3d81597a095197229d7c4246e7dd3d524aad8190d20a5908455cb33d67cafb92d2daee1c85757908e8d0a16b5015814617c7930fa74b6b4f747a4d8f143e0bfca221de318f27905a5309c6f0807a623d309721530cf92d9d4cdfd64f8f16ef12de09da2d5736efecb8cb36c4ac7ed17fa778d6b42a94e9039de727a4122e2cbd90efa89b84be2419d04b278a898fce9ef495efcf9c4bf58c2464d56591688ae3901f127d738a1d839559bd4e239c108bba1d69bf3926c0e3bf5fb12b83414aa0a2d3ccb4d8598b5678c59418373de2d6cd1354e9af65fcf20df24b42b77505b9408f6e1392b46ad5d0334357e056187e7f9135cada766ac54820246772465f149ba61a240df012e4e5e9d8b7b518c945f57d744e49761cf5f16cff15c8f7c967c26e247c68267f7a4a7f2125f8b145964c97f459cec3cd25c4255a0f212f080767c34d4bc03491695ae42f81cc40cc6d5b4b07c588406b5e0f6748fff736004576a6955e6407ffeb352a07f4de308a0b28703b4e763fc5f2a7430e011feaa94a4621dab1ee1e9703b3c7152329d3dd16942c0a7c9459a1dfad4bac333da3123fbaa22fbcd707bbf9e8daa3bf1757e3cde51b5714f20383bfce88a00d62e2b2a83e68424995d9a9ff2897e7d6443b81b640b5c9df51098c58d2b0ff12f2123ca5343771a888352b399861cc50f76a408beeab1f02f2e615713eb8381c1afad274decbe3341e1f3f0e5b81880da42accf96ad098aef54596375c9712696967d606ea4cc76fb1fbdebaa7ad10c6b8c8bda02fae3d23be9513362c9e6cd470b2ca2312f9273417f9ddb642edd9d9920d01046626180cae518095a332c146e59ec1aaa4c494c78ce1e1841f11dccd33dc80c62069750b4d0fbc0a65d77abf8721abbdb819eeaadb5961ad188476a2c8937a84589ce8b361d89d59de307f0b8f27c66fe8c3953bc2f41cb6751cd59630c056843b2109ed0b68c91bb383412082768d2a0c9901a76e481fa7a87589ce12f14a3a3cfc23cee57984c023ceed7f5ba5d391d55837673fccc111215bfa1d2c3556d4ab6093a69d241b6c3c4e718d74203758c0a7bf5bda7c69f924615469abb7052556b937f34ad38b65ea3879c284572a7a0f0044244a017797d1aae25bbdb43c8474d553d5f966d97167df7bcf20ba530513e286a5605904e30548adfb478a4b031166abe518e1706a17a3c97216580d230a10a776c7507b9bad0c3ad8f7f41b0646c723d5881d033124e34533950d86690be8e739fd3792d72653ca7811c9cbb76fc21cf0fde5ecd904a30e789c5dbe4760c7bd8078ea73666e5aca5f0f8863685fd65e64d766fbde12d020280088ce7764ef35754503686d2e13b141569b425f15ee2fa13d68dd62635e01415e681f2c6ac0e7cd3f91cc8c5afb5bda51f672e44481793ad0670ba56066a4f1748e6b450178ed2ea17f44c1eed2d431c6ea2f7b4e24f788aa99db5a19061fe8551931ca76fe8883bdae2a99963970b65563db908526edbbc5e193bfbcf759b57c9e90f5213a05f8df963b9fb0470ca202402dccb20da47e56560359d1dc0978721907bdfea5a464a7808bd3da3e7d1716acde62dc95c7f15a58d03436c4424ad703e726d7ae14f1305476eb5528f6662b45c821adde6a1c07dd67193579387c7ab3f9b5c11ddca791a1c441a82bd8531f109d968e08cac770a51572306b187d854ecce3d3d75115f05e6d526c073fdb34a8bb23649cff077f0831bc90043d20b0661b173250495719ea92f05141068be36ae99d9749973fab43bd308bc4b5f70a59dd88ec0d3f685387b80663295f5fc4f0796f8d7684a45fd1d3aba9c5f331400839ec46de2fc79a2bd4ef8d4f1bfa9bea94af4ac5fa74a0dbfafdab4d68b704055d6d40731d5f5c28077b782503f4dfedff8055a496a3760d8d08d4db56ccb94b9b50a2f2076f7abba72700cc1b698aa71038902d9ab622e78fdaa828f90833ff5333ec60786ccc4d17aa87f27ea174a9bdf529727f8d0fa914d6564592d8bedd0c4d4673d4696c0ee8d1effa5f96fa28ec49a8c5474fdfc72981a3679bc3999d3cf2937549163c76ccec0a2ef320cf0bdfaf8b16f10ae17899bc72c8e29623cea39775640a4b0ab0e037a36cfb8428e23a0530446bbd9ebea358c7c4cb6ef33db1e09ea4e30e0c728de10c99c2291638934c5fa21f6f420d11e19b4aa0c33485101aafd2f0f0ffa9c25bd8af845c10f1526c3d9013f6240fe79f96811a60435763a97cf4780677129130055ac98fb03bd747523a2a1ba52f5f2fe34b9e9d42113283a39ce424ca89c1f858590a851e638471c90b3f045e12fdc4339c8d67d544b09b47f345f2c03baea8bc5d9c1e7f96e93910dd2cd12ca6ed08e7d9101d7ae87901921aaecefaaf39be66d37932c6fd2ec7b5205e42855968dc2afd2932e65c5a7dd79a1eb5df1e13a841ec4a7ba58019d14c2754a231e353bfb9279bf5d5909b7bafb93a514efe8dc31c38fc404992afad01749b27ab71b3847d6200de2afd303272e525b22da87244d0ac750209e68d7ad63e9201bf3098113934483fb5625068073d8b70bec14ad25f2ff4d4be3d153fc0667018f124881c8b9f994e39365cc8da9277c9fdbc9da33a32f843d9b16ce052ee380c828dbd0ce7833ff7c603b840b49f4364977d9791227b192399d898a88bf7f00bcfa7e7072bd5a9278fcffb75fa73e88e68f5362d4552ac75b4108bc9fbd40f5be07472523530b023a2f007a0632c699147bd0dfb44d78118a025aec2ab82ab403329487c399ce343bcd25934fe1e304c30906c21ff7b40f642d7af09e5b1c92293332624c557dbc41643d884f3cbcead0d41e8bd86f654d0264d7d9ee747b8936e6987ccfeb617cdb3f968b13234507ecd4d52f253bf2a3ba1183d06473a4a2018be2c6193b91d2944e7898ca3cb77d1f6133f12c4f3fb2e56732cd0504d2ad65ac645f73d5f6f4540cfdf8a544c301067cb2a6f005178bc4ec66ad71bc67fdb9a2d04dad41565aa306b9809f7bb7519eba96f8a5c036c5ed0bf3326c2171dcf5babce38e2ecac78e4dac61cef1035424bc4a3ab224bf0ce41ff66a39c41ad58b7dd37308cded896401bb7965007fc0284122b1f0ea0f82e73b5a93b602d26483abc4db322b172db811c961d08dfda7c2574c0352139ac42387313320fe3affbc9ee277e2517f231162e8392c7bdd26f60441be67982bff2673bed92cd8a10a52c53194f771a15e45dc09fa8070c94950e537c9e8e98f6b1766cfbe6f0d8f61b6e88a3682c9740e1c4e8dc9fd3515205c09d7a8c424a41650087187f989e807f625ebe381060a8f832fb863c0c86120c61f77bef9dfcf462ece028419a184a1c9a6649d778ca52678d2110315a740ea41bf8e5269a84acde662f5e7aa6d7024ad5b5ec223bf467917451736dae7e34222ed39a8f44c64f0e80d2320b409691e751a4a0370eb798e0ca2af65b1fb681485e050661d2f3db9851c142c5746283fadcc72182fb254ac0257a0bc460dceafd050ce69eb72c1af3aa9018d5109f342f8340dc81f09486ec8cc436733c95870abe3c5be0898a48eb8bbf3fb198b34fc53cfc39bff850f4180fd6567bf59152ee84b3efc78d1f5da6b2c6299cdb82f8c82d7fd308af507dd997ad48ba37a77bb16f47166b0346ae83c72e034532815baf94cf7d21edac70b58d7ec061c3f3b6d473b049e3b297bda513135f728ba83c599c60b50ed6b2fe1302db831e7d8d2a3bff166173175424e693d54b682bbefdaf2ea5ac2909728b992480d21b47d341c0624d9926c542a547902a2c3f5c85627b1d8e11de15dee5cfa76aedc38f371c6de98772deab7a2e4f1afc05fde32b538867e639b48e1e85571629665425b64f53c0504943b0f711a07f617c01b705678e0f1d9330422bb3d7b3797f8709207fd0a12ce2d249fc953178c5b8a3fbf065cf73d3f5573b2bda0280ca307ec422fe5dc47b879b2eda1d55261648f026edab1b7d02fd204332fc3edae784f954ca0f794c6edbc50c13524e7bc3adbe930bfbe0a1e185a9751dce5bd76bc8cf6fd78b55c26437f9261bd81c71e8c9dc839fcdfb3b692430dfe068d7b5bfb68ae1b683d771bfaf50c9000bb1cf3d74801cb343695786c6e60a6f95bf7a4372dccf1ca31d240987223f73a75f40062bf9ebcf0784850d6f1f0430743ea9be1c3587b7b5066d3b7e5e4615a5f3db1a5df306c453f81017bf917a72b59db4e3170bda44225b81975bf78e7e2a8af4144cd6d5e9072d94662ceaf01446d406e54e681ed771090de7acf8553b252b586b2cd25bbead073133f928797b88fe3f3ebb0c661551f94293dfaa29b5bc9a0308032b121ff07eb5b6d470adfd2498c508b9d582e0bbc27921a26ca4dbe358ee89f1027ec976547201f0571a2c40fe0449af99d98751de86976c19c0c49e7a1e5c786842f081642369f150027d334093884523bb2acf65626a6d6efb2d209d42e84a7d688d321e8c71549f9e2a1074d74b05c595dd9eda268ef7778c1069560df869a7591081e4c7599e84743792da7e1836f9bbba36c174fba0aeb8eca7d73090b722b87a03db69c6738d7c346b7e123eeb894edbf514cf8ee92d4c10c62113ee06d8bb82f56cff0f8e28792efb222c0b65c62c14c4b047d6f1f75afc7aba0bde69f4f6bf1cd7c19b54119a861205e978d7852442753965cb29d31afa440d348673268a891f24f22b5e271ee85e53118d162916e6c533bdf164763b0de5c88afc4da67bc636a80bfa2c77eec1d3a9c4385e948487cc9ff41f6c8179c1fcac620e5a30a850cde6024bb1b3b44e29b0f78242ab673f0bb090e9182524745d9b4f2e562d37754f818abb559c9e91180ef4a384029edb4a6526ba6d6f180ec3e4205d1df166e5a65305ba2614e5bb71b3db44a96ff1818cacce5db33a2d3d91974f83c0b8d077f158e3e10e56ccba2a8ba0d89e9173457fc0d6dd775c7ba4b3b95edc3c5affeae3889f60eb4d34890eb0c65944d5834f12a1cdd4bf0a39336bf044028b8cc62bb85dfa8a804c3d93134b712ab7411c126c36d86ff6755ec0c633aa2cbc1719af5a4fa0145606ab22f9b704ce2c5e09ca1218715210ac7985b298ded2b46e3582288b68466a2dd406203dfe150b0a4a582fb15550bb974bbd17503a320a6ce67c20d3bd0db4a829884f299694386bd7690510a81aa34b0c0cde50e597b93dfa0da1aacdf44dd7a81b94ac10f508fee3fa73ee97a3dc4d9b61dcfc9c82bf7ec941af5d917aaebaaf3a544de4489f0c1893cc13dab2384d55fbe0a31884f2c66e0bea6c75ec4c8cba7dbddcf94b77a47e53a902638bd990cb1954ad45ffd2fee5689e76dbf4257935cd7e087b7261135976f1d0ce56fd2250060ea53369df41e39453e24deb78063fdaa0951b4adcd14844d066d3cce4cf90c20cf7e02e47f2441f58747185fd920c3af9f462f2101ea4eac7a712c37079898832f6b706f0adfd322c0554aaf2a6f6f6e727726e9f219b438d57ea228d8359951b16c3efd39d25a23ab3139d8f1599a2c64be79908b40124e548d1323c615a0b22cea28818c791a07b57994795f4a65240ed341eae53df748b94077d148f1db2fcdb356c33f75315d74bd392328d621560c2cbb2ba9b9447651b6c2aae0e9e55323f6bea09c1930ab591884f80b01f40bc843d7fe45e380d6ef6d3661998eb35e1dca707197e39abe05238b3699adf5d9a40ceadeb36245f2ddd5873bd07690ecbef70d67e14398d5c50553679b329bbf85e266ebb1df406c9afb8d025c858f458311a8c92cd27e390083aec6a6403133cb729b01f6fab1779d57178e09b10dd83568fdf58e71edc23b3dc6e5d7e1f6de8e1309ce5991ec58da13c5f237f572aa3780516f8de16d264206412552bdac51ef7e8d610f272367ef2f982182e1da8ce4ba6cf4b2f9f535d0241eb1754c6bbd3ddc1e8a55837f81ae65c7d94ead73e0e1ad4293cf2008ffa8ed5683ec52f1ab6fde01208a303f7b88d0b60d85cfb8386651c1261ffe0f9bb946826c3fcefc40006351c98eaa0844fef043a372c909cafb12baaf206eafc48d07acffa23691a59abec0ccbefa9de0749809478597a4b83dac450d019c87df00c350033baa16381065a04312f010cb6d1f4e014fad9845da4e55edcb6d39a390dfbab2091432e7e6da962de7d2ee009d8cf458ff3e0a4fddb0dc58f52275bffc36ecaa734771a78025cba2dafb8523cc1dadd5e5348408cea05f8beaf5413a1eeebb79442b7a710fde4086a47eb641fcdface297205673544544db65c1d1467f53d6bbc74438555ee22a41baa1b026337af9295828a6ba4064f16293d41f3fe3980a5f23cc5c80b53118d8d07f9f7608b593c17946f195b7e58c35e5fc48d885b67fae9998db9bd20131af1ecf8cb70578af9e6f5f913f2d38d4bff6c149fca8885a1d5fa38ce6832b1c765a20da8e3b1a17612351203c398db70a0eab9025bc537ea7e476098db11820029fcc360041ea7159fc453903ee8b91a2e4f4240d114357be8fcaa04833058df425e8606ac28a75f2ac7f2e16179e914aaf9015a64ce412b7fd868a41bc128c391118d01d61a10110ef86e090103fa361b7be9b649409dbf836a7db6f945a3a1d671ac1ada5e80206e3b7fc95a55dcff999b4d18bfbd025780a9e908605e3a9510fd2d1e7f594bfbb4e270a18e261f7e4216591d2c0c7ffe1776a08d6b06277ce17a73ab00471d4af99d9f27b4eca28b973bbacafebd17299c3f71930bb5e0b84fbc549361d9c2a9be17ba5b419d6a235c8c49f0dedc22a561cc55c3ce781f1117cebbb794874a57ce9302949b3f917363de7453e4fd56b144de201acbb293528807ef9f902d2c6afb93138eb27ccaae9cf2a78447a7b2b0d1734248ea7661435e62e58de7a735102e9de5d74c6ab8be3d18fdc87f21d47aff7fc3554bad5f8809b85d12976bd294d6d80f2c8bfff4b4e585d93c787c56809488716ee920af3cbbcc2999c989354ec222345a42711d92d353f4f1faa1f96715ccadffb9f2e3f47f2b3232dc51259bf3867715e44fe0456cb52e1e3683ad585065cfc1eb3caa212464f162933f10b4f64920953b670a9754fc3857fb3a053024ba9c776ff02580fa602f1579ef5fc3748bf7d2877e213c82cbaadcf9ebbd3aa31f3c458a83a904698f37a5e5ad6c0230caa6450b8ac531b62527d7b65e3141be3cada7d78db68ae4edc5b2837e0ab210b78bf60850151a4a263819ed7072b4e15dd13b7a3d9da0b18e1b6a3a73a60e981948453158ed52396da9528b1f65ebf70337d707972c95ba15ca4107975b4b507e55150c94dfdaf67fab84b6efbee9ac081f2bd8c454e61c4ace4f41094a2f71cd1ea2d8a87e9414c0a78c15d6068b42e97d8b26ccefde7150b7626e4d90b2d344972f738124895c3b9bb9e8cef1ce8147847381023a7868335f8ab884459ec50937ec9cb6e60cf117ff8df0f359ff7247ea8094065699f5bd05ddb2b8eaf7a6e90b5b4b06392396719dc67a024a0f85b52f42c0b7c05a4d5920f2a1610e53777fb25c69634e55be4785f69ed9e2f9d05b7612c88233df7b0eb0b9fc742626ea11a06ef97fd629aad95a6d847b68bdf0d67d07fb736f03a71b14a779d43e15f32ac701ff7a99a41cc9084f98f32c6783f7c171ba9c32894f26639e6283dac2ecd93295236eabeb3cfc4613872db9d1557689ab21416f3b72d6922b4c50b6408570dd6f85da0e9845f3e7f6d278ed0520b18df2e273371537326ba87af278a8a41762bc76ebca623ea74889db42d158303aa4b848096d4b0b957aec3e8c0371db322e4fa51e70b2ebaba4125c53cdcf08a9c29c77930d350c6d37b716611a7b7a2baf89db7652a1d77636e5a8161308ff70cbbc53c47a8f5c95028e067bc27d21f88808be7df301ab5116cea88770536d3bf8c838c420058a3d33a6140cc40d11b34eb76b0a9810c370de0a02b584a16e69ba0d31de163564857a6b723996e8b1192c438729ebf2d73531869e3a67218f17831442fe4d50649d6a4d79abde44430e947de5e04cf46c92c025b61b6a4803ccaff94399215429aae99d97110a56049f57f6e60b04e1c443e6b87e0d9f9419b235d0c2f93f75f92be936f5e27c5beae10760295069b3b09583a223294796109066fff64828074fce946e2e9bf563c2f7de6bafe487e6d10471d51d29f9df2025f72cb830a8e4e6e432960866d1162686af8c9a5a5e8a05adea992c47a9a224a0e7a323cdce6688c929e501a79d56d96b18321d4c12c2f15334c5e5141ca1bdc10e8765e4b1abec04ebe4833ba6d8418433f0f486b7afd17224f38a2bfd084008e90ee38f6c11024039a84dffaef98142620864fac6bc78e29679be62e2b8fc269c4de1ef9245c30fce72fce6a0d702b2b4f3f6b8dc354c54fb47ffc3c1e8f6d74032ef4844fe461ee8f7e763259f8311d13ae4ddaaf6548dd2393c200c8b79782c57fb9b164702de775c17b5a38c474702acb1208e6eee5169a8e11cafa20425b83a6ab9e88903906c0431d2686c43612f7b1133a8a69ccc19a33cf3ab161e66801d267fddba3dbae3834d782249c1d23858555a65ac62e1a5ca948dfb243f84c7a53538291ed6ef9066e9bffb3881f585e976b3069c50f769dd3bdac5dbf490341ff6420f3b2735786900c132a905bc599acfc8c0e89d4c4dcfcf6c4573001e41ba00de8dbf5b8ca6ae35d0934cbd8813d93882746952b6407bec8cd762fdced9555996bff7aca58a4431b087a37d6b795d396e304b7a04aa2aaa877378dcb4fdc39bd8170aa5f4c525af65c2a9200d4911191f049017be51bbb73ef26af5e0283f896a965c673c79de32dc0d8d183181173fd66c051d30a1c67271e6798983d237fa8f473cc3ec7be0dc1426c5363836450b46ee3032c844aa875785867b719a614bd524a85ad253ae841a3528989880f0d6aa0595dd8be336fb516c6085544ebd494ac5b79ae644c69a8e74f35c28dbd11d8a53b77e14c0668a998a4f87d0759aa95f2ea275d2eb5ddd4ce21f0adefa3a9f1d1cd888c302fea18cd71189c6e01eaad87ea36f98e06393e971d44394cf269d0dd24e3ecd42beb59ba7b07a06d588b7267c4ef3476aeb6d9e166fb7a8f1c6a2204bd01f2aff8d1c284ce1170a9d0425d999a96e233851e6792e5f18eeb3fcf52bbdccf126b6730b5761a74758cc2845410c7094c5c008f32cd6e03cbe7382d17f8ca11ab468917b65ee4565ea7bba863c995848f4e7b58e62c16e81670cd08d98ba70f9edfac911c4af15fb64d96150268eaebff27be1a6201957a451239730701c2f6ddf9cd0ef6b465fcdd90a7797dbadfde36aa46b936685185de1d5606267ad73240eec38f289fbda5b4a75697328ed45ff56e8feb2c5e0ddcb71bb42e909674033d9c400025015541e798be35dac274ff479ac49536c93fb1c114d59f7f07e8cd791f5b0d253835a9aaf217fd63b2115f865bfe44086bda566634ac9ffadf34664c359dee2d516bd78a294ee2db7bf0400cb257fb3799d3f7ab47a6ab5eee097ce8733aef0a93d5e90200e395afcffe902d33c367caf6988618cbede0a8e48ed16c2468f3950637f5c969c749dc5494dfe28f1567a4b873b36af1e062e457e866e158e98e9b4e5c08d73ee968a15b6d3d2cf66d2083846547cafc2eef68ce6d32f09acfc8364955882a48559e32d364c5c7fbd54b4f21984702228158a1d13c10c49735e61d020ff0a79423eeded29ec51e920f7bc1ebc0771162d4da98feaee428fda580bdb452d900fa1a633169daee6d24a631daafd4d37a43315aef109fedac38e975fd87448cbc1b5fac82d62aaf3210aa30d119fb1daf8f8822770d87c538d58e39c2fb0e3197091c3b4632fee152b6e9f63d15aea59f59bcedc7d857a7558f32dd50a0c3017d37da6438f70713cd7a75ba08971fdd685c5dc800521a9efea124044a19c897a99197d73c07813707423ec1fcc91ea3b8f56bf27f296c57c5ae2c53a770ebe70840fec4cabf769101bead6374c3222fc0affbd651f4797a7dabb78a5a86dda0171da27aec5eaf8235740331b58993491955534cb02f7a46c50b6aa5b3da3e44eacb2387b9e674e0f37d1cc1498fa45011a004304d245e44846206d2c0c972d0d2fc086ed88c8c1050ffba3ecd6d959287978cd5bae6f886f44a7fa64214514f01ac8f31f23c2c956739784c05c42daa77c54b07d070103d4e6f72dfca81694b631ef65f65753e12030afe6402f59e48dc5131515b0c991a6af7b57edeb3ac664a9ea82c5aeac514b72f0774f4cdc5991558b2b9f96c94a3ba96b1e74b2c11fc0187bcca50897f2280d8547f81c47128d819fd80dad8084e05fdea5fa7ba93d405e343eaef781905715dc2f9585252228fb5bd98587222424981dd046367f0475df2345d3fe2882541056be1ad222f781690e52f4f7781e6fe47a249f1f2172a0aac588bbacc5acdbda83b0b0012283543f99b38eb87c7535dc3081dd506fdff7691bd07a31f4c19497b9405c12e4f308c1da338c3973004a8c06269bb8ae48b488950e877fcdd5474ad9949e3c05b41ee5512d0617f0153b49385737b97deef990c649c6c0eb8e57163b3e33c8a5f53f375d2bec6ecf4306f8c2435005cad38029b2acd035c8e90cc389cab7e79e8c6215dc8e29e8d5940aaf381e5bfba2fdcc62eb5e768d8022caaad5c2e3f956c246af5ca4649ab5804b1611b00ee4d02826329d67ffdbb98ea9a181b55e0a56b2fd16c71fe67b074b8ffbf971b1bac0f3b16223b968d9dbc69f4680b2d0cb9f4251eb688a631d9632ed3c598cef0ca69e9d338c76582e6be345a1e4fe8dbaf083b6636cee6d69b5285aa125b60c5fd57cd676bab8ee8d245a62dbcdc8635c6d68b7ce2f81a7cb31c2a0e08dd4089b18b49c0a2fa3862c834a3581740fff67c13f17e7c66e559df061527d493214833692fbfef8942485bc00a1a28e1c505280062f2274bc6bb4bab2fad332b5b11b59ba5826c984d99a2e0e13073745811a810c6101cf0656ba9000bbf7578f7c6a88a3baac7265e6f2ef19a7624bb5523c4ccf262fb3fdba70e32f2b12ab202e1b584c37c585e5c925113165dbb2866c33b88e7f23929b40cd42dd978b86a9c22dbf90f4ae6ab3c79bcdce022a5947588555837aba57783ea39e96dfb639fa753d2fe24c900616f8db2ee66e2f8b74c1ad1caf5060d5b2de98215ae5ff31391be4a0268a18131bca2957ae6d284a4d27564a97a190b9854699c5dfdc7d4db9cf29606f2d3d413953890ae6a671bb91501ecc5b97190914057cfd4a520f5967eaeab2839776745a369ef9d510eb53282aa3fd8ea7805d68b46376cec32202ed65a2ca4317e8c6c2bba8c80a2b4b9da78adf8fae72c692b7df691fdefb72e5d2e96a959b516fbdcd76b0daf743dcda9f6b84872d169e3a4e1b56790c8263aa1fcadaa265b30c4f87d6930dee0c9e5de1ce2496c75a987859d019c180d1aacd41ddbf8a1e64491749ea1e72d8bf2ecd3ec726ee1a2b525e2d80fe15f1a818e4ab700b9ab5dda691a3754b489b651c4b3700214627b5c99e8d1623ab4b2a8e91a48c688492c7ed0d5611f5f6453cd1e6238678426129bd6e6eb191d81de44fe8dcb2481d9097b98355ab088806fea987c61677d65ce7495cb1cfdba1da24afb23bd419a9bd6eecebb4fa1714331984b9e38f5510460de88fec781acbe3e9a90846c03c223c6cee38df18cafd5d342dbd2165edcd2070aa110e8e78ec7dd7388bf3a00dc224f420074654683c42b37104b6e5d813b8a7723676688d8651074419ef5afcb16beec34df1a2e7c25079ed7787465285523ad67acd4021de502a36d80cbc1a40899511764b47b513862bef9d1d7498e08e5ec6e596427e834c7a022a101b59b8897231643d0a4079011e0a224fa8f168e8819e47a5035a785b840ae767b923f50ebc242981831292d71457d0dcdee4d9fa2f3e535d2631cdb382048598343b7d555cf0efa004464714532f90f54c46177ebda8400599f1a06c8743c0d2765a1d8ec250c1a5936e03d568ffdce2ba87ee0f01219710fd53fb708ff8290823165cf992f23d3a419fb51bd5abcae35072791f77596756eee786c581af7800d361b2ee69e9730b460fe6a31a4c76e43ff6f566cac9bf0512b830595ab4f3a70933b92db2165da0fca8da613eb37c5f5b040d39c00101c86ffbab1c1b04b41452a14adab58c453bb94366af292afa87af102ec65f03e817a455371357c9f0ce5e2f7355a9116798d0df2b51c1ee1ff8e6553832256a2cbd31fd19163d1129ec7a66be354c4b21b61bedfdec3c94b2b418ef0364bcedbc1d297f55690034c400382a272fdf2a9f0f87f852f9161a5bd519def4f60bff6da2c38649900340c1a2a991f49e6ae8e03e8f2d26018d17ca323977f9693c192e27199c3e2924fc0be1e811f5db6d5bf0545678aaf3d33b942aba5f5a2260a4cb1fe164246f578386815ad8580395e6374df5354c8e758ef488ce7a76449dab5bb668e95eed3472a0f8cb657912ac2111343203ef89f72c05b3e6b8214842f2200dfad6367a410ba0699dd05973a0299b3076d0e2dbcaa2c1f02f6e65e2560dbfa4b75133cc9f780adce24322d24b9a5e4362b67d815d749cc98ad519b3dab547b501dde4e84f9cac6783d68757366b8b3856846cd8689aa51d2e11fa3bd0158fe57afa50c2cfd18c63e3e9172a2bfc14a843953d3479ea29d9e5f81b6c8a3865f976571a3f61e0bf9cd347646e2d6ce9292291ca27e351506008f4cbb02e65eaed8094f682b03b5e0def096395999fa4a5458385bac6de09c20944bed7d95418b75248ddcece3b3fb7b5282b3599a710900255418aa01f70e9d3e3ea36183f61fbbdffa899acab80dc200940c1d0973ad3b7b407769f30fd96bfe5f0712c47068177e6b15346b6d26a69380be72396f6f2671c138d86be5d2364d580f26ab55117737ec4393f23cc6c9e7a16510e3e936dea6aba6fca26a873c4bc86295a693a6e2825b6c76e5c8128f624d901b3ad4cb5d937b78883f0ce6a0d16d574e7aec1a238a72bfdf72407a93aefbb848e52316822955278f97d00f05bdd0af2f38232213c3feaa1b74a7d784c321aaa4f436808f8dea0205f04308acfdb3eb96cf26583b772e45405578d3d0fd630d3585da3ccc81c27c48b518e3af6685bfa5e8b08e40431ab45bf9a96b7258437af1426f4bcb369e929df61599232df2ab8f96afc48214924682e04da6151d30efb58e5199a059cffe68c7351a70ec7245dab5f12645b19638f3d9aaa46ba3641dae24097a4e12407682dc948b07c46e0ef77b84c9c91b5e3ea23e2ff7a7a4e6fb8e1b3152b7c45cff300d1980cfe27d2113d7d784c38bc8100347171176b167314db0b9a5d811c1a8d7a8255dbf84abdbcc2b1fed4496e686bc294fe8c7cdcb055d4513c9cbd70b503bdf52ef851e8f40ff99aad97ba7a6e54f917578129623b4818ccddca35572c863275686fdc948e24b34c83b1bc688478244f7f1ddfaf86043be633168cd12ede147c6aa22e967d7d3cb0ca64dd6d409a2a8403092057b5ca7164b9a3b391dabdc84a85dd3cc012997a148455007c382f8f11d46e00b41fea315ed3f08d258c0a558fb5e7d1bbe5d8f262be63c6b072ae3742542373c307af081b2c34bf3d15894bc3724ef78c01f4cc72ed8cedbde252a701888179344bf2185ab713048c95c1ab5183b98a775770c1b52977651aec7960d3fe5cfb5fa94d09ba1c4b0ffd752115373ff9df91f15f6c27af2f599fac86ed3e6ea1916f7aacbf814e209b659b5aa56ae25dcf8ec71414fdf4dfdb5a94b1ca9830e97b3bd49320baf386883525ede1de47ebaa4ba2964784c6c0a62358c4d385b800eb445cb774868a2495b216438e5849a3c30e17ff980d44ce3d34806c4cca4b4a4f48879ba6add1f2332d792744ddaa5235f0e805c83d12ecfec033ffe911c84ceaa1283cdb2a8e1c7ebf1591ba104df30ec906500fbc2a64b7c4f7a4ff2b0f7dae9db492903f0bcb9303600753b5f6ab9de746e66b463c3f0df9a5e6dff3545085e251a58a5df4a74f035f877a2d666aaaea7554b52cd3dca1bbab45750faa45c9f9947de4ea068d52f7fe5bc4855f7ac1708ed814868b791f05163bc7fc08c474d58ccab17012a745e88fd54b7dc41cdfee1140bdad508cd40827e4d8ad9df9fd51e3e3fc60c3d2e83e4510a7baec2f6650ddf68002baef596a05bb8efe4013378cbb0751d9526ef8fdbc99cbcc6d3097f237fb2368ad0d9939e4a9c70f2ae982f8ae252a511310386fb8384499e9299608afb7a6554218714109c0f74658a46756da9d1a88dee557bbc521f9fbbc886b5df1abc301b3020d26ed243142ff021d64f9f5c1b81ab5ce66813dc18d170a9b13140ae6c85edb70dd2495021edb57c2591551fe4d6d3d853bf83a913a6e24d28e2f0c3359c521be6e7275e8d6a5eb0d81a7e5ebf0ea61bd83abf054ebc5f234ba87d234af383585e8d4aa21a3b31e1b62b8685f187d18a229105db03e5176716e1e70cb9e86b9084b169b2128d87a292b9b04ec8e44126a75a5658a2e147ff8d38fa8027728e6ee46001ba859cbeb95e4c3b9297c66bbce0acbba22203300e6e882134522e6bf33f3fb5a0e2e17c144a6db1f6a931ebe5821ad9fe403f0e4e6fe00568ec5e2b8cb6c0a95f1ee0626578662629fc0c7e6d4e2f296e5a8bce51bafe919d7728403152e9f7ba69f4d7dfe9c8eb4f11d9de135b6a3d2b1192bdfcbcabe87c7257140a2bf1505deb52bacb2265eb27e2dfe995c9d29189c65ae49f766c6a0d4eb25380a4c4275d91a7d8e6619661499d78de221cf5aac711dbf6c79e7e7b3e0dd49e7a02e200a2de30ac7a5d31222a3e863e6e616624a8b32240c38c6bba4b4e28ac345fabe55419c83e480bb463999222d820d3ae8b40ed311e575025f9250adcdd8b32ed1a8395998562377103fae7eb6c9a4ec32df30e2876e15718f0319e2fdfa27b143ef5964fafc52a65002ae967ba76fc9410f26ac6ed10319277a31d78e8d83222d08f93aba289e30648de0fa9849a497bd2be5784dcff00a728f0ab12dbce17727b08fcaa90d0057396e4b295ea2f9e9868b008066b7b2d5bbd4128fd08e84363fb868996d6b7a492ccfbd1a78a5077a85a7ce2c250b0e36699d856ae8bdb0558dec3e3e8fb08917d9d52c31e61a254a6d1bff0ce059b4e6f2ae832465584718fd094f50887083610cdfa3e1604eb2ae485519319135576861733f04d0f4cacef0b8ff179768bcca9f2e4bc8a3160d12402b2287ba17e02acaca8793d5003139cfb1646c4d6b9f7ff4d787f6909ee866621fd21334e939fa60e9b8d2c9c92ac871a9f7143bdedc9c3b1622d1109a2df8b91500c50ce851f99be051acfe7c5c90d51fdfd1f2098eafc7dc95c0adbfdda4260be616a74891387110dd13858004f8493a702ce19b29cab12731e48974b93d1f6ec64d93c2b3b382593aaa7d1e9354aeae1b1eb45751f0acde3669d849d53115054c3d24bcde811b8a3f6e2e99624c483e6d2e84727beec320b8cf088f21cedd66cd1be1b9a9a4affa7381f4ab1444c3e2db5c95bd3a821907c2be5ec89c96514e982781716ec932515639dd835ff4fcfc32eb12338f06739763828fb90e73eec19ec3c62f90a818e84636b7b6d5a253a9471aeb7ec5b04d517914af6fd9814993dc65b329065b4bbda9647a6fbf6e7a66b9c52ef51622bde440877dae3d99695316e035f4c2df63ed054e9f64dc51ea4807567f84eed781ef950cca8ad94c794dd581863ddca22aa131700eec9854cce099b5dee6439516bc21031e3da0c23d8fea6bd9bfa88d26f2de154113c46607183676daf2b553696c3edca17fa6a1c9c7aaa433b907f2e8e8ac1848cb5f5db3c68da4d0b69888972327d73ff774b62580766e056bbc2e577c5aa2aa32dae8b24271eba6497076295781e1f91da38317b8331d679798a34103698de53518b1b09ad31b013e1ee55c68a9940f0986a9b08d68a137ef4a1e6f39134c1c0cb1b073c08d765b48125208117673c12dd5149a9a8579a2a418d9e4a5d16df8c73152b264430407b1a50ca78d4ac3c68ab16e1b29dc86c07d5b3714ccfd43761ff9f698ad2f7e1e495ab93c78518c56dea8f76b4700cd0ee9df56d047c773a7c3f916cedc173d7dd793696cc19b6c9c85f03b482d09e0477903325ec21c4378344ec514c52ee7c92786e20aaf89e3bb616eaaee4df9b079ad768314290d42a5462497cffffed7eb73f8ec76f80f20d8ed76b2618c216354e6cd201449d1bd9eb60632045917301933673a66995e72edbe8c95f6bdcfafbed996f32c025d33090ad2bb55f724876a9fd41a73e7ef7a0351d574a075ea934850b0b49f4a9812a1d38363f70ddb383fb02b63602865defbb402f4a032c0432351311667f57dbbc92440e53b2ce9276c2cf62d647be894294d2419eaf545bedc52cbec36eca240fe6ffc05e64b27bdac503dc7aef8c481139d597d76880e11928ba3695fe8423d8b1c499636ac1e5d625ceef81c61d334443b2dc8a68b989d5fc88917f1843f5a4b095b655ff101effce9c4bed310ddba591244eff7a0adc50026b31a00dcb060d003bbe3610ada2de37672d4bd01cdb35af262246f6aeff22ed448135bb95387a8cbcce12077f12bc82e514a867aef9d10048318441822a4a7219af795417350b3385d472bfa639335df10bb4462d3a4c31512b59875d3abb934bb6d84a2ffc73ce25f6fce547f29aae6ab6117aa5a586c5376b7e7a74e91cd7b54d426cf35a3d7538584282254a50ba274a4bfa9b51f23bb0054045e4a80498de5fb0c6761494a5c89a92518f6535e6995de85b42d78bfd15d140fde2719e53569be562a57dc60fe398723b8f7cb14514cdf7002a910f3aae27a9c7ec6da3db9f02059d605f05cd9c7f1d6861887e6e0c7c8dda768c87024bd10700ebae177505436aa1e470d14d0e450ff823abdc6876ec733a3403cf2444e307d4cf5bbb5e04062bd101c99d0fb09b7fcf3026a645f5df38487fb8e9b8760587be84bf7606c184b79af525b4ac6dcb5ab5c01f3d8a2f80c8765a9aa66388a600154c3388fa9b91c12443ded5b228089e191d55d922e85577c03ea99c7fd1f807f12f96885e9fad9ac215c204dd23ad5779aa8443771944899ede91e9ad19fb7d2a834ced36c36d042cd1e2bd4a3a62ba9d823019396cca3a69c128b87bea037fb4c9edaa4cdcc313e62bb2bce57843421f57895666886cde48729c455257d391b0b8f5c855fe00258b1461330d837505b1f899e444c5ff5a28d12159ee6d8fbeccdf4f7d1414ca04602975f917a0ecd096b4fdbafc8795c5ea8251a47ac82679229ebe1a8791905efe5920f5c62d61dbad96fc8b792195d118ac560d4aac26da56bc548b97b956ca3efe7e565da3e225be70b13a1990fb887022e03ec91e0c323a819b42f3e2cf02a6bb5d179da2b73caece10774e34cf31f1c1fb2d3feaebd7a28401eafcdd9e7273990a916d0d2789ee12ae6489dc5b725f62366501d86ff39099e267cd93188addce2f261c56627cce5e8debb89d1880aa706c83630a9b448f2b42c3af32b137171342c98e68abb1051ca51353af251553a9caf1af311e3a9106e4b724c01087d6baeba6b594c46ad6c3dd707f546bbea59d7e8f3527ec1cedff894bf0c533fa1e1b987f0b2d1b03ecd23c05f6892d09253961702758a62bbfd829226ac6a1417b9c52a3a865212b30365939d2f739f937fe5ddce6459c54dba9e4e248e4054f57e219e0c1d0f34011244bb33d55d7a67f1b57826385a9ac37f31ac9f6510b12cab52473386974a093fb2ff2dc4962a73577312dad9e2f264c0ca1d02e172f0c82955bd016993b8ff0feaf0704c48f62b6923056cea1b22f847f6e3192541d71835f65cfaca1ec6f52209df00fd3062fd40d9ce04df7b245934cdb0d7ad291b2b2783bbbc90f6033322e301740afb0ecfd94093bedcda614ec40f74af07bdcaf7fcb0a0daf39b0adbc0b093c5274b3aa5aac708e80c1dbea1d52581d5174b20e6f93f0b6841bda7dd1d70a096af7670f2ae8623dd32a2680dc32ab1b683cd096fc7141ceeb348a1e71c9b18ccf7166173e9a4f9171f9d14826972c27439f943e8c44a38cd75a5e53fbc8d7a8756abab376e2c5ca22c0342a903d2fac925219385f0d13f7caf899ad0003f42b31c1bebd768c09608fbb4b98c276acfe273e2ba0de07849dccbf4bb93c9fd3d4c26900361e8ccdd6dad917fa512cda0e66b63f7650fe71e32c17fcd90b47a8d2827240befa11e70932642d2ea7ebef747a32e7705b5033a29e3add47bbb6b635911d555197614287510ea60cac9febd9020c4e2a21dc2ff57ce73cf0a865392d40bdc766b31a9e278306276faef848c77a8db20b7c087de219c6f482997089af035abfdf99cd7ba3fa8c82a406f2b84a9e927817206ef182ee362f3b87df051cb9cfbd638e7ec1ac76986e2f07235e1933688484f6c5382e272ca23f0b6733abfee8de57bf6400d4bef224285b6835acf1b5365bd175e04539de48b5592cd0c6e4d78ad66444fe41614a8541786e7c90b2e929bde66b6efe4f0b33560f3378c793a853d4ef7bde19da8b7d8f70c54ab85c2bf97fea70d4f71a2d9c35a75e03db13d8e03865f1d4677250d048ad1ddf0c9375def99f3d6fb99a8242a6e833124cfabc65e6eb3a3835be60550929f645a01a0edaca57bd2511a54f6f37b207eb41de44e62231bbb72c5ea4895108d9a5fa6fb0947f2a47ba65ee497ab8ca0521435e39e7e16a4eb2fca5187ad3899b8af685d6099036367542ed8db64e0683c539408248c601b20a38dcc4c6a21a86003aff6565222ce32890094a0b9fd34713cf4683705703dd9b95a468668a2d7fb6efa41b9602442fa840031f203553802153bf1356fab93be97434836aa32916dc6d6f5fc152c9156c9b62e633d4b7a9c445edc7b74676f74f24160d967cc4cd02d4c55d2c4c6468d27f60be7e7e1d3316b21cf006a434649ff04f11e74117f7c8ab40c783655bbd8b53c1b9698f2421d101c791de6d0b4ba2a4b2eec28708104b42f4d700c29992ae2d0aac41f56e65dfa596f089ae07021d55cc087038fa541fd7fb86eb6556bb1113b1e936be22cd41d16350b037622b18542c796edb188ab525ad82275b9ab1f04d00be046e0dca8c3561a2c85f39c5e58324b48ebd2b5207556dcb8f12c1b3a6358bfa9c951fda73356ade161831db5a90fae8e9f7ccc5c15c5e978575e7a731ce0d6530b9a5ed90ce80a1c5a54ab812ccc998226eecac8b903a167c686859d234df43bafd26cdc70653af82ac0427f8310886d881be067835c9bfb272bc5e75323ab238397d149fef7dbf5e140afd998e5745a6e92dccc4ab38d772ceae9607ba10c89f787c36241de808b8b8b247cc31e3d2ceff07fd287333783ddc6d9c0d10bb16ccdfe85b4f8e8e1f0f3a8d8db2294b5c352e5d5e886c46018c28cb0cb0a53fc1e14cd6c1c582d09c0bd2b07df1422cb8c3f0405f27809efab9191083d7356b6309cd536d1f72c4f4695f78e3b1e44e5f7e72a30ba2727b2af4ac0baebbb8b641cdd04c7b49d86bdf950740649121c1f5d7cfeabc8df8119baa15e9abfa079d98d152bfb600773c55006523ac1f97495c7a4306f720f95b5d002d3f604d57d49e0a03f26efddb5f683b2538402f77aa849ecfa0ce085b4d020e8e9cb9edf4e12019c4e408d7d05fb8c1b0420cf44eb5e388c722c9128be2218ff6c349331c24a63fc1649163eaf3274cb932ec3a07e50febade49b4396c07c7100d534b85f206de5764dbf087f1bd7f1a0e88580f628d22f22f592defde1b8b0fbd5da93960e075600737882d6f910c042cdae356da24c15752099b9494e56cc7b4191d8ae0f896773b3b87a54bc2324051f231e26380ea22909d87e2ee6e84f7513d56aeddd658f130029ee6d9499a6c6d0398c606c5fd4f656d756f87d99b8c4ed86c49070c2fc845539ceef9e1e36ebaa6fce0252409664ced21c419e5f1f7126cfe886dc3ccba71431926cc96ccd8c327dc3b351f328298622564edb8cdc3b0e59bba52faaf75cb02940dadeb05da47af6cfda8da956f6f78b5b6411be9eb995997e61878070a670dee142a8d4485d9d3309ad13f8b3afa02b793e4b8a0f97a73960b8b9b4dab9512955a136c348b247b42eda18561ded2299c5965a4f263de7e1f9015bd79c8c735fbe2dbcee0b6f0f9cd9b823a2f83155938eb8c7097198519fc7fd58ee0b9c37c62b274d78b","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"9376a6c3a7b835354e815a8324b17bbe"};

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
