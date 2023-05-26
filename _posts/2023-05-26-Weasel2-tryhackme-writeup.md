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
                background: #76B852;
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
                isRememberEnabled = false,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"e31886dab4444db35cd9410ffa91fc2a22cd77a56894253aa8ccf3353180d5fc5a80287c480e5d42e8f94129fcc073a2647b1fce7027abfaa71e70a498da19811481be0f1430a118779baae80bbc251b92a98f9dcbedcde16f581a6bf1e54c52904882475a98b627bf38584bba10ed4a55946acd6cef230ffe37fd0d4d599e9f4cec73e3959b949ba6a1234831f585294c3d80fb6c00b4c510d6ce78fa114fb2f4e8213bc922a9659c204455d4e88a7cd0b45590d8410555f4a6426644843ac75740655cfcad3b1b9f5ee3301258058af1cdb46b3f45a50a08bfb7d81b4a305cfe18b379142e12818cfe9e26380207beefc0efe48a0c5483ea607a10c30e4d14cad5ff6aa3c17087a5ecd7e0b9a9c5041105af2df1692b7d68897693c117fbc1e4620b8afad51032007384748a9222d93d656e6c0198eb56aec08e2a5939523621ccf689e0b07ac02b68643212a1521c9ba332834a98abb01066a0c775d8fd052c88c02b47df77a09487bfa251ebc858a47c79369bb80718be6a8d6270f340ec0be14e2e413f6b3ee90130700f22a5352e668cd0ca4a84b053bed1e30a4392b61ade454ee70134d4ca3e1cc3a11cdfc388ced0c4cc51ce965b4009d3306e41765528365abed4e7e4d4e4e409226fbeb46fbaaec3f35c816f309a2fdb42c679ca6d4e2670667f629d561f5b85c226ac9d74ef717afe684855ff25367338530bb68e330d543f0819b057c924ce033b8335a10917a46a9ab13758637612baf1c85f661602c8a269d8b07abcdeab733b000c16b3ef00a4356f3ba043fa25accfec18a6883dcdc0948195194ea12a1bbcf60e020b3601e84801d85468099a421ca0ab542ddd72ef6d54b9935edba78a0152e408c30d3716ae0206bf5484bae0b7d31693d10f9a46986b8d153fce6a428fc5b7d2026adde0214a6e06d320f5ffaeaab88a03e730b45017b8b7318922a5b03ac44c0530e7966b2d532ef1a7f3e66bd3decbe3145f15d7c170b9056093cd37ab22facfe4c078b5818a578c026548365cbaffaf76e84341859bba90957001183e78ac0e1e22b305a61abd532fa592aa6742ff52d12c89a3df059878f77d1244cbcde88c43ed582bef3e92b37fb8d508327c8115e5cf089f7778c65c37146c6239e8868fc88df1efe8da53850c18e84a2b39fd699eb9c49244fcf84328caae7985e1a4613d5e0f792b2936651e3223e6a6951b6f09ec4b7f80e8a5c6e16240293d21321d330756b856066da0748fcc4614483c84b5717b2ea93abc8c9dfc59389ebf3b7801ef85d492e83b651e3d28a564ad94302f286afaf0169eb6e21c7c5b9a929cbcc13eea57a06cb4c7267f879780ecad4ef69ec0cd0de992719fa63cd7883291d05a859a881c181c60b64db049c8581753ee40648050c45de96dbd923071158de69885ed49f063a5836dcdc96d50ebd9dce34e196a4f3550870f81e7c0d5bb9797b4dfc6973e4972a02e82571636a37771536f60dc915d305a72dfda95dddc91d3b02a0bf33a322dd6f0f3b4102d253db2dcdc08add1cfc88b0c670caf2b68f4fcca53ae9848035b9ce4f4d123aee83cd8b1da3fe030ed2e1194895349e553e979a6374e4db19d5b3f643fb20aec8b5b83d9f144e588058b787c883a0cd86eb47edd8d4451ccc17bc38e38e3ed83455a15efbf97b918d2d7a9b9a62c9465c3e1fca4017419039f470d1d2490177f8b8868935cb563f0378b8b17b4c0b263f63c0bc52e5368c04b8bee874fa6ff0eab172fb28ba26602331ec550d4e02a622f9132e43a4062a15567b6300054bdabb6772b0d2203d50deea1813297e802fdcb3c6210d64a48a12e9497d739adcedea2753fe79ac1f41fd133392e9cb8269593e576b152da83f1f34cc19a9b59216e403f462e9fd089d0049325ffedf991db6bcd9a8a7b92a269a83e948c857ff69f45e3dda05737d8ca73883ab7cdc49b3f94baecec6ce8505089d8fa5cb1ab39531e25e92e0e33c5bec1bab5b42558d9261aea3cb03b1c8f291ed71d831da9ed1214c9713ecea263ef2a208b642198b6d6b8a29281d7f64fd7d95bbc955ddb9a846d885bd5c31e642bff03fe2a4080fb4e8fb04d493b4d77b8269007a8a431b02a2e4035665b6deaa121706a591f0cf43ae79cfbc7e1fe2663f9c28a421c67bd1141ea2d967aa702a66f391943156b2a7ad77f15073cae8739c7035d1de832b24c29c9bf9dd5e3a337f3a3aab3b8cb5156873588b1f6d7c6ea050bfc48a1b75c03e903f592a9e1802b83b97f64a67521d5869447240e985682a7e5f69fd622e9e2e3f1e7f43888eaac2cc8692affa3707008fc5e0faf3a778126ba5870c7b485e0b2f773de87ba7265d752025df5f3ea28e2ff74278a1ce55a604eaa2a53f0a9e1f30bfc05505442a1b4aff94179d5f296d35b1547d4a755c03fc98c9274ec5e293d38e30bca23600f1bbebc48369ebf89a26ec54cb624325b129adb546a60e2fb72751b908137536f340337f9d1e6e8a7dc6c2e07b9afc4937018a664c3067fa3c8a829868cadc9d019b8088c1d5dea39a9c36be0c0e37edc82a5322a4c06ae5b96b169016db2c9a006019e3066dadec97d668b92294e9ce4220c13162530d4a3487107c48e65a18abe57762fa23467d11ad877fff6be7344e5554280c79dac17dc1f51543bdd2908e1f48b61daaf59f5347e5876d95e8feac49c1a4c9288eb8546d791cfb628c3db1ac21964a02d03b11275872b0fcb330cdb78365333b6d5a0133d922af0b7529089b23e9493530141056cbdbcd500a9d4988aa07700ec241aff25e0a32b3163f223843ed1e78331ceb02c92164638903922b5bb666770bf3948bd38ee9d6806af846f1e2482bdb37aa2bca07529fc734dc5bda97493542a2db2b721a2d01f33e8bbc7d8afee4d9d38ffbfa387918f19fceca4b15ad3a27694ea92ad7b2125aceb67a10566d7f7399fa1866a3de68d926facc4d589b5227f6ca8eed6d97c5619aac3bca32bc3c2b404fa535689b6dda684f13c0bf37df2ffb4f70f4fad6a1ca75426f51329a72ca40e1c0cb51dc9b6213591d5b95d05cf7b5d384e147df020d989ff27c7c708ba234ab3bf66c7bdcadbf503f24722cddd79680b81c79ab423b54a256b6c0b6f065ddb4685c034fe875e3f16ef198ef699fd19325eae8073943c83a5aa38802f9c5eaa322678070a237bf13e138456f004a8d408516d59527f3ac4a03ac87b934a2184a008d1c8495400053293866a814040006ff9e5871aa3a2814f19e0d29c7f3e7b8a66dc5ad80306fe8c3a0ef94bb15d9755ed40f3d1097cc68378bdc214b36daa7f5c439d09817d140314f64c72e6585958dfc75d7a6e7c64f55bdb26d9334ff2858f409f71e5727c25273682897cafc7f3b71f06858cbc3394aee31cd5324afb4653aec403a5d1a5f306d456d209ff2201b878227f092e6a08f26251e142ce0a5da6d05648b6215e6282c0bb95227cf508ac001eec1ef748e9b38b0f7b7e0be830cb73457f21fee62f08f3ba4ca371c58cf3a03c0363718e5898e01ec6f0694ec7ff6552f801ee37b8e25c0df178c09cfe566273b3371a2f0b621a0c5ddb82f5cac2615d512079613780457e9b9a02d0e258483a557f41d1ea1d4c111cac9e093c67fd596c419a5acc150a8b0ede32048883b38d0c158b38bfcdd083f5fbe32fcf129c669056656f6f87d6f0145b511fc68c3751a59f6e2fbb1fe6447ecb9a7cbcd5d09b33dcd12926fd6440feb7d06e0b2601a597e2dc5fceda76b88129f14b8d2abccec5079e6053db9df680dc2a66b0f8740b42718abf8319ce2238940f446c7ab005dbb5c7c2817d3711fe411a84518ffed90b6b1e8fb249b482d5211a160ee180ab2776857844e81971522c6180f41b4587e746c2a63f98cd99c6db010c4b2dd17d2583c9156b87eee6ab1a654245157b9803f978d3b0ceda417f874a465a6cb9c55dd55fbe0f817ab679b14793acb0ba32f604dac972b07aac604cdedeb9e351723f17af223609ae1b92d48ab7b4edcde751c37d194473170fd094eb9d60c29f8c16182c2688101bdac98989a61879ace6eceaaa7e33a21ccb1ef29d41a17f66f0228a18323ff86e2227db2f3586141241b0a762adeb4aece34b79ff1ec3c7688a8044e903005e657fbf29462253f88fc37a3e00b6a31742bc9511dcf35833bf3578f83a5fb8e8b0f78e0fd2d3eb378567355ed629b81fa68f9a2b5acb1912fe7d0f2bd4d3284a96ce1a13633b9b6acc23e2b3d6cf1021cc163b14f02a8beb4ba3207372b928ae5b64b05b111eb67f9098fef58fe65bf316d36af26e5f09153a2adb7c2569fe922a94326f7f996405a606d482fef3c5e28dcd8c1d450fb2d1f105ee9758e40c97b9896f9986275eba845ba036497b490bc15e85d14476c7e9d609564472ce32a7e060f1e809adb472ef9e457b657244cacca0e2ce4c4ec9f6b7ed7a93bd460f26c1e6052301f5f82bf5febb73388913e6f2c41cf9e9ba8cfc5b7e71f73e760f08d14ca1503d97ad2823d4f14763f5d94a11478f34cbfe1609c34de718f7f2075f7fa00275b8023fbe82bc276763f3aae3ed1c97376ee9bc5a9e43451e21e257fe4cd6a8d85788000837e0e33df85fd53d11c7e0d951e620a18ab56f7a985bdda7f53319cd2f5c06ec5d837cc64e6c41bb918318b611a0d687495bcae771744cbe84b0ceb155538d354cc300b5b0780fc035a2fd603e6687fcf5b0ef3c95c0b5cec5d6551d94bf3a95447a5d3f5548593864a319f7e19e1e03c727ce45737b80e3df8c1d78720e2507f59a5744d1aee5f5db276d45265022fa4044534ea3c1d86df493957b4d2baf64f6fb0483e9b3a95903d6937a5315f4f8faaa96391ed66473c94d071f6516fa81c56850a553661c2e1a693f91e303dd77b9a3fb0a6f25ef008f19b65325326c805c6cb6e1273f4ab1e9d43a5f129317884e1da7b80adb6fbb2b341c1f2b508974e73cb614846bdcb2cc608f44959477a7425ce41631ad89de7a4523cf1673564d07c63e7cfabaa22c0370f7ffbb0b6e7eec88596dfc7ef88ebd0088e9fab38450fa467c8678ee6dff448511259249a69954fbca111b9ad6d552285746c74107c865e92494e1f7ed16f0c5717d30e0b71c6ffa9af4a20d9bc8a14f33f84319ac4bd633f69cc0831ba35535ab443e3e84ff881d415a32ff4b9380dc4b7a0c8a78b8c5e61ba4d689f99c099d1d1e508364a125ee132ea3339508d9861657a425054e288e6a127b54373150f22d10972b594fee2492a3bb6be2cf9e2dc53a21b2e900106e8ff2377e1bb011ef2bd1994d0de5796332f29488fd2d9f1deb70de2c65a773638c9a26f03d32a96d84caa1edb0543c96b64705e06aa9277d334f4db82d57f4ac7d1ff1ff76b348a6eae551a41d0f3e8507e482f862f3b1968e42ecd7a8a79ca47f487909b776888731bdbfd1928e571ce20394dd46c70b1a60f4101b88ae3628acc083c4704cc45a95a61f94a8d71f25ea0623a56740d8be4674ee4bacc46328f4ee05ac524048e940d05142506c5b9ca41992f2d990c9ef1943489ab3b8b2c767343fefaac5f5e7d6e2fec27075426bd7f18f3f78b53044896b1fb5bcf138a2c0a14290222ae9bcbfeadc62c21b89f63332eeef5ffabb1f60c7444bad7fedd02650a0744cf1e3ab3b1033a0812a3fdd9cf20381fe3ffcf2e64272953f4dc6975db27915bc6653d4eb11da0796a0bc82a11e09f9b67743ebee2607a2fa06e69d91355b269b66fb1325f429fb3d3cd553b17658989c7cb0aab0e6cf8f4dbe1fe47ffad75ba59781addd86a88011a49f9f94944db8510d94e1668527b08c5252cb8d7820a172fd67a84d1b31dad150e0bfc12523e317bb8a5af6ce79b4f594974a07a1fcb094f2e65555eddb027cf19549f3f072d00a4b625a0f4c25b995bdd11ed6cfbd9d80b7be37e887c898cbd367fbe7b8141a8673ae2b9b8f29abbf3c5d0352277e83dae318fb3e545f33dd51a2d0432ed5f07483fad4154aab99b3940fbc0475fa9850547303c4bea726db7e187cf1fb953f54f2c86c1e89b736c7a96195cf41fefa0b79703931e2d09ca998a06cd2bef89751a11e56467ad78a15d8cb2d6dccf6699b07955c69803847bac02fb14cc9f2bd085e4ba24910936e2382cf24e552744030a4916edc16e80a95cd5b86ba240a403f4c0969496ceffe2ba17ca8c950d83b0d1bf640ffd5e4698dc6e1c516ce1a550c21243d79821c33216a191c9474418839dfe1d5bbfbe0df8c99ee97e6eacc52bad59fc30ee9191e06fdc9a6dc83327ec7b772ffdc89d3659c9a56ef38eca14f0348d35bae3a7fdaac7890472ba75f1f979a3a8fcb0443bc4f1a00a148ed985aa8929c8c8848fdebe146a3bb00705a6ae96e42beb88bbad8278518fb724599159cb6eb939bccb856c77a05c0727e0c4d2b4ea6809ed40703d1b8a6977ec07520567231dd7b48936841bdcd69d437f4744c4b352930155cedb7bd30c19973bef754518cc9c438adba798aca532f4c10c1a601e18f0bafec79286b2124c9a108346a03847a92adbe2359292615f460d2dcbb0c6b84a78a9cbd84cadf4b8b9b7052455d06efcaf729b6eaa7d13f7e403e2fe39eda0e6660f7340f31f2f4e0448591c429d5c4bba5f2695f66af76de0f52aaf508fad3d586498266aa285d2decfec8b0bffb461dddc1cd55b35af54bb0765b5e9858781f0de0507b3877c1bccc9217fde9b5cca3b354df75945a1cddb955a471c311cb85c3426624c530e35f7b5447acd7f0566777ff97690de988dca80d64549180d1376af2c789f70b09d5701d2f6033fb758bbb034797d270aea270271fc9015ae75648e0294a00e2487edf8adb40b10d868bf61c3b79f4ad65c2280f849a70b3950f2154480f6b1a53641693326fffcdbf6600c6d2c6ccfe3c2cd81285bb17c3e5e994e08ecf679867602a19f1ea1371906a2cedb21e6b2c15325365cf58229f80520090dc2549ef3ce4069f61e963e220ff5be5fc5820c0e2f0a985095b6ec407bd6a241de6c71086825d650bd0359335e4d5619ad750eaa191f277761999f9c0f12364463be3c161f6e35a769c5738ba0c6963e5acd1884efab238247aaf767e25fef67e026dcc7d2ddc71947da311e9da0eb5848a79cc38ec26e8360f32966a393a0c94f5932ab3df62b6ac022c5acee2b3e86784c4c40eaf21eb2cd1569d6bb517cc3419478e5b170b0ff320ea7334952a005e15d3bff2e5fe60089f6218ab2aa2515f2d75d8927190ea84a55d00dabefdc20aa555957c0fd443974ad5bc7d9ea9c0b35abc76d1c35a9fbbd789c334f54563cf096099222fecddb4cd455de09987797d471a891ea1c2c683a1b18f2333c8c2eca04695062fd7cb2f1708c17f282cb632182500d6dd94cb38c6005619e938de897f8b4e84531f4aef9dd453a283766171c6a3e0167ad03cac1798e04847ee867e4c78973e0c5359116048445ad83c36899bfe9e441758057e9840770c7b5d0db047031ebece56da2954d71424be1dfb2cc170e9cedf5e4ac76e49b5835e1650015c219bc0db6ef3eb1891f325d42d8863e636d940122b813ecff88127692f7af679a187b0672b64860d9a91c3475c211f71958b1cb1fd76b11a2cbf431ae80f8e5c38cfba0e64a1bc53de1141616c1c819f5ce5c4548cfe8dd1bc24ccf326d91fd0ad39f8e3c1749b8f19dd89fea163cf6ad38a3fc4d04505a72ded46674be966c45055a01eef12573d1389b3539e07f466dd8a7d8f5593fc7aeac4ddb2976fb57895d76a29fc58f81bbb72d4413225033031735b32e2a7588fbb192c03fc109a6b1d4b9f3e05904dffba453b64a189cffa2f346a0e1e4e2f8349cb802575be744af5c41f7e65d11ec1b358d5256fc5252e31f41c220f9279128128dc323d34077a00b8a27f6305c0bea72b863e209df941dda157e020c662735200c34775ddbecb33b217b3b9da49c1b12986de8621725d51188f1c311023a8773ee81dfef4cd5ab6a12215aab98d80a11fb6d515f3c87e6108c805743374062b948f88ff82cbd11520d57e98764e67b3ff8680d4eb126f25b43ee7664a54184bdda7bb80aea25068fc0fce78ed4da2a961f4b6f6957603263bd1c996eae764f588c92ba6635221025d4d51cc7f41a598055b9754786085f762a9fb0c021c1c973f615587c5db9e3c1c1a5788f4f5fdab5875ee7857227f1b248ce28bd2e8adad41878dba5e6ba40033439aca5941bc27aadef3ce2af8ab1b9ee61456cc8644732724170470353b21583438336f322c987ab75ba4c96cb0dd583dcf87e0a4f20c86cb422d701cea82333b1f47e812962b1b5fd2815777c6b4c2f6be3bbde30f6c7cfeca985e7527e32fa34ea42cbedfdc189f841935ddd40263cc004eabca5b6d8e0c6cd46a05357dcd18162318c771d31b16c5b7cd4eaebc4644e2c4d2c5b06e2e086c3032cc99d07eae7493018fcc2693c8ae4ab2339d03ca7210691925814e7dccf5ee8e47d7fea4000d3a4ec4ed0e747adb8a6799b47f7af2db1fe43f33de27eb31bdb901ce544004b2f664dfbd8ef8d20b56e32ae71665450872d651bd2eb2952afa4a6dfb1223aeb8e762a633f332467861e2a06c641ba95fa7798fa441e9448c98da79abbb1b8e46040c18fef35cffcd2f38c80829dbc14a3aca25e717323c82efafc3978bfd96b73ebf0806b3f0f91089cf7ab136fcf5f1cff417654c2d66ffdcf0589c63929d7cca36c1277539e833b933fd1bb78cc65558499c80c3f45be048b88450571b9fb99805456f4d7ffe4c9341a5d64b482fe99fe9b36b2b5697329a25250fb7fd441589647cdbfbb9aa50b0fa7ae5b09b9bbb542f18e4d318f6b2ee16bdeab58f813d118cc92ea71defa76ae4638809fe16db38a1bf463708fd38de5d43434c22f1471e92f911a2789e33056c4e45b949516c1c22c677d91234b32f27565faf7d7d5f68f06d99e79f499f43591307789e8c06a92e33b618176d9c809e8893378267f0c8910ee0fbdb806da7909526fcedab31c6eb6173435eede021bc67cd8f47447b319eb1649cc490e5325520a7c528cc841a352e7ff915ea7360602a805cd738cfd1c718fdfb1d918ad959f84da16e8c56c080759e899191dcdaf0093c4138ab39757abb4d4b2ff195667dd196c2eb98c3c8954cccc865d232786d496873075d43d2a7b4c63651ad2c6b2685428ab4b9287879160a64160810f7af8ddc3dc5d93da5ace129c18d6f0f313c9382d57913a1f8c49dfe33b28d04c4b78ea716f64a83e9cd945e6dcb38e41da72cd6bb20fb1a45bc11bd3de48aa272a39c9b6e688644299c08cd2f18148ed6c05a76f9d4e3dc605bab7e48555f3cf5bc364c70cc9b7ec5486911e841b369a002a43a41a74004e410223e0964b3fe6c3006de9cd0b36cd6cca974298dc45efb3c812ba9dc5ed9b2be34c51e23e4ef033d70cfae4d74429f6fb1dccf5837f2c88caf9b62e692d1b7e9f975c56df5861cad42aa161581f1d6fb8b18d5ede948a907033094b40c0d743f5abfc99d42d094ef4be22a6095c05f2c6aa7e885f2f0b57e9830769a4eb438c2df6ebbb71f2512b41bf3804e88f04a625df069f8058720e0bbb649f6458b48c9fc6a398b10a45ea99cf68122473f9c352e7ea7ae611ede7df238ecd763dc33eea0a447344911c54d1e73f39d8570786d6774d2b23c59589d07caacfe26e84588b33476a8ab9377a4040fed89145dfdb794939319723e7a53f550a04e1c76818556e1ecc9ecb54eda729e0671b4cbfb686947ce59064df8246c707e829391b4e345ef1a3626a0c2fb035f30e871f93f8693bc0008370a715796f2b71b6d0a980e554cefdc7812e194c90cecb7c7d62f51d40ff4b50b32e9837d16336676ebf5ab31a626a289259610491da285d17bee17bdaf8507f6f93d0e8244c9f7c01ec0171bdf93ff2e216ba461932c83114c3883872742dc1bcb030467afdca613310e17f85f2395e1deae9f387763d2c561105160c34bc423440a18b4b9e782cae35561d6818d7ddc3f0d2dd72ee3e178aac01123ca39a439b99907d56224d8c533cf3c4f8739da7154f54db3d25ebfd65121f19b0576a81f65f4e746e0de08b4c38e1fde08f2320c15a4c356bac199d366c7f5d277c6dcc835b730156d1aac66bfa0ba0806bd8e61a5832ed8d451c7767d0d266558c4b126b7003c472efd7f076b14ae0d7b2b5399ac43633c58f62b589c544f52825c0c48747283173cbadd59e3b792c6646a25134cdfe23c473f5b2cce6d0aaa0c4de3fd4b958e5a5b81d6b5f2c782d0e5aa5f331845615fc9632af5492763d4000b0731265adcf35b20a1aa273eb66c312e6795ae7bd1729d2870327301667701fdd7708e8ff684f2db3d43f24f60631317170a3d87607c79845cb97dfa77bf1fcea42971edb7018a7981119dfb95602df957c5e6363b1bda1006ce0f75791c29ba4d8648b7ea8f768bb3fd1e701e2f102655a70330207eb42a945d3f83ab951de31c587f6e762ec3e28f98f57cefb545ebf02cd712fd082df737ef70139578de068f66edebab3fb902f2c751eb0c5e45ffd95287651107f2e913e9deeecadbe0d043763dd9ee58a11733ddb7ea1a46311b7dfed0ce29150692063a3f908ed1da4355b8d4e20c4e2e61691cbae358c8a03f375cb17540d44e53a4253baf453837d0f74f578a5fe3cefb2603c62d30ee95859de455c355788ae5fb3dc4fa90ce293abd4fe33e22b9cf9199197cdc8a63481b182af6620cf024e74035706f61d18627c2174bcd52fb656a5b963d16891636eb2b610c083d04530a4a4ffefeea1a915e916c2f54493a11b4fc9065abce8c62e376f3eed020c479e66f5b5b2af4852ecb057f0fb20dfd4ea2ece3ab786b09e65a42292ce7d48f5f8f0d7fb8741e1e23834be408b00e7b36c964ba10f0c3d01bd2a3f8fcca4d7d340e80e6caf57d03d6b3a44914f60d5998872c63111ef5b6820daf7ce19a9384ffbb97ab1c8fb7bd3a2aed68f1858c1ae8adf334ff2c567eb1f987b1fdd2baf6d4188e9e25ce40cf3e9426d07bcd57d771cb1366c0e253eed47ce480fb790de4d480b5a1349255c2583169d979e533ae9d97c1acd50861ab3560be25113cba1faa5e67a3f64bed7740305016c90a419bb245619a2901d049aa5809f7822d92613564fab3590649f72a2e4d213d2f7d398d6defa8e14caa0e8ec4b4054a8341fe75f01f02e135a988bd85cac70be42b989f6a2e196ba0cac21d83892a1ab5528a36673d4c6845c895198e475ba7939238d4597140aceaa3aaf6eedb9feaa2ecf1c0ce3f80191895714a590dd7af83055f08707161e179fa0c13c38ffa51a16d1fe20266d5e97213c770311823e076a35eb2cb51205326f99aae3123b51e4ed61b2238fdd713c25abdd92be35265f16fa379a2edeb948549f7e6864bbbf094cc7add3bb57ac107db6774b327a55381806c7720879c6fef1b0174aa36a79f88b1a3fb263796efceb7ad24597f2e2e0ade1b9d1001c9f7166ab4790d60d8514026a876f0022357f4d23012cc2d4d0abf1ff0a1dc61a740e4a5fc4e379fcf283308f52de9b4efa2a84dcbdb9bf8abd49e8fa1d54b99e9b81ae6231d486557947aa5b5f85ddf947a3558b87bad2042dd5027bc7061559da40402689d49e3921729c7b2bffdf03c4039b9e37ccfe4bbc4ed2d81e64376e0ab0b114ea6f25905642a948e504f84c4cb86f275085772e338f6cf8ca638c3503c116a21442a90b68431a366c5a727857f83961b192da932ff01a65def7716e323740af78bdf27d6ec7cb513f404ab00f88fb82b93c6463a56c9b64ffe1502f2d8fb029261ed88bc66c839d739a507549c7a06af365616e485070547f6a00e990621d9157199e5960befb00c68a8673a4254705dea7d5ee6f26f552cba425a42a05cd505ae89e25d9773a51ba942e7b5c83228ca6ccd28351fc8b097a861af24825a284e364fb0e2f47ddaa48366d97689687785641e34530c9ef4b28d71036e403fa58b35b37f0b715d937f8d81628dabc6dd1df7694b7d47211d942631d40e33355f70cc6184cae65039858687e134348498416f5f91ce1f7fc7a08106866636b9d8de651b6f119204d7822c661f6a27775a446aafdf7c7e99d8ba33761c713ebba1f77b35d8cf49092e13530cbe3acb181f508579bf07e782cbc5ff47b551a240aa6411dfe008d603bcd1a5f17970042ab90610b859007a1f3ec79b68fdc703e298ea7b6f2b62b7d02e817a97e69443b7e8cc8158dd7312fce3f28c0e5b063033ed5f4603f46c9e14ace5e00a13a29be85e291289939a67dcb88d000a2004f0d3fcf9321dcb435c906577a228767adf9f4d8059d1b30379e2641a8e58d4b753570133f4f2029abf58bf018b77eb4a3bf76fada2243c58855a5377e1293bf9c86ae7998b236e76d51b5d18f61e3aa504964e5768ca981ec313013c93d17947cf10bed5d215e1fb546a76bba7542b7b3c4e5a948972cdeb52c8d1f8d8402cd9e7c5bd300927b556e4d0ea6c03c51f40f298c42d0076a5153c639d589dabf2395032bd29ca3e53ad0f6e2427e09be69bd2d203ed1acead5c220ec1e351757340aac776824916bab245a4e5b63ed678953e745640b3e7d477ffd92688c28b60955cfeca614887b87de9a0b08d2d88a92db20aadb63c137b496fce0eb4af21ca4de05e99f617ced261efeb3c38bb761ec1925b4cb34cd1373e69c6aa249f34b4fdb062c2f809b5950153036fa72b620056d7ed00806b3f7012bcc6495afee982974cbfbf5150ac91eba4a2d823cdb73eb5585ae883fed6c4bfc9180cc26a87c2d1cafc842318e0ced740b6afb649d723fd3be7393d053ada9c070ff02d5701f2f820adddac5c872778d7094d16499174b4602f2d8f3091deaa241e6537025056bcf12da08d3c8e2a0ad24efad4b006c026315f8498f0d6174899764ad09d3443520a6b8adf50b2f8ac0700cfe1f08d531a2309909119aed68ac46e19ddbd3dd8998ffab5cc964c13bf199fb072e0382891eb17c8104cd18da66004beeea90c0f842f3139bd8962dcb4a1a0b280a9a40c04ec14c2af79cb1207ce5c42ae42d426969caddc548548bab16d477a32bc98c8a2bb1f7bf550a1f05e95a4a79d5bbcafb7f346670e0ae49e3e699c0052d23f6c070d9276c4c05646a4bf681c86dd487f7a6aa153cb61724bd596d42b9f559acfcf268f96c28458c27743f2132e89e8756805afb5ba4df90d2813b510b20cfc63818ace5b496c8a8310062745baa20f0d6f41ee5a9ad3532c374358fd22595603a45ce7de343fbe434dbaf1c594e724b32b89af3a195099cb51948315ed6853396b2d8e088174871132ec5e5dd81569ddab9bfec0758137ba95648e09a1470cf7c9a3b8c222c92af66b1021ecc062755c8fdfc8bd10a282b9f2837f910fb7f76acbb6cad64b3774cebc4b730a42b9339d0672795ffc032d0bc934a8c341137d2197fc46aaa3b3c7d90e2489a24abb7add6cd00ca4b0a10acb3c4db3a103dba7176a54fbcbc521eb29e808197f06b99ab900eb0606424b67776e91906a7e01993b6f1afa15d22b1a8d4fb71b66e749fd68d7337e76672bfa96a4486493dc9d203b8df383b2c80ea14e3848fbb62d606563d367c45b02f8df2bdffa16a687f1f04364aeab4089776a133fe0c32aa3fdec2074c0042e9187287bc7023ebb62bb21df3822e360bbfe9206231a496e724062604ad5e661e761c44ba27e363a271997b6498c323160a75c2b609862a20f25c602e5c0a5ced58b18d6baf8de66967ad70b96f7880b2f49ac26a561c6c8c37d609f2f471fc60458a94e4a02a45e7788dc0a256060a8ea921f039aae062faac20e7f7226e093be3c859d60a5781541a1a7d3262987f412adec8cad18abd549f1323a9d4fdc6eb8c8f132c210b4300807ca7db674379e7db8bb50586c5a4b1bf715d8da911682a1872c168861f35626c0e0bafe3a32782e2bddccd3c08bb6fc7b3c76f79c44d3fcb74d16a5f02aa99ca05c3a06e9e64678501ff00eb42de1900096c831d584e21398fc02c0d84ff1f71f85c97a128239e852b8560750105fece8f6014c4cf8ace95d7c5c1bbe31c8626b2c2166dab4712303b1454225761c6dfd9e0f59e6d15304302e6f0108cb0991982ec0e056da4b1d3175b0336e0a24a542493b8bad314d02d5ded69093fa5f10243bd9bbd5a6a091936693b62e69cbd2e3bac1feb451dbc7f78e29ebb831cc714351886c13a20ec469fd76d68c473051bcc05bc0ad3fd306636cf1f3805022ad3a4c5ad64837fa341bf397eed9134065fcece44e8e060dcb4e95d4ab972156b21e6ee3e5b0334e51b636161895eeed33d965949d0514aaf49377c4bb3dabbf6358c298e1a44714818eab74cac8331e82bba2c57e21f46706b556fb9654020028a323591731f739f6e1b19e691fddfc2374e1805b902f38c89a711bb2f6a497d64bfae5be177420822d5c08aa025776b6888d67ed5ce12a3e0e199ebe84766c2d9fd38bd84c5a589020a42c2ac406fadbbfbc0c9eb5638dff43b519558eb8cb82cfd1f71d2a50d4ecc73b65f4942ddae1c5e6a2353219c8d40cce89e3b19ac7a21abe5b790b5f8823bd1af644490d61edd03efce7bf50d3ba5face490993f04cc2a363b96363a69e65789e2fb351efe26a37ae253fa10c38d408e0bb2001bc3774d3d25b8887eaad6443a9e1f1f8c526a75a9988399b4da0c5e510704ad2f64c3c66718e4ff4b9c03a4578a83f48c24cdfff817a3f5a76eb472ed21df1b725bb94ef866a3524cdda9dfb423ad05fd6cffb831ea4efcf803e867265bd01a1058723783cfda72b943a51c0789bb1c8633a9efaf7e53a7e8b2c137ef6d44416d00b816af5596fb3497717ce0c466aa55be9dad9c9e06db643e2f9b4e86c5db1f8707e80c2d08ac84d5719cf10049d2145e2b26127e43a4e81b8c564627aac9c15ce1a82f6956d59134834fca4231718c92ac8db6b17e17d72e48a07739be00a41157e86e0386ae90cbfa960eb856eb6e0494b581b4a7580af5c0ce9a71dbfe403541933650373e1463355e01164fc0c71a91b81c75f97aad2a1011ca1b50c1c9ea012c5fbb3a62a09ea7ebcf118d9c9ce6e97798f23b67ab20d93518e12f72001f394b3f5856a1d99a9977167cd9161e4a0e0ba8a5942bd8205a67bae30cdbaffae3104c180b081524cb962bb062da8a0ee93d598da8395a39c557cb6a566223cde2e69ab732dec486f85f42660e4a6253eafdd6da4e60a0735dca51dda1ced295822f05ad546f19b0d7d5154f7027df1f6b2164ecb78c115dd7b9b4fd4b6da465065f9cdbab76b95781a427c8f601d25f39f7a760c29bd4381243be55701c3de86287b2b77f6475c97311ef578c6ba2df4a5b64aa3595532201c0e57a32fc1e127be94faa6f385288b74cec772630e56a523a6ceae98a884ec9112133bfedee0f14e0638d178f68ae95453b78c47c4a2bbe42247a9da315642fde6a14035f68e166a747395b83824b129e8db1b7bd2b3a9766d4e1a88add33083fa95d9b393e733292fbe9d9c66fd323c5d5caed7a2091702934cb617706a800805846c98fed91d5653973e2a62111f56eb10cf59ccb9a92bdd2db68de443f1d89058d2c639bfbb51613ceaab849451c69eac96bbd9ca3b3de6762d4caf04e4c40d2430e3f8a403173f0be387f495b0f3e8fd404ea09571c0673ec4211e59d6793ea7382bb1936ab487ecc748a5c55bef528d02e08dca3bbae96145fe7106e28fb2347f1b2d258715d934850f4a6f1096881677ce4b70bcc3ff6c24e65bebbe1e9c9b47e8d0f30c57618c8d2c24f98b7c134c176a9ddcfd77c631d9eeba92fefacfa0776a45fb6828fa0b3f9252d75390f1215735e9b47243f950e8e8382b471a759ba0d12325c7d67cd9403e849753e3d6c59c6e12d36747e24a613fd53c64fb664f236f5c7f6432afc92539f57658776555d10200d0bcef5db3161112e13b22df38514513e71de928259c219739c93f5b3f45f02bf0b4b6b8a58584abe976d086eddb302cb4cbe11b6c670069ed7aabad02541e33d75a2cf6f7d59fd670e21e37c590176aa28c4c5ad7edd399331812a7d42941dcb13e072fac0d554da5c131ec20e389cab8b4466ef15c2c0791ad1aca51c895f55f8ce7d72807e25bad29ad82f1dae8e2773c24f9ea2c0b322279fd2fced43a6f438952b8028664fc73607e8c3e7a566dfd9a0b4ffbdd0d236a1fb63267d4fa6a30716a5fa663fde572e48ca16b3795284b7eb69826dbae25ab9da1d444d917e138794d01dfbd06746d945315453990a214746abfc138b95b61e95da12a6c77bdade3937476abd003c98e45f15cf63f669364776d3393f5369c35221c9c5409f19119a34ccc0d294d6404a8c91d5fb08addbda8c509257514b4ff0a5af26cfd77f4f909aee396eb5116d106f3bac2a0728ead39a7d131f6b96e76e9d077171519d68ec10dea367d6df8d36bd65089a0d52d15486b063449b2f92c9b6a038d534767e9dd1388801ed9d11aa6c9cd4f763b9b8caabfa98872623a52db6ea8e813dd26d82b3660e62bcfa0aaed08b481c81dfa65ad7b27671c6ce005f6efeebf3bd831bcdbfa2233fdb23066d184583986580551a0c29d64f38c15ae7110ac8fd5c33bd2c459b6b869a0714081d80f59cac4333bd538b2ea13cc638b67db92a173c4860012948c516f2d9e89390c859092063615309afcf5328fbe4492f130cfb521de86fc857ae1b8017026e074c0497e9eb16248cbac632a5df57a50dac8f64d20d03aad96c6467a2e35b0db3b80ef9b43361577c8e3045b09aed45273ebd76ddac85b1533013f282681605aa9e5e3be0228959b2d9cefe5d25c13e70bda4fb789dd6ce3c6d455533ef8175a68ab296b44473745821dc6bd950a0553cec5de6e7d43eaddf69c5203a9e5ff218f8a8174ae7df2724808b9a48ed503fb06ccd5174e2a290fad0a677de25ae760b185d021795cda3c2b771e7d92030d42438cbbe2e149938ad484cd8f4af1d2c49f443a686aab40b16a0b39dceb023bf205804ebd8251ef4f99626575240e466a1f0ed8d7ce9067dff2fcc43d68f067988149e81c259f981a87f78f0abd1bb8802dad02e4ee1e319c7ef67a8caf57aeeba59ffd9fd254bf4777511a6098f20e7991dfa86f55f61b5e65bbb1b58745bd70ad6ef5bc8c1ee346231873979a4ad8355dcc7321bcb66b4798d50659a3c3cc3785880c942af5e32ebf0f16a2884ef0094f81b5334b4ba707ee25eff0c37725f0a6f56640f7bfb39d59b80b50736fa3cef0ad23b72b0d11f2356839b9f1c9863d31af02105e65b31aaf5e48de69dac4c9d40c0b454b5263d04f1dcbf3f133310ef6fb2fafcf47bae3d8bf395fc6f081bb98d06168fc7133afe243839b2b683390f713517ca5119fa700bb61fddaf9aec42d3fdcca3e879ffcb21cb829f560e662aa774bd2434ea064497c5e96e5868804a9458b58e76b3372328bbafd38b16aea999449e9f264399e0839cb8cbb419bdf37078aa19886f5ada413b9df58e84e13d6beb9526d6b41de84a8113087075b61d45eddf9700b665d723c281b0b057f6e42268caa8ec833da6b4bee8958940308a969ac6cdc29b74cecee87a66f98d62ef8a8f4c0f951de8e3f863f20bcb4da664e05fabac0be0037d9d8f76486d6fe5dd2f11c3baf76a88222321e820b1db80dff952173906229d5c7114bb5d8cf9a5b1dffcd7cfd1aa86639a523961a12f17704852cc9ec51483d1aea59868a6d0d4d26a578566e3b46941438aeb3a62369605ad11dab17b30c40a940bb32b2c302c4396f54c76ad68ea421b697fcefc6bfb5a5a66b8a27eb3bfde7fd7cec6a5a66d854a66d4bb79775f9f97d94f9e8fc62e212f1a088e9a044a71405819cafe63c6793895048390f0d3c174d6c9cd34718d27b4026edd9bcdc42de47a77d335f40ebac45f8a910b7c5f52dc9ce08d43cb1b822d9c683ffe6d5a9bca537dddd0be5955ef7995df83174cb7e8d62d2f28372e46278bb5b20f1936766a88d3748130edc5594877e0941a3f449ec409cb8426020f27fcde053d804ff6298785b91e61d90352210b545aae34eb08685feb40d203c18b68134c6413f73ad80064c81b6f9162f77b6e901a6ce03753f5fe4768fc6b067d64ec908ee18eed7cd5aeed7ab19a139c4612dad88f3742e1dadb60d69f835652ee2c131e52cf4c032deb5a9f04bd7c2a44bf012a268e43da12ac228306fd08baca5d9e843c57dcc6873800a6514a5c490006ad9a6251e341095263952a7cf0ebebab298a6e6463de16a9b2ad253326495ee23ce2b08903acc9c4f69126331face6ec8d290d9e307ae966df55eb7fc7b05a7d041c3c488b357e612e6ff4b356287713143764384664480084e51706e19995b5ee7508a79738c9884e48856c542c6f201864e1aa12757577aeb0afd778a708aee7fba54013114e3b70dcb2a69667cd2ff171f178e1c6b11c1041e9e3dd0c43b79961ac6734e0d076af26d91ab573d525c329a8097a6178367fd8606b6d833d0c657548aefba72fb500480698e521874aefd9828db1169db765d22ed9c54d31f11d20f2f2a55fd557500699d5dd06fab26d4c7c07dd8279c6d6314926530e7b5bfd64ec369c5fd51f80326dc72fb3a712ec19b19b3b367492b524632882ea80ec7c07c2dde265aa366eebbb8daef5a219d4862007518e6b17337592d95a98f7809f426410a0ff74d07acb3dbea6cfc5d8d142c12f1bec22a05ae704d5a596b3f24695a5e3e15bc08a60d9e7b665a64b6194b69d1a5bf7fc93f583f5bab3c72417af398e5fa93504cff2918d7016305c6ae02e51a13691a5e423d5be77ee308552a9370baa8a27a6c747ccfdd5551de21f4dbea100cb314ea9bb97435b995c500fd775af876b690aa4053651b3bf086881b2719a90507f759e22b10543410b83c124c429128cf46c2a8a1e2315e34e64004cafa8a81110096690ffae67c0c6264f44425f629de5dd12a693ace90e17de3892c93066500a30379ff5b0eb70f5920846b38869717d5426f608a976234534c50bf0194c3c2b0778b08ead2b046a219c27d8b2b143c6c4b50d7f8812dc5874ed88a4d8344bbafcb6ad9d6a8a1354aa6c48a6096d856e56d7aea214d962ed9768ab9288493e74e893cb8a4665815f8147a9745fbbd946e6e1bbf53cb5f9c5b84b86cc87a0a329cdb589b22ba644420b5ce133da91acb01900ec2f2528546ce903acf3207551ad5e3d690286f8339555da959ceebe3eb3aa4bf66d701e0436c02cc44e6e0f3a36c92d18d5b6f7c21d124211858e6e64d0a2ace74a70e6154cdc6f7c59e29b7068cab58ab36c5b5d01ff7417688befe4e87a361a42bbd1f5e9e1decc8af9d280659a53d4e85cd4d9e453f18e15a5acf1bc190781d73313d4f43ab8869a9c1655567dff87521908e1b8cb374fe0970964fe09d59a15ae08fa7c6901647951387b7e8a24c0e7975016634e35cb9091c6de987205b83e9942b9c3f0e35b6a9fa6fc1e4415cb7bc0600948d04fd2ee08f20fe8b8440c57f331950b0eaf33ac01debfa928aec82f031f530029afa72b96518c39bd2266ac10f6c468b951013e29e291f2aaff2dcad5958d9ce936f7881c1954cb50afd6d4543da61210e26eac1b3e77905ba2942c167d0d1df2826122ba69adf82e2b63d4814c1dea64315319d3dcdce3a5e22257b2d2ee2135d304f0a09fca6ab887ab10e7ff01bedd3cec75e24d7cce67ed5d1dc3f6b55bd1c8f50f71c154fb0030e4edf0274739ebc0bb1ac4547ee12aa0773c0672cc8b8caaeb3a164693b99809064bf7cf3ea0c7f68d5d571c9b00970fa726e929ffb67cc1343fcd7b446650d6ecddba0c9638abec17ae9910ac99d57282a5c174dfc7dcebfa5a429250beb28777b7346c3c3ba2c4d62b78985046eb9ac6d2b38b5ef19b3a68d5815de7733dac4881b0d903fb3b6d5f02cb587937a8a350cf60ab20001c4b0a55c2e8814972ffb469fb0087181ab1ac43758d44f6398849e3c507a9a436b696fe68a93a4483009924567626eda255530d1bcd7a9c97dfbda673010f5dc7548b3445ed8d824739e9180f9e61285edf7983bd1430e3b78dc12c9e5a94500d7cc4cc3f659e9f0474886a952a7a0fce2e0d254db989c9c66cd6b14027d99666b38bbb7a902188e83e8f47694d80cb4c1c5284fbc40654540b8926d81d08dfe56e7d18af59e7ab0480fb06fca43084f73f46f00747bb9aeddfd42d38ee3a6dfeb19770075b2e2cc4098cbb32f3ec02de6bcc3b095fbb6636fd9a624c4819b749dd3b02eecaca9903cf093e0ae6e5ac6faa598aeb661477e7d252699039d06ac9d157147d7e45d9f99dbebb7a61853104be6f60bd35b54c5ace843a9149364e3bab118c34e7b7187f75b65d4c3f80c6539975db08ef951adfa9f4dc5fc6d7785810d5b0aad6a5674a04fe1056b3d46952528851b4f8369f9434431a5180be97e3b6fa8bf4e54af648b72d31da99d87de748a69de584695524704cbd9b5e293fd181d9db402e1260f9741e71ff4d264f3752e3e10b643d64fe148412617e150cef6f913a0ff2e5ab44136b9e1ec7c6b4723a0a663d73ca915fb828651e780b6037219473fc4fea043af1fce596c1e217bfc98df8a7995a796a1c59c1203b10bc5309c3d795eb21024f1a6f929167f8a9cdb96f512ac9b3c108feaf99ef38ae2607a5ed89a76dfa92a23565dbe1866211e2dbf254cadba3c6d9739d0bdfad476d44a41eda17e2ed829a81c046a4d3e054f4383779941d7872e5b25350915b147d3b1b900c7fb8f26bc89986fa2c6831c0bc503e89d6c06bb867e8cfb7b99475a04611edb59bb540f0ed73901a6bedcd042eed350ebeb83073afba08ea3e76e55e2642281b366abed473033f8ebf4579abd49d1f75a621fd1feb0b338eab6320b047f2bef6ddd40b77b26e33c0758a92fbef801acda2d0e2298760a7be6e9297ec1f76854b89e12d99d30d65fa0859506a4b15c386cd0f0498eea14ec3b7eb5128783b4dcf0c67657f8930781c1397ccb36f2f5740048b637d8fdaae3c10b4b740e7c70e0142d6da1642a22289208b6bd20e9cc1c5569cabd26925874684b9510f28971928b5ccc341d9ce742d97f938f286bfd05a5028d18d6eeb07821f8398424647cb18911e1da86ee8995f144ffc56f43537ea7077d41220ef0d5d64962fbdafb374ad8febe88f62cf139d7c0b7da2ecde4aec70ce111916ea129503d0f2c55f68a737be866372edb091a884eca78b1804962ce6f9c57463ad22e0348b93b61fe7bbadef6df64ceeb85373c0ca34b35beab0fdb979be4b797abdbd197e289254b3475c36be3e54df084e578092772649bf632ddffe9664c9c4d4c27b5d0cddf4bd4cfa072690d06a00cfd55fd1bc8deeab47870a248a8f9670ec0ff8ff5c9540f5f75fcf38f18cd6e01a8b67c0ff970d9eaf304c0e0b9962f1c71381535700110fbbcd09fbb840751dbaed510ac10434605b4f8e98a2b3c87e8be006c9df8bd0b1e35f4603fe15f719abf655893f00208800ffcbda36173a1e961627e7a92b4bf33b4beecb0fbae106df2b5934719dacbeec28ac0675e83d533365d6a66a967a21221ae15b6496f9e75d72b1d201cc3d215b8426177c57a634738cf4a64c1caed87e80330e0cc5c89e1e5d056b2aaeddcb2f0188b3e71f6340d782e8236627b00a972384aa2e14502405b64163f0e3d3399d8178e7b91193d644b8b8bf1759c0df0a8b3c53b7a03123697d552af4e8615fc81b0ad796c1e42af89cdd5927160ec3b4aad4153370ff752e236590ceab2a052e5cce774a4f581ea0146cc53459e1849d4fa77994638e659d4eb3f3310e672bb9e2d623822cb998a4548797fc7d9e0c9b8e2b058f1a1f84366aea4720e09488816fe99ec7aad4edf48c4db7d97297260a41f377b45431d6021ef9c986692e592c9fb4b1b4d200001663d308d48ee22460aedeea75d85676d733b9e11f020201f795e4891fc970aeecb7d81cdd0ca1e86a3f332ed6aae270f4b6ae5450f01b9c0ccf7cb2d9fe0899b4be659e930e56c4988f91d426271107ce9cd33585c57fc38f98f64f60ef962e8ba4306c0929408f9d170fea0025f4b0697c3e0d15b9ca33470df621cce7bf944f2a7c0d45b705f670480e4d7ef8320748b9e0e23600c42f91e3e02fab0fd1d78b9473f0df0e52584813fcd55ad0dc78d61c31531b22b7ee6190ee3c9ccbac9b81ca9681432bff02120ae95becaf08e43ae74b091ea01be86bade9da166b122289fe8eb5d3d412208d830e807fcbb403b5509f38fd2f8803167c6e5ed671fcdcd0a1a6f1053ad324a7754403b2cbae852aed85b4d6ce88b4a5e2b6b0c5880bc37227d380e2e9b635076f48cc20ced55b9945f4bfb9fff86bc11ee9e05211bee256b5f7752c60c3f23b4a69a9136e299f27ba628553e0c1a01a97bbccd5809435384ec89f1f97bff3e75f5ed022875e10eef1a4a3e357bf635d92e32ead409a1df67d46544885390e2812fdd52ab71cd6047ed4df96200ca12d6442fd11dd1f948894940864ed45f9ffd137ee583376148ca03e761d65f23733d95ab5c09e8b7badabd5bac1a62acd1e1c846d8fda4f9623b64c15543ad244e806bd3b3a1d06109ed4458ff16993cc6bb8b74728403195e519fdefa3a157cbb0f1ad7523f9f2c082b214ca038f0a23bc0197a4a321f09bde8abf0d5933cfcbf13b407e182e8a7b66364ef6aefd22e611dfd48123324d007a3f8adeb1b591f7868e96db97119e7e4fa4710aa00a8a62b37bf93adb18a0ca036862ab095c8c23d108965ee30b6979ab29a299b5b4a9fdd79c4fff059d5f0007171d810f426e6926e377c006565a436a44e629e60f4d4435ec0317f4f4e5aff1633baaac3f41559b69cb5bde95ee455c396bcd209d88971356ba00a2adf0b27381e20ca54964b74db0fefb781e322463b4d81b827b732baa82b55c099078b7c52170398d93a17f523a83ad5e0a04c854ef792ee2ec4dc2e757cdd03080ca89142063dc77204b50ffe9f4a7164e05f772a20f3ea80d9ba1b55f109fe6837e51da932a8817ac77fc67f588b6c15ab684714eaacfb8e9ad75bc46a65951572080e9ef7f641f349ce9159309fb8c67282b07f638dd0feecadd6687267cb8cbd81d723baf737325c54717df1bb64729506d4e1bb924d4b9799ccb380e522d8b88e6686beea4bf4cd53c5f1c1e63603ff400410b7376dff6ef0ef9667ae26f40863b5c106490eda0ccc48d43c868b9b7255457c56dfacb6e2562a797178a01cf8c2b75b465977b7584494a79f5cf51de5e8770f91904167394de8330d4e3a6017ea126488a0af69f4b539d9de44b12056858e42861e83582b36710530f11662c700e43513924706c764082ab374253841f44a450c1c05c54776d985fcf3e86f546e9d2a8e8494dfbfbadf18f4a1e430e78a81ec9b39c132a6643b388a28bf1279ce876bf9591ba250fa76599b8ba58b3e0fc7724923be94c009f7fa6aaa103b2360b730e69df91b508c3bcda5034b2eb7410b91a51a3ca065c4b7e11f01955bd5c1538f34cd8264347bf6b4a4752c8487bc2aceb1a94d7d5707496a3fd2b8822aac075af7488e170d7144f145ec3154f473bd6f26eea41fc44710287637a7f69ef63ffd5436450a0c9506fbc9d18b3643cb9871aef7dd7cb5defcdf34cccdfbeebc0dbcc7ad0b1ed3fd332253056253f75820cfbfeb166e89219d9afa331fbbe37da02a08560a90280a85136f1e48af0e8f9b2c2cecf7559e78a53f26c4937f497e956ccb238bd9a609419a990e17c02505edf0b1777bc63d9d04e6819066209edbc288868a650c51e3f2a86ff87def6cb25a631023b6e2e873075a7d176160e8a47b5493cbfe6b40c426fff8158de642eba0bb619a81f155df62062f8c9bc9c734e343d42915abe2b1e8e616949e8ae7da3e66369ec66831518aca1c44d5dd1605fe8747a7bf50113dc48157d22b742c19676eedde2e15aadc6c68b5f2a39c0d7297c3d3ceef0cd40f88bbc5ab3876006b86d85578d3324969956d5307d95cf3a2275b3c2ea7f8cb21400a09d00c206cbbb47ba7321a4ce88bc6d5e2491cd9ca1c07415ed0a9a77929c48a4dd01d047ba3235948ccf7b53d1231eed1c37a7fbf9544aa1aad6415ddf84882604cf1156d9b9ec681c345200cfcdcfa891ab78c5ac35938bfad35aa70855a75a5bb5db","isRememberEnabled":false,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"d858f7ae6dbaf749552518002a6860ba"};

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
