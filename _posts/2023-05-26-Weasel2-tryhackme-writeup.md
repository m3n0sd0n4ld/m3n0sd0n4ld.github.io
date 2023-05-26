
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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"e7f983aa374a2e6f31fde5b1461ebc195a35bcafff7205f4acb0b3dbdd8694db59e8ab871cd61c58d6c41ab61a29439fdf715129fc97cc3b10819417ff544f0d9e001780d2fb1b2006ce697438468b93b5bfba94f62a1de22f3ef84b915254b13436230aa33e4feacb13104c3d69d1c1632272610b5818e0cd6d2cbfc4f5d03e3844ecf15d4ec8fcf68b47d5193719cdf65cd4ebe7e6b60df4317300949cf5a04e18347cbfc2796aede300c258e07f98a87ecd11295e3bd2f545df74be252604f0319f26934dbb10d01d92ff9a705443cbaeef76feaf772983ac9292d52f82f172ae9712f2708175cee12dff515c4b7c33cd8f448c912352f315219c5afc4f0b6db161aca1ae65919c3e2e7e6028e1166eafc87320957cbb261baa294468a17ac95c39518eda9925a4a84622ee4b2daf2e8686aec0721e6ab7e9570808481d0d91618ac9b47b13f263c4e873882eef8b7346832589dde803ba3fa3d98853528edec35b9017b58457050fedb9bc5bb1cd34f9c96c3b8a08beb49dc877185f5f294c47bae5584e108d85fa12a234aa3a8c534f914ebfe1983ec7a16dec664d0bcf82d0caef3ce28f2510ff8ddccb2f363aa301fbd2ea9edccff1a1638f4f1c9b3e943d62ffef7ab8bfa307b40380086031c4152239e97af7dd2220f0fc4ff17838900460969ea51d95db5f21170e6b91a6179487e1fdebe13df6d9424f2bdfcedd90e2d01c52f6ec47b6ca2f01d4d7d95173bcb6a70d0e145e87cde57fbb795a0fc3cd8aa567ec3c63c41ca3d65990ca68da575bb798c43ef68d14b1a408d37f2b8fbe70c6a401920a6a87689c2a0cf1fd4b22302d3b1511080eb67cbbdeab34f39241e0f5fb8e0cce50dbd5d69d929a6c7567270db7538779d6d875f655b5019a64980e60f150206fb0daa7ae29f1f2199343bb5c2a09287b38e81ad86848ca3f998b6fb6dff46ead09edd40cefec1ae8bf39bbd2b4ab65300289c34ce035dad0816fa125b00d4d93959ab31668fad7b69143491bf36561bd0d844541ba506ece90655d8aad11d2c086eaeb2ed54bc3fc28869be29f816ec343ca0c321d0d376b7510d2a67a414a09e2e4db335c795f13b4d0e8adf2d4884c92a5b78b0c6aa0d6931451d94c2d838d38606d730b77c6976bea0106e8178c11a749d6f91f2fa3bd3e9469b66efe891203f3b9ba827717f1f475ca970dec0fa2bc684278c2bae0b7f064b7ee585ae461a82ff2cbe433331b6575c5daee6a5542b222414798b731fc0f73164c0c55b17b6f120d3abb74ababa234d0575f2927207d7254239773dc934becbc2e358e5e95471bec63224929069b67e5ef692e3ae665b913f5c3812f3472e1d72dc9e3bd4d1d82d4c53f710f8689de05a89d65505974c41f7348a0467f424fb1b05f3fe733ee89929cb39383688dba29e8075cb23f4133f00cc59ea71458b605d43e374a1ef138427816b03509b02586d7b381b21f0b7a963d395dc5666bde2b8389715fb2a5fca03a9ee13061de4ef622e17c04ff5ec21631b36b59f7fe2269778872cbf5aca49797a215754734594e210254ad71a02ff4c51f685cdec08bf5849c8a56a135ab856a48d291ca48c97a3d9b6cc7486df25e906ab58ec7a9ac71583aa974e4c2c9297160fc4cf6627ad28fa0494bfa619b4266bb7ad2c019c2733946dc3b8a4edba150fdfaeea9e49ca2e547845af9d5987f85515c3d72289a7f72a940e9da1cfc1ac16242c6a42bbabd5cf8c520f13e8aaabc7e8b7cc326b8ce7f1053fb9258f0f41bbd2645d0119de762de8b7c5bc11e263356dee1c5280a1de24bb676084a4e9be9c5add7c73c9f7ebc45f6cad0fd51c3cd1c96355507935dc06c63a2c7a8153e79de2fee5528a939d4f8edf51c9bae8e9d8676e9a814f11a5e569d6b2d30992325123dfe3fb34cf3539533fbd9410f5c1a09ed5d59b9c982dd45f47bf069c46e26cd3fc64f1edb4a4d4e5115bac5173a14e0e0bd9aac1362e9d4f8f60cac303127240daf4b1bf7f8277ed43c73df66e2e38332d30fe126d3d4dc2678066aa5713c81f0edd0519fc407416a8b96168a69cf18c84cf55ec40bee35e88d739db308b3b9be6a1f5047b4205d8a435874fd963d05ed8ba9c5dabd32dce1c1b6723fd54925f96ccb6616616a7b94fe3d73295a4058d70e3e9c2330f5cbda13856f29c867205c265ba49465194d3577ae73c91e7b3bfa4d911074e8b74fd1cc98ad9e8eaba79823d036db2d15dd1934a762f3dd375b3b704f139d46fea83863ea25c136ac9923d7a2423d3eb5c537c34af42488c3b26c37da7fcca5e97bb0327bde106af6fc00ed8de3bf457236b8a1c61cbfbe27b4ce37a5d165f8fe0514f437b112461826b1a6c21943dde37da80def55216f18abd465b5ee06cb1fad070e737fe79a885681d67b0b11d97710f59ac8f79a420716e25a046e690e90646ad73239bcd556c4ec1d816549d70312e64874545bb9cc1886e9ab23fcdf71288ac1a369beff90a790df4ab89ee02d84d1d003c483149edfea7993251eee9fa71572df9ce2d1ca3778b3daf59ec0ff206f84605fdcaedca6bf2376c4760fe8849c966ae2a2ea8b512e5f176c28cee3aac9e45e20c3409f068d0c324ca04291dd9acc1ac6f0d4be74e0b9b5567187010d23b5e455a1a1d997bb8b646ccb2637e2177d429356960585523057be22329c93552a9bb409f0791402d7d1fc989a9c7b9ee70b81d7d8b47a050b9fce69fd8ba31f98fcb08a369ac9b3bf2d5103cc535516bc72d78a7cb87be9b424faa6f8108310571f1a2d2a4583afbebe7e2eb864ca6de21345408f534dd8d253f53df280f1dd2d40c0f4594ebb0a75904b0ad851c83f7056db3fd4c1ceb039d4a8d7043984a4fd15ece22aaa4607ea7c238e8dc46af73e2c80e99848d2041ed226ad7551e4ce90d9e4ad197ec02a6febdf646a40ee9188fc2abb9464bf3edb52b66994276c6d865d02a1b543f5bcae91c453e1440ce2692a05f660cee5024ecab48cee5ccf6c340a94647ff6523b8028800008db669b1a48c6f0089afc9ae4c7d63eb0108e8e5cea444b6c18d6a6fda50919189dc94c3422cb57c71b4eeef0831cf753049d7cb51f05c13553c53bdecfafd2590423ed42204250741e819503ebeccfa775778447bc20df5dfa8d526fd5acb28efb85cdecb75e65accf228a00646153a1e49dfadebd2ef8bd0bdbfe70699abc62dfa9627a7dc2a94e0ee4449ec1f12201494bdf102dfc8775cec1b9abfd7c0fe78bf64dd84cddbd1c8721ed259a939acfc9344cfe5ff21961262b6d9e1df55f87d32b613c8dd4beff969f62169ba0a6352f247ef08cfacd951b4e600f53a21bce20408b7d640e8b24af7fca8c046604e69d6070393a49a913f5448b581b0e026da8f1286edf2fcbbc4c7e3b6cc329ce54b369c96e4f787edd6a9513c47c465cc13fcb52ac591e60a0e44f330d6b2bf265ebd2b1b69dbec281e800d1d9b397d5ba1cd68bbf8d63d9187c7502734a821861ef2e5eae7d65cc49dac7e2144a47c71ee499de01a357847eba212ff3a68e2ca974191ed8131426b818e0bf51292f102a53c52a767c7a9f9425e8336918cfbb75a88b715294904f78d8e86202d7ce7212afb398361fa79968ec839cf53a35374b0ff415177285fae2609c2241de688ce4a29e629181e2f8660e9e3993232dc975b7ea4291f41e533820c0b0cfbefc60f64e97966a355e006d6f6a39d8f0302c401b212c110b3a85addcfce16a170e484fcb5824e4b3de054b3f423faeeb95798f3cefb1cfe0b6b7c39c4a3c07f58bf9058beb252f4ad302e02d70c9dc0ce38ce531e74bc9473a54f99ca652bdc752f9d6c893407f5cc6740d65deca26401ba02d4268e2352a95e59080f0738dfda62539a82837543e1cd99794342f16b2c28758eb38660d3d8218fe8f592cf74fd52bba7540176e0d65cb530630bd53076b74dc709a667bc4ab53695e877e35bf26064e1d4a1e9e8ad5114b86158e26321ad4bc1dd0c7891e7f599acdea3551e38338606ac7d47e677db86a6558ba340befec8186710cd1de7e75ed98176d7ae5ecc20e5d41cbb3288cf181bf334b1d66a9c978809c3c8f289b086270fb118cd2c2648377c2dc4c10e56088b008d20b9e99384c98d62de1c9382eee2670d56c9b46bf56ddd99787e2d4b0b2971660a0f6c05497b31776144310bff5d8f3c0be7535e130d83a1640856165dc04b7a0594056b0b42e88197a6c83f8e1892248da49afca1f60c050bfdccc1850311a6e446f04a44e068bc7c1a895e5b2b5a05b8391921bce32790fd08c58fad6df780e80829d4ee38fb2c2780dcb62e4860d9be3fcbd2055e0a2da69c86a84571d91f369faa367f104c146a3c5acb356ea28d04338b69865a166093a1c511e92dd7f3cf14b4f8ff1fb85180b79224109629f564832381c062ebd4da484f20d054396e8818bacf9b222d151667adc84080bbc2b1ec4d5aeb95064e3bc387ffec131d15ac606d14f688d1056a84aafe82f89e3604892d5c1f05a8439b1e575b195a48ca8e3fd18bef4b862c5d83b835af072acdddf25af98e63141adf76a9722aec5cfaf103bdb4c18ac01db89899ca83cf78792567d01f2a6108a7378aaafdd5c6a882c972f9756fc1c4e4057ced32f953d1e32cded74f8a5f8716fc38cf85c449cb5b639ac9733887234603598d5a0b2083e216ad0640511d64fc3bc39b8681a713bd6b0ab6e9eeba2c0857da7efdb2ebf18cc3984d0c60cb2ba8e8fddbdf4a676075350d860f21ab54d4298cd14c5a7610358540b3e00a8314709c0c3b1dbc9511e0b10b3bc4d1f6501a5e3a977bc156eae385e7ee749bdf6ea0fedd1c2595acde09976db0903c6604d88d737efc68b87c99b9808373f50c874ff8c205388a140ab2807e49ce879eb8cf9489113fa4c27a61e14899d86c77bcedd74b5c688641163bd229e71c718ec48ebdb0f4460fdb74d09bdbd6dbd01cb30c9acb93f6ca9bcf6f2a99876eeb0887416b480660c0470a68861f5029e3fcf03044c0f3ae2b20df314f770f2c45dc366a0505124a12bca48991c429d74fad08ccce85a4fed886f8947304d09a88aa2757da27a4c527337a80a6aa550b0c4d7326e5e83b201324192cc37a29c60c14277cab4a50e6325244b628d91217e1c592d4013b0f54bc972a9b4d000a71151f01717ad03dd20dc822a295a049af68d020f2a8ad228a9b7868dfcd302e8442eed07c5e5a9f7d06057e8e54615884e29bf078b5682b98f22a16ad718d7c458304936d1f764f4901b59e01da5bcd37e43d7ada36563fb80bd07fc4a8992cfa877618c2e8edf52de2708855cde1968030ab4abb58e00b96b83c8f12f6ae65b9e85a87f35ba13018eb19a7bbc23cd38e621445b180041130d866be36c6cdc7335c0a7aaba6fe566a9dc264a4a2746c745f10fdcbcf7511ef7bef9d129e9aac102040478b7e13b972ecfb91dac4fca5ea064131adeb3c7c2feb9a0770744de1bb43874c28e0b4a1bb902a884f902e29ab8d2c48bb4d6530e5b34be9fdb7d596a0a80564a137db1cb7016b3aee234f4854384da9a70b9350c11a1feaa8dcc3476f706252e87b14785d1dbb68e8a582c0e209931f9f852579a80ce42e6e0959e4b2e7a3fadd3b339d0b49c282f5f7cdd9b7a13a8e8fd1a93ff56a67705596027a9184c799f9dec09bcb03b1dca6e6772bae5fb26df68f9c70c5f7d491696eec224ecb9229de1d6aaa31d36342fa34f2f851431bb752b9e230b759596a417c391d15de8fcedf5b2c2157e4938715d020eb0b562ec5c7856440df7dfc8d75d25236e5448238e52b1552ae4e116bcece4dfe9a3300d216cd643c677090e9f1fa711a36446fa0984b3f1e715dd96bf714fb050e21a258def7ce6459a604a176098d849dbe1739a357946f25acc9a3027a56d92a04dba4509a7b7b54c9cb4f140678b602be284b114669a59cba54db7c98a7cefa9e8b5776c9c1791c682a8b7fdd8b77510e60fa816cff702c8d0835e81e14e7aad409d33649db70775f36461cd5c5d31cbf00cf6fcb70429baf2035d83596d4e50f764e53b3ae6fd92cfdfa33fb5777d422687539915b2f6606770af776e2ea12d5a0b70118622ca76d8c04493864ad0df5c3f95cb7bbd7400864a2eec9c7f1f74a2e54c718e0c495b8d9097596fea1b4c21975fb7aef64e05db0c506e849e4368884fc102cfc1fc0291ca6ff26b8b7d7354260eb35f7fe285a69e17f1e8efcfadb637b1cbdcf9a556e6de2f2ae745b55d3ce9f1f7b7a8461d017f0cadd4aac795e656020ac685675e2ca57f9f4ed05d1b6ca81c6339b61be51fe5ca9f3c18090f416b6505dd8600ceab77dc42c90aaf715e6f3cc880db87d1f8e2cfcda86eb944c545ff5bd445a35ec4fd0c58b162f4c4e2f038c5795e1b8fd0c1f73c17d2f243cc867288e66e3822ad90f8a38df057ae7de16e376a470956f13bd2b6c423a991478228efd225d2469bacbf4c97b52e0efad354fb1d83d3c056cfd147bdd40556fd5fe9689f51e318b2090e87af1296fe1b6bc76e8f8fe73f5a3fc47a634c50fe52d83da41aad98b91572e7789281f60b7e52faf002ae92ff442540e849644cbac73f12019e34ed83ff1f45c5f8eaec0035e340ad5cf6aab105e4114bd7ff9a66ebbc5dc86ef60d8bb4b2c99497f76485c77e9c300e2f4fc0dd4f6bd377e19056f6d1f5a4db9a6a7a3a1d9f6efa715a8548de669d74c8f19c43d99c6d6bffc887adba4c52feaa0a4616318b869f878b1f79a67f4605a3ef13259de5e3cac88fb4628c0d67c4e68e50b5192442b1f37451bc2591a4da228045934f0641106526f3ae0f5f812fe00b5b42d267d1b8f9d9b22fcfb8ea7a4f818f77c3efbd27af65064efd3e3cf3e8ef8b0c177fd567f017b59b73cdb749463e25101d0c13af4dd3930a464d18f737a0c8363ed022e9db0bc9046eaf96253a4c04b30429ffda10af16a3dcacff50ed0437aba3845732b354d07648cce4d39e43d11ee22056e575f88c359b098750eca6d621ea3d7cd710a9a7a1c5d9c15d2d9513b4a8d2d3862e004ed8174f941c35863a6740e8eaaac1c35396beff5f1c41e6bfa7a79dc9e8af0aba16fdf5fea3f94a73346339ca1dc48ae0bda8229d0a253ba47a170f5bbfc6cbf58c539e5f821a45d318d0b3c79503579f95faa5cf99e597ddbb229e2d4f4dec16f993412f2a4c8173b4f990c3ef3cefeb727d9cea2fde1d64c7a870ff3cd547a377225e19ebee37041b8b9aa35a084e24bb9606e8278ab10e75a44fa62024597c88d4d9c3843f6928eded95bacb509f67ff54fb5b457d6f1328ccf764889903539c883b23c173857f02b7a9da2496dcaccc6d2d2cdee0a53d48869ea807134e6eec4ab685abddc7110d7b93dbbb3bfc3fa59968148ea784f49bdd512618d31683c9b2d72875dc652ea045be55cbc21042bf4aa138c1960bd9188f0aa53b1bbaea3554cd2c761af8703cf48c9a10d560c2919acfcd1fa289858cf6bad7d0f0233ee76b8e9c85010f38745f73ceb679133a8069888e7907006dbf57a2beb7d8753b8aae6a45ae74a4c099e856bacc0e8797832383ddef30ecf16a92d5b51eae56a5bf99effab4a5030cb32b19dae5bf011c2974f0c8655de732aad3c1947d32038cb7fadc60330d95464a34d26049bb6dacd2c565227e13d55d33340f503f06a868746873f576c2b502aef8bfb3ccb033b92c0839716ff939a263954c32ce813defc3fa8afcfa338666d321690ffbabe514afb556201246feb41177dc812f453bb8c5681cd33a647eb9c636bb2f9c0bc20f79b18072edbdad635d6f5846269b2f66cb6e6ff7474e31f708cda4dad8c0cb2d21c214b380ad1b9e823fc70033968474a7f9ddc283d74c86de626ca9fbab6be701eecbd663bc027b45b52ca94ae93c05d7bb6a21bbffa7684e7014325cb8300d3b89ab18d04ff91d600c63f27560a8e466d15a8bd16f77916396de0a4c75a2c9bd5cee342ac50d037d2a2812ba55b3146d5fe64a94628506f972b59eadcf5383618a21f90b396595f1ef07c48c0515da8f27eb6831948ab5c265317bd6436e3d60c71da76009a48bf8c205c75073fdc36e3fc6c667b3d21cfeba762928ae06fbd13b761b59c6a47c33a2928007c55b7c07e0c299f19bbe69c40f2b3ed0ceb5b954235be690a2cba2c0920ac8df2b754f9fa9e23e84850757abdcb518e56deac4b3a67ece9f0cdcb4bc1177d072fd4087e1959d415208063bc97298c9170e7cabe12d0c5ed565ff9c9cd5bf6fe6476c6725b1f0e9306a61bb3277c0c91357d68a89c0dd5d887fe15809e7afe344c4c0e2ef2a0a6f31a5f1ef96239ef3d6b654751df3abff0f6fb9d499be28badd51ac6a2cccc23af57ec607d10e9af1fd9ca8166a876a0163ca00c118d415153e7c5238bbddd06763b986761d216421a71fa867f00a9b6b4787a564cee0ec00cc0acec4e75b0d5dc1b4e82f270a9c2a21485fdb099d5c9756709128e21fc88925ab0fe2ae280d2655a62fad2edb9be70881f48913031f8992ade812b7d07c9240a2d4a7c55d58131441b5e9044a3b5a84d80e1c51035d982e0d3412b12b9ad245151b6607ed48b18747c83b04055a0f69b497064d34265a3aed83e7c5a133b087f0cc8a093b961d4e0cf05afae00fa1991f9811c49a75e8df6daf0921e0295caab80d38867ab74ac54cdc96163c02dedb8bcd551c3cc033f6d6ae7f5c6076eb4b1fe4253bb07237bb3174e1cd2ae6a173073ccbb25a57467e1b76a1f34e724941164b9a4008cfad6cc02e671256eadc7e7a64b82287bbc09301f1acf0273a49ee17c8dc702344686d13bc3760f56f064d9200d6e192570a7d47bfa8328db5de4af1c14d18da62d50d13f57acb9c36d4eac38aba5f01a7dcab4560cae6993b2a8ff243e1d46b2fc2c5753c8712ea104da04ac16addf50a2c7dd4fb3cba1151d22346d99391717d281b8a7234ac9ff9092a88e22083113a8290f2b6ee422f43d18094f3c56e2d0414e7d38d26e0eadd28785da31a7b3a347956634c806ad5f1090f3342ec35eaf2f49156bb28dfb22f6f4ca5ef18ca6ff124d4be0cbef0da27b0c2b6bed311460bb990dc50a7fca22f9c5d1ae8de950efdacdf3fce8f67966c3b7c225d7315473fbeeb8926a9e5536bb7378d6372123e15f7d500c963a70b04bca6a8f822ddb61691204041ea6065dcc71253af9268e6f882c34c3cd177063fa51381dd3dcf906013b0ae8ab829a0ccbd2022d99913fcd527abf4ac2aef0ad3c989882f45768342d6837ce4742dfcbb150500360c2ae2c814f957fdeb482a09acd22b6f9b3a651b83bbdb6acde56615cfcdce182b9919ec2e467d649e40144c48d7464042f54dd61039e4bd57f177b3e783a2cf722609522c1bd74c30d75489e7cf185af156073bf785c1a748437de176ce8d8981c6e86fd9061033743dbfeb52a64abd0e47c7174ceea6189be797c91f2a6798667df7ae9f3bcf1ca20dc8148a42d1c9dcbcfc2acc5007778dde8f623d59c09d58dacee4111cbb69d9f640f32715c3911e1942e698424e21d7291349b0ad94dc65797e43890763d8e0187cfacd4b3f93495053a5a6b7bf6ac425bbcd04450255e7103c7b444186b799d38e4104bb1ae49e155c6d248d7c20e552b108adddb36903f0104dbefdd189d13d59460de60f6388ba10207d7e605d2d46c4894131b76d72369c8066b3de27610cfb62a2dec9c7f8dd45d320fd4ccfe8a57a408835714613ce8a9de5cdfc6cfbd5a0e6da26c2352e5b3e1dfa7d2aad836546328960048f368afec5c7d14ca8b6483b60e202c5cd96123cb1a1443c3bd2a089ff14b431f1d31259ef5fef05a3d0122b6a75b50112d74cf3eaa028e9e3edbe23cdac0d5260894012798299f70904058cc1e017af26d2b87c4bc4477e323a35806f6d08f38b7d5de342a533b688707fb467c2926e00270ca47834291091ee8de25721a7d2dc00902cf36214ba2c8324d6599db922b09bbc8da27b514845d4638f046ee9cea003d604801f9e8b6386155e13496237967804fca26d7d55edb4d89b74bcab5dede36d800e55ddd209f34427b14bacc7e9e00fc4d476000bb96b477a303f035b0829f08445b0db75516742b59ba711619888049045d2721f03765f31c6a7558e9417a1db64bc08782168688a0996f639acdcef623f4fad5f75b4d06c5585496d794cd573ab9f7c97f35c6af62f139d7680f24122070f8053cda9a41db07f0c113278ddfe7fb3fd7f7e67ec529ca77aa8991942921d2fa6d8a1458593e99c5941e40cf7974d0218fe107df34cfdaae5933e697235e6af75ba3cc3397b6e499a4f1bda108f7ff288437402d9d6a601296a6369ec4404fa5e723ce5ade658558d2523832de56f5eaf1232909eb81ba7f5a74e983ba0812be2d4c8d03ad17eb479ee6b220b619a851db191b6adc13ff0445a3a6cec4a022533ae2309a93dfaf37586c03fd3907850ae69bc7d2036813bdcc95eb12dee78c3a4768e7be70156a4054076109f2eb0090c2aac09c983acafbeafa92846ea4555a5a26996a22f476a4714344e04aab411174bfa6c1db3f7df2dc6fe9b5891eff8081810948b00cfd7537c9dc7d25f123c044cf9784d726305f0de7d947836ba7a0bc15c3c946c41af085ee0a1e257ee49fd1ab33bf4d1a90273a8078459e4fb898f4f59127aed529b7a05dcde3efb0dab71bc84b3b01318650e3fd9efc8a5f6dc1d2596a8f0b27c8a7e6559e092228cd2616d091eaeaeec747d09c61105d90415285de351ffa50108330128529320b343258ab5b04c09741f7f81f8cd4eaadea88933dc53d20d26d62555df687911cc60f892cf690abc45f73192ea6efc149b2a22760cfc839ce695eda2a615946a52d43168ac8fa96330b8cfaf097c2dc3bce2a290e463fcf310cd74c6e7589a971f7d5c998d721d4ef38288d28e42df3233fa92b021f76c94021874a7a33afa86d938b5eea734fd84c3795534d5499c860a8ab96ba2d21bfb85d81a688a17ac4225f5fc3fc34b0fa3df5bb22e93a35a42e488a222bbc51e1c8f4500839d0dcb75da6321ad0c9fcd1341e990e0ac957bf5dd20e1f3cbf3dd162e612eb951ea84f44c42680994bf5d420f78102fa6dc6988614e7ddf43e8e8f815014a54daba21bb18f858d6ad26dba96fafcb38cb31984231279fb01018848571e1f8eef5d2b9bf291a53506a6da0c2ddc6bb475c8324bc5c58974f17c08ea6b9716ee4cfa37804a82ed0247f482ff259559acd64996011973393db4f803db0201f88b6bb23c02daf7e1edbec4c9ffaacdaecb4ce719470398bbb43a2d5329b1e963586d0f6117f77cb28ca1ae47e4fd498d88ddef63dc570c1c40c79b2827d008427da7977a179058edca640c52fa7c38bf87c27ddf7f8f8024f28dc8664fb8914e2a5fc579fe05dcd6907f095bf1d5574c496acc2058fae7d0b3541c580fe0889ee7b5922b3612b36bdf213d09165f7dc90143e392be931e11ec9498013ae1a1824bb38d71bc6701077e87a3321f8c9a4e6d501a55a760e0c48302e5006fcdeac23bfb50165fc0fd6041d0ad532547fe968642b48c1194bac9b56ed088e831fd823bfa7fab5c12545161ff21ab72e1f2ad78f3134ed9e25652d7af2fbd7d8c68f1a614292957ace85ec8401a3107117f8210cfd290c008c161f8a635ede8b929936a76bdf67852bb3e8349da6e872a1ba79b8d6b1bcffe12f0b646c9c4a4e6df8e2e407f5d3a4201d55325c1f799141a0d79ea6a7abca9f8c84b0e8c8e8b0079dab8e8bdd9bd5483faf9c8753cb4cddbb177657395da9b0332029e37f8c4a8391bccf29ac6e46ddf3ab6a96fa89ca4c62a385f41c2a123e6ab8fc4e4963d5215068ff9be7478708239ae62acd565cf45544052a162596716fbe195c5bd976db53ad7e910da71a8710ce7ed3809368513fc13158129f4c8dd4b9731ce0a23810c680329138910924dc8fe8124a676edd2002883b35955f4b1c449a526da4317352b39c3a64cdfa3514e5df5f0934bf6b7f80dc8c8ba7ac1b9e44a4a7df8d20f03bc1c741edbf0a9eba79fbb2c374282360865ee58981307ccd39c882e886b45613f5ece294407112d002c48bdd34ad63226d98d0f9d782f19d6e4f137ee6901dc1aae1034123d6a5047115beb62fc463216f996dd02d14b154c3bc0c78f21b274eef8b95c05077c8d87f2defd4f3f76674e057e5ee9bb6ea20fa82a2579fcf414ff747ae97440e921e0ceb1aa6852fdef7baca9263692ee45b04e98b3cecc305b849f8bb50f05e22769e3bec9d1aac7537473f48626dbf472ec79b3a6750625550b8db43831d94b9405fdf1cb13d1e5bf32ba4ea778993de400bf4f5299e01597c82cf4cfc9885af66d474d1222cdf373a7189edeef768450196f1e7fbd943b28762bd10849eb023e69b19dc65eeec089967a30fc1b4b59ac3e6ddbcd2917b2d6d6013b1fbd5084aad6ac8e63f2109ba5f8c5a940cecdccf66406b1bb6f9d4c9a8797a814590ed43aba072ac2a773906f22402a543b1decab3218f3ac767b3572bbb906a87dd1bd56995b792449c5f74079ce76e3d58b364f7168908df82a778a54cdd5d42c82da6814edf669209cdeca886fa95f63c6aa1bc6856b310a5a1d98a2aa85e269cd30512d501ba83b3ff2be3d632a4b99f9ac526af7d8b90b67f5c26e93c9e949ce2703ff73b0e5a015b718f08124d91d10d9b12db29fe2523d29c6b42f77f14cbeb62c823cd009d57e95ebb55d6da7cc53633b322613858685ba0458e4e79926ca1bd4e09f308e67fc079483070420006b62bf6d50e3d214160e8d1d9fcc4fba0ccb2867c8a008b76d85bae859f43a108e28aadaca1bd781c9dfee5a350a5d214529780b2c6c6db79912b20eafa55373e55cd7b8c146d9f5a23bf2eb37605b274ae0811dea8493bf14e85a937c15f5d8796d6268337328ec20b22a22ca2d05d448f155f4f4af89fc2e88f132613ff0aa823952ac79da64d21f385962cf4a7a79f3e38e6845420260565bcd5a5f85f4d0a31024a275ef42cf96b45032701efff76f0479125b69b5f1d7411b658bc6c23b533d4842d87337806120f0fa7d9666a99b250725b2cb6ca176a7f343306fbd0483863b7b4e38bd5ed150c36c7aebdf69ff3d7809a86be9c4e88c4c8ada11647148cac51fd7c1facda4d4ba1a2c3e5cea24e940c5543eaea66619d94b7e950b9091bb6df1f1d88e15219d2e183b8174ec33320e47b55651b6213b1c3254d0117ed7ad2e0f6b0d9a88e7e4e0ef6ca0b223921fae982d689b1577f7430006975c39cdb27dda5d95b3af41cba174601e535b818042731231b7cedc1e8bc8326e75756c2a496984945b5ae358a7943551e8d57084674ab6c249cd8f7f5e0a9f68abca89a7502ec0e6d173a19073a9a3ebc7fc0e6eea919f2d0a7bf523c650cc1724286da00902e33b62b724c0d8be7bc2b23ec52663775be22c5c37e12d332ac5a90c3c8a6b39d7218103d90bb5a2744a26371f0d7dbf9bee27c8d75f65092370ea0a8fb474d5514e7434478d026eee3626f28c92e0d9f111329a19b8e890c18defae83f37a111ba3f48f6dcc0c469852c242c133ee40b0eab8c7bba22bbc4cf3f518d40246b829ba9532177deefa11213a9b467b88ae4195b4591dc52016aa9a63cce329da95c7e3af446019b17186b2487408d406425e10b99dfe6d69393664a7f90f2b1d12736d8b7241813f9f46d1232f83b506328f4347eeeff5590d38fdc84946e7e71fb70373e967f78e8b2d11911a3b1c250e1e02e9769093051a82d894b6988b233e446712b9640b3a5f84052c22a466d6b432e71476316b96d79e0d4b653cdbc8858707a847c8be7432cc9e7474cca271705205fe8ff0a1059a9a5e8d90d9d91db70a262ed169dcb80df8f830fb41903d1b5e16678cfb14de9c1cb07dca2f0d50a194b14ea83f3b79e9197384490549fb6647e7daf5837fa7f77ff2952689a37e4a4c5395d29f394db7b55fc0e130fdd37eebcb7ffeabbc0368f2c9b8fc72d89611def52fdb5a8647f0acc6751d9e2b1af3aefa693d67c7fc9f1259d029a73538cbbde277793ed49706733d1b231a54e76d1211c2fa5db65f5344e631316fa31abaea07e8c4f051f505fdadeecf95ce60b1079a5d64487ab8463c47b058fa76a3feb4d903cbfba3b6bc0c91482e755a42d560e0684581fa6d7b008797757a4ff5de700c0470c51ad47110155c21e1d7c4aa41551b4891bc976e018e3ec8be1beff03c9a98989c6d51f06ec73e550e490513cc3ba475e5b808ac4c2574ce0f248b9bc258bde86c353508ea551eac7026786c951ea69e2343d5a454de96ccc8c7e96d73253f09e9a8ddf959e5772de801ef483024592238cdb154e7509007e1a68648833a722a6ceb6e0bbd889018857d6f6af0c7d1a2cde1c54ba9e472fa9a8244e5f063d91051d4d27816eea3cc8e3cdb00ad351eadc73bdb4bab896ad7edc463ff93c8b91f6beef5a360091323275192f3fa2fa27021178b98d046f803b152a0f5faa0d607bea116d1d29b5663f8ce1096969d421e1bc0bbba90e20f397ea1c78bac8b7852d68f6d3a784d1039dd35d084e59b611008bcc58157f604562d532851b84de4075a9c97d0b686dd60d5c4fc7028bdcead86ad2a7943762f9ca6d3d9f8b907f4cefb88a7d84774e7581104d6a7f3dcdaa6e7bbc1a8e48a1961d639a836e1f9fcdd63bd3efea99a86b4fba498084c830e57baabd4baec259e819aa895b9c59843dfad48c84b4f244bff38e8f75c8e003d6d5da6625c5a3841182aebf34dfd4b2a856bea4f0576ea611b6f67d03cb28c00668f4bb7793474af278c9da8a9ed3b25c3066291ebccffef2eb94cc89ac555b50cfaa0c2dab5bfebdec0d5b969898a4e3be29eebbacb86eb17a598f6bf2f44e66a4d8fe6d8e04fa1113b3ea548c81d9d5b62a9aa91eb8e2fbfe1aed4b77e8bb69bbca25fac666f6461703b39195be3d5cc5df6c235355bb8b602ae32866ef9b694a432e21936aee9b67f1d6005b4174ea7a0da95216abab9ee853998617e7445be507ae4bd9dc456803eb1eeb84b6e0b87085cc80b1161798d16b4767530f8fea634c9c2fda85b4f06a84b0f887779d65167d8ec158033e1391d705b140643bccde82d36eec19758f1985774c77bdbaf1b7c3ccf05f0928ca0e30e1b1873426952583acfe566df8e1eec02a653d9affbd3ac3abebe084eab149f968fd2d4b6a9cf04df4910bd51b89e0e9300ed3f301741fc1317c4c0b5e1ee413361e203d27a6aadb4f4003185d08ef1ff49bb22a48a4892447ed89939cbc0d54950d5a2d6b560ba356418b56034be5836b117619cf322d07c174bd4d2566720eb6891eeaab704c416cccead44c8369bebfd663d35981d8453518f5e80cdb19558c312b9b4de3026546ffc35a2521972e0c51a5d1e5d851aa925577c513a6fb19cd44c5061f4251229f01624d5b93db0ba4d5dfca5742b4465205a2d21b65919b88fad39309169dc4a74fd63eed5b441711b40b1f9b95f0faecf2cfc1c7834ad2eb08be8198193e4039d23c1619cd525305e2793bdeaf2464c6521cb88e497ce6cb07cf76404dc682dd14f8e8e6a0b3281930d1c49757a446f3df27a82a4627ac24283a0b3ae23d1631796d3c60e582fa890f8caa3ba255ec8398c7e5192ed07033873b5eb11934f7557b3af1da0a775fe11d5468caedd7f0aba4a32e118b41cea4989353076a3383c7d3ee14e82d2efc57c8ca2a9ad2be2c224e1dab1bbf7b664d8143d086b234e31512a69e1f871a2020e22a8237404029b60389a6c9b65645497ffa9b012ce53221b747c91ae3c553c30ef0e89198605e73d97a61a638cb2562ea1695b07d1b5cb591b7ee0f4d5fa569d4d76b391f74038c9fb32a8614f0d12685cfc5036f8a6a4bb45776c1d82901394d79db3365131e59a7c2cdbe06cdf666fbf21dc886bb3b0da52ef6685dcfdb53187d5d873700b89968d35e48b9f390342bba551c27959e750b0c0116caca2ebae99b01005935bbaf7dc6c604642a628466cd3bbaf37605eb503c5ea8bb6fe2239b96db64861cac584ed5736319e4e3bd293b2c224571a379127fb80c7e3afac7049c02d52cd18fbbce13272c383b78475840bc816380e5e768bc04c1eb0a04127c84785423fd8d98abea5b1da0fca319235ce9cb1ac44a319b9c54b49bfc67aa0fc62864fcfa42dc73884a34a76cf479fad6c96781f4b0b29a626c96ae22cf03dee4e63edceabc8ad82a23a3a48f00e22f51e74dc5f7a47d04fafc844f7170b0019c43f8fb746657192264b15082ad8a3735cf933af2b9d33d6ec7c5f41933a2f8279e50b2f4674dd2e3bf5fa6bec748ff921e4b3b8fc2d7e7689dcac7aece51686a0b2b68ed16fa567112d657575b973f4daf4d0c5c9751d86b46f3f5f77ee78243fe2f201b74341ec9e6a66e26ba532459b2595155b5b1d624579dea1532fc4350cbda2cf8f48bc668754199562211cb7755c56aad96886b603769d9f37f96b0113f275e911fbbf09dd81e3b48846da3a2d58db2d52d794f6ea4719e6d8e771b073eb1d1e83e5190f28a912b7f1973cd99d1197ca63123e091d3170fe553cfadcbd12033f0abc6a629b8d6ebca7a51b2210258c39cf59d87011b1c9b7ca63040f86b59b7bd6a366df4e2e1ec9b8a3ad51b2657f38560bc34f45e2130bcf202a919a43afa50212029ca425e1d519e8331c961c21b9c1eba8144b011c862a7b856dc9efc22582e3146eaf1778edb057de5aaad4417fb06fdc4da6faeef9b7baed277c0d38c13ab748eb8f249f0bec57dfbeec170ceaddf867b61bbedcec201aec91b4675828323cc4a1772a14a0c4b28e79c2505361f0f76114e6535884f77d1c29ac9a5a64021043e27e9fcfc181dd810944f87d888c07450c22a404fe2999a8fcb5967b2b79df69b3a3318dace16f51e0a851dd5e35b6df7cbecda38eb70c3617d2c8d0bae2e2ab50f606119e7f8a2ff7ce8ceddf540b4e05c80af8c6f3f02787d80084d5ebca04504175bba57154a37506ff524aba352e52bbb319e05baefa0b3d2ba29deb17f9e7807df4f616e851238689a8ba8cf3d5aa0b4880644da7eb05c44ac9ef77bd8509bce177ddaaade8155c9b2b6f371e7e2d7a61c8eb6e5268c714092bf7bd3b7b8cc87bc1bf87b887364a18174ef298a182631a53132018a1fe5eb474532326f2bea11cc98d86d97b0acb81bb8cf2bb8445b26bf67a91e01a732ed6f488fd5e2d9ac5111498179ea64ab848ae207a45cd1011080027e604ef8b0bee2d0cb03bd73e26c7b6277d464733e313fcc4476870203c47938d5bb7b3550bf670c517876460ca955a16a957a14438b38b370e9616079e3decf5f088af2e91c465631b05ec336cabf31f2c3d3bf567bf0b28f403b3e8b649cee798c9a5cf44bb3859fb29ddabc567de639db53dad964bdd516fea36cdc6c210e49d93b41fda191b656cce25b6222491c2a457ffcb9cf86008137ac1965a12ce564accce39ffa81022feca4a1027f8ecfb2352a09834e9baf4070ecc5a33bc1441b937ba7ae0268438053dfa47db03f39c3499ec68f1d150f0791c9ba2898897f0e82bbac463c67206c8b2119b0a59491f65e8b6d5e560e289b8978c2b44210a97cb80a37fef3a56d8ff0434812e2012cacbd3bbca04d0cb2ff4ea516d570dfa444803755e1843335212027a3f6e72deb142ae88dd51123692cbfe65ad2956f5cb6d5ead00cd48ba7c0fe720bbb5ef3bc74ead13c5f764695932e683fac4eadf4facb4765d9df4e13fb6d7221a5ef7c3c079add0e42f333d109f5044c61e56b2c7a63d69336bb50fd65d0ac8287031ef013a1d5b85e9b1b3b2c70079cd8a8709eb1c0c2d4b52136e260f649fab13af544f88cda44cb478743be187a7b9ebee2fb1f73b71803ed7d28b21386ab4cc78cf8178270be1cd2e212fc7ed1344bc4ba22b5941680e7ddec7b90674be7b8a5241b18b65c4eceea933f1a65e998db608781a7813f5092cc5bdd3deec94249c90c0c16f3ab4113c791b383907e34ff253610df409772b8e330cf8e8e2c6e7c73e6bae7c6280c543a0c38d0ce3241689f2b7e973c438313793b59ce46dc3926d4f6d234905a6bdb28ba690a00c4ea635f757a7cd14eb5e453f7cb3ebd34fc89bd2803f7c2a637079c5081d34516d2ddfbff045608f28ebe09c54ede5a9785e1d3fb1250bf630294c0cafd41c4a7c12673fbc4f65c7d173312c9b4349ff66c5b417e9f5db54b17343d33e0f0876fa4d5b5c5259811bd76f4b0ace37846b2dc9e5bf229215ecf29fcf2259c939b3db42bb3a99d810af8e05052d09a2815628efd26b508433a049a08185a3099244d6db6dce426130fa97e54d9a50e1bbef75cd96b394382b480f2374a9b68603900337f11cc77c0517d53d1336edf8a65042d41ef480bf9098cae5feb9f25a643910864154ec4900a4018e6db57393cf51df199b8dabfc1be56a6f1fbda7a47b7c5e19b7f04b5277a9e194f7fdbc52626bfbc5b29e1ed6777dd9f60da0f3f19397e29f9db93f42a7112ce5304ea82f2ce637e99681726d17907b2519622f3d570ad99a36663e5d77791ad6fb55631ed6803765dd17486aeeae2e24987c296b0e0bb7aa239fb6460b3fa44716d94ad5f867740bbe23e2f04d126ab0854578bc98a7f478d3deab11d213d39664b18a88abe9e8281cbdd357480853dc9b479e12a0877c612f140dd182332c868588d01170e23416515b42c79f0be163577557cf3d40b67cd0538155c0d1130e6d8ffe974c4c190e6c02ca2bcc807da9fc4de939af566e793cfaa9959567b3a421b2b956888d1e9cfce0d20fe51f0edda554fc63279bd27215ec141bc6b95bc854e6ef1cf0ab274657bb34f4ae1a13eac763c9dfdea57cf6a9236401b954f610b811074f1a9f206b659bbd18d11b21c7053b83fdd0a23792dd26e8c411d92d801dab308bd359444d6ca00c8aca4ad924ff2cd26e1a203450499a60383771cb53b8eac528ee439209478968d134758b669f11f8df034e7f1325ed4b7a88feb5f2dbded117c4281453e09f283a78c41cabcb83a34727cba64139d264b28075dee0331fca0193d87176ebcba918230fb3963fd2dd40b1aa9265dfec5712f0f6e841c1a4a53d3c19f81445409c74e3fc00e7e43bac8014477a52e4e4c21c5f3e94c47fffa5a58a2b1fb6ef98aa7a36ca45499d782674ad7113825249dcff8280e0f5f30165078325f2ddfe081c3eb15621c0712670792661eaceb2e0ed328d8ecd920410eeada66e9e59089b035024104d36f8ff700cf88cfe28a8c5a06518b3b14744ee6f238cbfad9e8f69204215c58b0647b349147fc446c558e5752eeed2ed94ff296dc3e82f7c67c5835fb73ee985cf40422fb292e8680faae7d08f1140286b97954b75e143497ffa61a55a7395d158230c676282010e43d91d91c636b43ebecd72370423016d834749b7abf4671f3badfe7e5157e24313dc7351024ee997b20d4b50e834f6ea00933acd6eb9120ae1926e1203451b228f87052034755dee1ecaa2458a9db8f65b6fcac261242d63bc97a7f4d5f96f5d9962a0aafb17f618bd7c093cc06ff170ad00d54598263752b80ecee5ca5f32740b066927c2a444addac31517db4c27dea848b13ddc88eed34db186df7062e15f518ea845b75d784c741fccbbdfd5c7074e0d1b19a12f0fd4400bab9a4f6cadc7c896237611ba891abe322ca6f38d933b1a4d51440e6fe40869167e69f2083727944f44a844efcc830d5f7c16dd5a07f9a3ded0e3b9daadd5bb4dabe647b44007fdf989ac751349fd52ff16d3535537cae468e5c375031c6fac619aebac51d1eac55b98479d9e848d1fe65c08103aea718d8e466975b4932bbcbc8e29e31caea36a6c561a5e3deef26bbc0ac2645de971d4ac892e3569c2acfc1dbe2daead00ff16cab7893f83c042e1a7c8739052fd15b217d93ba7f280a5b2febd218aa334d4beaf77fee76c4a76631df8498dcadb8d399fd4177acca5062aff50edb93d6c4fc21bba954611dfeed332d6b2abd1f43bd9cc6bfbd71d45ab263eea50e46a8f590b852d42df9f7b586f269941e52e695d3549182fdb3bfc070b1794362024a35fd855e5a6e86333906a601a31f549685d3b9a3f419432f10eb90da68131ae32b59ab88104b0009e5696920e17844f1f2342906e316d3430977b3a92d1da2871cd89d91a516456e4bd476a077388f6cd7e6b0dc9ef9a5086deaa64e1cc43c49d747935ebd2382ccaa0515424813e5ebd65c282835581e19506db0928586dca7abfd13737bec2dbaf45ffab5ac5ca303d17f950fe7cad4fa182274ed42a7ef42d8fd6a10157ce048fdadb8e88b45233b9e363bf269695de6fe9b835cea160081f2e5aeef8e10e91f2e43e7a0d0e8d4b49179db5dfd8a1732fbe96417a382657f75fb498f46b5a4599be4ddbc895652bf21eba652160fbac423b29af05e9f57851be5c171b234d251ce49a7fbb96db51666f4ad72b7ee794944b9848536cf30279246f6aa280a566c36fa720d33594e2f75c6f41ed1955ac812509870d7e7c696c877d1798453fa48fe3a50ce4ba4c2717fd5ff5c2f7f538001945d49a8ba387bfaa900a36547839817c77582bd4ea48443f1b7c6f731566ca3c9258a626d6fa98ea7a6e72421025208fb1f20591f3cb94ff641f33f05b571e5f077859915736d839e3978ed960bc6ca859a43528edaa9fcf26bfa2042060b059a524d60eead396977700edbf7c35f2ed6e0fe10d182d4447f98dd2733c9a59625be9719eb8b36a1dc7aec0b2368ba02e3c6f9785d22d75948f5939846d43ecaf974a4a2bb4fb1c176de0358d7298ca656c954705d761d418fb771a84d5ea0ec19ab241a357c356128c7aaeb106df94e484606f7e37375bb7bbec5ac73ad0130c640d431ca921a19e1f2c42b7275226dce8bae3b3b02f7f46efd0e129ab8803a5f3afdf28a8e2b40c214f3813106b2d7c125ac9a5256ad4788a0eec8b4afa1e3907f1cd63815c1bbc7c84d7876cd65cdc2c53387638370c1205ddb116fc8030c91e24bcabb0b497c6c73a7c66e3e87b34861c57247443b05b3b72ac06a046215bd52b30b9ee728a526efd8e2bc4704b4bfe299fc0f05e7115cb6828d0539b5d37a30773a525f6c9477dbd106144f3720e90d3065c920dba5d18030fe5235b19c919b85c5ec26ecb5617416ae6ea94905e0e2d407b3abcde58db1305621b766e24f61c4446b676a7b6536f73b57fc6e427cb09c21c1a70f29dfb316252fd9f1d77a5eac24bc34f2a0c03ff4ab0c193887bf753fbc7add255630bb4b77eb90f5a25a20a2ba31c9dfbc79d0c7a1fba2bb6011ded6db3a0c8495a82d341df0757ba83719ca6f1099b3115f62a2bf8c95eff32b9175fdb3e1208ac5137a1ee757346b5579ed2b3c65ed664ab21881775f9907a07df628439de7a2f1fb16c31c7d6cd01587b0babf4a85a46401034431ce92263e78944cfdb14454a04ba2cd581b84c238aefd96817c964932260fb5e070110ddd298bc207ccedcf187209b187e7e34c2566e8d2887004e59b26978499d585d63eefa4aea4c2bc353b6a8447341b787b538776e770df799236c4de88cf313954eb1efeaa61f075b7fbb63a09e966c29c2717d244856071f65c02cd909ff7321a9288884fc76e9b2b7474eba5b6156ba4aae3f1b91f8fbf4acca9e0a19a731be67d154108cbb9ad284e9525ac4791d35b239a18e9e7b863a8b8044f5d2fe4c45583a64ade6e26a71c7b969e27686048ee06b7bbf4860a4c17de1b52ef2e436cb238fea116f5ac6d85ae8892d261030278290d0d7fe7a133d222f7bae163c3196252870434f3839aa58a47cbe64468c28ceda0b5dc7e659c194cf18f8ced5307d8df34f3cbee6748c42dc7ed15c828bdb8404ff0a4173767e41a1ed7fbf98321f8b610c5c416a8e17cd39625f0bfe7b83b7586b46b8fbda3b5ddb7336f75850dfae494146332b4cf0d455a039308e5d2ae51292892f7b84adadd676eefa61ec6e4216750e16c97a83d66a50f40666b50c492a1eee08a2f013c1c5508530b6ce5d10b1f6ae27bfc7d704fc352c5b04c22ee318232af599d5736595f3f1f8ddaa7e37cd873eccba0ea7930565a5c15d4e3a7d47290821e4a4abd6834ef5b6e2aae609bbb9773f4aaace6f69ecc05afaa42a560a6316c62a156a4d4bafd7ceffc0be1e92e375d416ae3fcd915c7959acc179f7f272faa4b4b90b0328a2260cebcd0ef081153f6b9dda5121250d1e8d40797d0b8d2d33841fa6d8cff17316ced36639f6cb154dc94346baa0b50bc340d01db145df2035a813d654fd430d05a94b13261b930d7ed69d25bcf31aea3005cce0e166dcc1c5a18c95135dfb7d485e86e76b87c7516ecdb5d321da49d55e0df408fdaa3ed1d6536367fe01a2638226bdbb210d3b05c481eaac745e3955bd144349878414344441dd49a9de2c8603d5558ec334469f5c33b098b7c1320554171f27ca80fb35b0efbe726b403a31ea2e3ddd0bd7d9e50e734eff3a6197437de100a27db33e2cc76ea3dba65791da54b04d0692518c18a99f222d88502388029dfa59225b49f27606c3e8252eedb8da3f9fc49f3f940000ea77369b4911f72fda427e3d824aea29d8580b8b9a9cb7357408357e7a51a4b85bc2cd6f5a209713aade5e6b9d167771f9d9de0a4781b1c88dbb22a1632b2434d0d38d8b91a16ce79bde3743f7ab161ab2e7430efb9542ae9b73e6c720ff96643d55f5b96ecc8f187b8f4cca2efec8eb7197d4297f5c1c7f91f658148cece0ea3f83f1db5a10d87ecd75d1daa21d7c2a8be3be9226a9f3e61eab307e17c32d56b018804fa744db5322d8f2f4272c2f4b99143c6be793d2d3616dd9843937dc79621027e84bd2ab5969847256c39c7a381fe95c8490184c3a5d2f66c587b04fadf4c978dca9512bbe644130bb29a2cb2ebe32a85ba5f28183044676863f0b9c12634fa12d4616f91bf3858a51d3d47d72811a48c38b01f49359b0462d935970a98b467487ef29da483154408a2ed92765aa5b74ea7bfdcac0f1fa1300c9dbdae7596ec5ea51dab9f8f8568f0bbc04492a3a7cfa856e0e96e4a5dd548d3ff486d6cc4e2b7e0a6c487777012ebd2b017bfea9163cbf949dd677e7074850fd2128e51a73adc77b083124b61a1add56803a450e0d2093c932c859e3025175c8d9fc8d523fb08377c37457b8a9f08c04a44a9316c22e5630fbb11234e293c019a99edf9281e6dae056256b281f5db212ba6cca1c951d13c9f326fbb60e98e0ddbf23bca5b9c418004581dda66b189b8a73128b0a5985d2dfcea2b2378ee0e2426c5613d83d848b75479fbf985e2ac3c172e57bf43b9f737e7883056546c040e977af934dab30bd25856b4d76c478ca98b39cc291b323fadb153b9872617df9bcb0a332ea64be062120f0cfd8783dc38343d982583ab909d92ac345f9488155c9ac5761643cd68a4a59ecf23f5aea1f1cc39edeb9c62c66bee50a83b74d8d4bbe7763c09165b1baf33131fc1d81e7c9e78cd2443b165f2629b31ad4a4a8f5b4c9d29c1a8c430850ce00db18b23745b4bf1f47a7db5820bb32f191199225fc4ef5fdffb6b94935ce1526a5e74ea33b90c4aedfbf2a22277b16b4c8015984c71997034df0506652fe19796029494e1da743a7fd0c8256398413bbc1962f2240edfd122fff0efa0b023646342136c9a8759a29d434a0ff3475a584f51e36c84bf12a21fbe1afa5d0c024837077f1187632e94081f7d21b3e94c33a723a7b0a81685e8e83c7acde315a665b9999607890a0be11cf65587e51b2b355c62b066dccb2ba703641e6827f37a87f7aace70b962bf5e1f3b38165b96264aab533bb0706847198656516f46475064cd3246ee6b27b58f781ab1a13d9d960c3685b86b35de00b0cb90e3355a49c81c027174a2663c8df8d85809f1038cd18dc1db8cd24cd5e2e57e9080679e6dc0fff4af953951071585657e97da3a09579f93be1d4f6030e150a5197791710e00fdce968b10b33f0feddb1c85231f7d15222dc1e9249b2d44518fabf26bad3056cf2d6f9610db438b514caf513d925bf4a003bdd7258771fcd07ce1bd1dc436c96aadc9c253ea64e949aea7719590325a1f8c23430796bcc0422c72aa9e54040ff4ef5df32811c822fb48b6dc7100ee2c4ca055fb3cbf49fb3a279434f506ad6e55df3a3f13b78516f13322b4f6ae83eed94e7d","isRememberEnabled":false,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"d1de734591b73fa6b2fb8b47b277d5f5"};

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
