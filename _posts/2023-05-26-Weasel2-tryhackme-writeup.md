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
                background: #E8E8E9;
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
                background: #E8E8E9;
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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"d982a163c6fb836a38fcad2fb9129829a5e6f79d86e55dbef8ba24d4cf62f12ed8fc407a53e855d05ecbf770ed626b88789122eb55f306672c6e7fbd5e6272c0845778a7ad9588641ab63ef1924d6a2f6bb5f17c076e4ce8d77154f1dc4365cd43e741b8c0f8e059b98f3f37e350d5b136e263ba0facf7cb817509fa5614f727ad19d5062f7c0609b3aa4b63dcab451bd9d2df4eac1d7b639265568e0dea25f7b396f0982bd7195e1568c4c52e0bf0860c04fd89aee2933bbde22daa2aee9e99027f14013b85a55e0d55d44b7a13c9055ad031d61ba0239725cedcf3a15f5692c2740f7458402e2e08c0f96e0cc28fe4873cfe5653963a64929c169c58881af71eca803de72ce0a06be30592cef4eda73a1d375e079416f17da0303f2f7c21097ef04a6bc7e8c4ce6ee784b42c7050d4996317e619240349fdb77f5222d1153e500c7d6d455c938306368dfdcf58ac8eea1ab77088e11dc82bdc365afd34e1b867dd81bfa033d6a5a9c3bee09bc018db2c9f546db40dbd1bb01d0e8472280b826f4498ec5ba8da3b726a0a978c69b7e1d996a84f78a6cfd01cd2a9f85029c679ce8058bd3132a530d730ecbe7f96cf4b868ac42c0b1591e34be4674ff561e08eac4800db83d4371a4cd94779b92c157739142a93b246bfbb25184b9db3a139033928650bc8577375443a5b707f7066050b1b0803b4a2a30c2c6f2e5d6bb59bd4de337135079bdc8626b6d268788b42082787afdb04219d183236b004c00dea613ede853abfdf6ce38a3f83e1eb227c963be35541123372a1f92c626cb92752e41b063241d79ba4c5a9b88e5106b10e353e828ca8bea023f2bb7f34416fb2a73f06ba169cf50f70f36aab85a8fcc3e8c3041ca24b8387a53697a5a03abf27b3b9367cb96fc3a9d1de184b8b48de7ceab6f0871ca0d08e2ea1c70f0fa7656404adc445fccf26a76be8c18a4aee5edd34d60c199b67bd1b084eb0bcddcac586aeadf8fa43b3a50c51a0be324012c6b96841113b3774b9f4ced0f835686fb164ed1082f423df356827d2cfa6ddf28fe05d027f73240117b8c60c2e032854795601b6d705fb58eee8c7e0c4eaa46f9b0cd5eb099edeb3eab5ec2c4fb026c5980b83080af0383e0152273b29a927973d4019f596bcc20a556481577676ee3287e484b0246bafd6dee4e506f11682fc2c882ca25537dbf8ab4a470c2d0af442fbcc9cdd990af59e78711ef0cc59dd2cce89da6781a0174cbc342640139649f877083f9e421e790896ab0f83719ce2493b29106f21b887164a4b11f812c872888ffcb37ccd3c0f45d0d0195773da44d8fdad8d86d455d5a60599b19a8c4d8890c0466d773d738886748680ecfe552c501857d4cd51a00910a467200dfb4bb00300c9ed330506b2502e115cbf06a3eabb454b5ecb1be251e0a309b49c919085a65f85cb3c2d53f3196dd8cc9b3ed1b144f02ea6e01f9393b81d0af67cc79a30b76f35eaed06456be73e5ce74ecfe4e530f46bd3e84e4c68a213682df28be23a20b52699c28d41dcde4f8921b1c1ba307a9d84eb059f8ca472126c45a4edf72c613549090dd349b8082b0de956831337cf760fe42a70845f298e8356f662058e268c0c8664239ecae75c23491d1d8b9040c8483796bd549200fff74caff4a98cd5eed535b6eefdf76f385d94719aa25899d3352c2f3a624bd227c5a91b07c32e247913d98fff1af976c98e529bda713e87ff37df166364124637a10967e32dc689ed09937eb47f9ab054b1cfa79cd630a32369b7270b7712b7f427f04074d47e3df66ac3d5c1aa8c0d6744da5265842d246ca4b34b5f6631549501db07514699255592ea3a1db91df1c63f6152db0a7e6494ab553dd12b19ccbedca73e8c4862bcbf7ab8eab4ff8e4d16f0c1a92c2656b1e176950bf72584bbfa93e911a6c32c6e110d5ba8d6665d8ed0051ee686033a959be8bee580b4b3731f352426c1021441e4f6011af4751639c0a50ae1a11e1c04c9f05b738815db1d3bc6dcc16e3ff81faa5d61b90755551f3b4563a4d6574188752c34e90d55b55e7f4384cb1f7e99119bae6a08a867b8220971d2ca5e878eb6033c6696183aa8e2670f80c8c09ff82bdb688478adecd764503022c8251bef4ad281fc384454dbddeb47346c3935827020816e8a4207ce888aa146dd3be520df092ca8c20c75617e0f8bb09c1121112612bb91039632c0fe0110ba475898b6c84c82f26b0f70ac41b7c53d9878ff94c8a88743cf2f136857868288d24cf821f7b23819565ebbc5fe552d0149fa880284743528c5f4214bad737c0b8c837ed110c0c1f6111a41f9a873362d0dd82314054bd208f4b69e549c231273008e2a811eb346f24687a4beb22ba29f66b5fdc940399b392bbc087604950da1ac843469bedec687852139d92ff3302fc4ed696e0880b00e1733310375d3320e6e9ce0cce3c2819a2e7a516802ae4e4b245627cabd4d8715eb47e215ec55e375521356334d896577c028255b13639e39189429ccca8120d77ba18198b8ef52e74a4f87146e1ce1ed2613eab7c5d3d6a25af8c5a855a46f9057a274855af7edc64b77051ee2df752901352d4af7ee2e4a46bd5582d5fd66b711754adc387a99a42bd62b2fc8452618745f729b067df0b434f198e374a44d53fcdbc0dc4da06a3d68585ef075a75909a2216a99d7419d2b5111a0291272d483bf2d34f2f060560636773ba413c161691399f15974bea284d511bf741473fbebc40382b00b4706c2d54e77fd1adc7897a97c4fc1dcbe99acf6a8496388a0f2d77b5bd87d4b7a8bffa895780597e4907e2722680e9a481396f0b5ff2d876e3b2d7f85e119b1e455a91a4bbd15a21ab7367cbdb6401917ef5647441289998af44c61c2c1beedca71d966c1a393144dcbe72c6c75079f76ece507fd2bba949d52445b981036cbcb8e89bfb2bb002748d99f966ee1ee29ce492813adb8149d7030336939bdf05a2911e47f8f28f4fe4365868c3b5c28d449f203a0a3db5cc3bfac5dfa9b52a07bd532ba4ee770e8ef48fb6cb597d70705bb8b3065e716ae88d3e0d4b797fd8cf730d8dcb54deae0158dd70cdd72c78513d8fa556feb8a59659417ad226b1621c1d4ccd772930e89323f2846a6ebde39b484608864877f07ce95a9585eafa511d3328eaf987e1a6f09e3ca3945084e822ae8ea99d57175665b0d609141232d12d2694214ce04d8abb19e68d9dfee6d385efd4692b9a859254900a6ea956d3f48a83d3a11b582ad98643992f2b13b366d6a5a325d57574907049032f3768fec20cdaa9a35d3c01c66831206d7e668ca42521b983537277a1c30819d8f5274774d93b84cfb93c7e0f200b60afba5314bfa67fa6f5a15614e56ebbe13e5b42718392fe3bb15d2484044b0502625c1512ce6900f44022e5b58dfab2edbd0c76912814d13f5995fa61742f4977a7f9aee69b8c10d7cba4e5d40dd008239dce849feccbb7be599ca6f6f82a4b310582aee78928de31aedd452de9232fdfe719ca6c7f4fbe7296a78cf57f2895acf2368fbd84c53f03f99d8d1fafbfb26610aaa9eb58366870cb2a025f8127c9feb383fda00f0799fbb97edf22643ff68630532668d414daf949359eee5ae3001eefc02b84561e500b941af5a9a5479df62ddbe495520a8ce995af882d5d2bac1072b8ca1ff2f1b18b6c2f2617ee2284386f19fd30b2564e0414dd0c870cd4767f7438075a9211924eb0d8741f625ce2005f4b5c4b19ee3b87ea38637939c1a7f3efd4c1727b096cc4e6c699f930d09fdacf10dd9de3a94e63c841a0957dabea3a15ab06a82d2a17adb0ae754c60166d672b1187e2f14faa9923546e318fd17fcc41e3553622e2f32ae49810c32c22fad9111e3137a3b7fb6df384b4d4a2381c9bf0637486f4145c7e7a9cac0398a0f7dbd295b7bfdde10965f3a4090fa36dd671833415cad4ebc93e1059cbddeff8041d84f1ee5472ec7e2f37bc29a62315d08b10c770a07f8cfcf39ffb2b1cb542273c1a37ae735d67adc6b686f31c9f4668a516118922f6b460a4f92e186c361c33225bfaf8dbcb5e5857bac19260df1fdbd9fde831cb92a384f694dfa3acc47a61be52bd10e535b829fd83674fc753143257a4ae6468129e194e808508b216440ff2f113c8b73a4eaefec1ea1142847736ec8f98a31f3eaf0b85691b61f7a358367fafeb2f099378da74e51caf9463b11b58ad00cb10e63a667775f36ef77d85d12db13968a28b902eacb1a7879790283676dbc03d3077c68d27f372c41d521d35dcad057c7459757c3fd1bbbce5e0e153333517492ed9b6f87fa5e6660d76083183b8030cf09dd4e16ee5ff6694d35380818b2711bc68a3cd48bc7a9a71e764b639de40f4c15fd032a94b9f8d28a911fe882475811f0bfb05cef6951980271c326820ae5be45a668642dd10eefaa0079505622903aa20ea3daeb727acc038c8f115485b94bcb8d144410d1419615d632c7a417fde840ee47cb83f89d6f8378e5be7ae603414e8c53e50a79497e945c80229df875fa01618938baa946ac7773c5afbf636ba1069a9dab0f447a250d1372f3c2c0c14239d399d64fab19f15071b69e87363b1a7ccb3f58fcd7a70a9f704fb3fd01e70785a90535b38d16e381d74e9dce5f5cdb5b7b083c93953332e4dc5ebe49755b129c0cc9a7cbb75b58ab5a8038b46abadcd912fc59b4b51d90ab9486e3f8024c87a80bd37dd1fd15822668df9cf47d087455dba71521945abcf18ddd190bcd01b420b7452ce5a3b05efc806632ef00ab23d9e9c3823215b1e5a4c485d9ff3723ca79acfd00ead3381a6cef1e4e9e5c341d954bde9927040df7a7b46714bc64b5032f0af7525c3451f8e211ca2858409e61e276763c916934e929ad9038b36b6f993bca389a04ab087264c3d25fb501f808f67b7828eefc556cd5f4ee73cc47c460977f1a594d086dabd7e9e3789710272fb842d552c22943ff91314ddf068668c31939480cec5296fe9a9ab9866f3eb4ed3376dc5b7dcfa2bbfa282771ae88e1d5cfd3b60540f23bad9f2dd0de27e91b4fd0dfba9a4a15be90caaaa5a85da71e3db3292ce9b78a73196194724918788d773cb91492c865fbe45cef71a410adcef97133e0cd70bc0b98fe77c5539b841fcbfb9e495f75f50ba0f53f01fcbbcb9960173c3fa22e6489bae5d7a2b85d79a860ee8dee942da2cc2588d7e582acf288039beced81f3b6f932c219a469c1dbbd8160a3fd066f1bf101a69632fed0a409c21b4f3984dc7bbc451485a7b4e333f595c5066d6bb94eba84bbfd410e5382c1f7d4dad52ff80315fca09465d35b8b4645c1864bb7b99d52f7fa67e8fb32e220d0d193efb5ba07ee066f62ac8742d442b8ce693857056ccdb233e26b3f1ec3017f907693f9365a34f486e88c6b3a82eee9cc7f4ec85cd574145fccbcdb598c6a5c84a7bd9138c1c212880b18dcd2d0c9886b70ee5e777e6bc22b5aae763f6d7236d493ad23c346ef0e87d284ea71a8e29a4f648b854bd2c2626f07eb58d5a7fd5acae84c5acd686288e8ab0c3c60226a1560eeae683e92066eee14016447aa76974f2f5c6290a9108c9d766b1833046e1263469de2aded1ae5a7c6a82230e652800d57ae5fd535df7424cfe026c9da34a338fe923367370da84114f4836ecafc397133e710aea35f8984e47ace8a4995f3056ada7b0a754159c2f3c99fae49d7e1b16cccbc0f207c2d4207628c888e69a403fee44d5358c3f467d05e93f94256101f7107338bb4efdd9e13fa36860d90207d05dad6a169c628e28df9b6be81e8b8c8cb7f7efb3721b39c7bf52af4e2db4823e4dde966f6d00bf802edb31ca1d3712fe31bd13090620bf19846627209b7e3a6da382ff75f643ba72f07b048e1b256052187f60f787ff7fe5f82ad2a4c84b7fd545d5796e2addf05528a6010189dc4f60cd98ff762e350c2b9278024bea0fead5e7eac3f29a0736029dc7e8a6b97136b81bed21a652e412d3cf0f2940dfa5bd75b7c3a616c059c990428365edc2195d66bda9e96bbcf73fa485c955cd1dd55beeccc8e5a80f77bdfe2a41f8ad8684ed4258aae55ed9ed2b8313f2e01b4d13431ba0a79cada297036b90d8616fdcb6b991f75869bdb72e35b0ed7512c81785fcc0578f9ed14e0988a00b258e7081624ed0544db870e50f3e643f42d085564e03fff58d33e4645f7bc81d1b5cfbf576354bb1033453295c8c303d0370be75e60d2cddf0e517c7c1570c6be4081cc2e1bc56e311a73cba1a2a49e12383683b64217cf3529aaafd51bd7523d7ccd764a02bcd7ef53aff23d4ba1b5ffdf7f190996cc31b3a3f3a9808aed7cef355a355f092853296546e3001f725cfe116226551ad87c1587b7365f249aa3ecefacd45c9870d7f94399d0c86f936c2b95963a5e322e9bdc28bccd7b23391cd7b100e1734c990d68226f3a410a7e8e64977867d47b168f7cd50ca147afd6dd08bb0c164eb8f58a3d5775f51b220083e3fbc694f46c4586e5b017e5d1b4c41c6ab261ce341436130f75b1ae70cbe7b98ce1110666ea02c657f9df4ca186a0bb44b67c5876408d916302ac8f30bbad28e3a4848bda74e66eeda1faf4ce58df416b4eea999f7eb3148b20226a1ca18f00040a16334b3fe598f9611283775711379b660b9acb99a52e503f7aae22ee99044cf2e3ba928170293e3fb6bc3673cef2608b85ba75bcf7b605c6fa0e5b50286e9e495fd0783e40ffaa6e4ece4a18e5d793da1e9ab9633f6b513dc43ada68f4222abf3c1ad6c0382e2882c48671e573a14f3b3c072022a0f73b90b629341de6d7347243cf7b48c9c9a9b4a4ad43e6df6f2b9612871536153f9217327c79845e027a4882ec353e89600cb7d572ff7860311042e718aa1af0c0294aae6ad1d73037f142bb46276612ca772202b26a3e6216834facdcf43bdd2eb657e1f550b4fb789087338da9a5e444dc1ad5200bfb572db101487db5f359efc1cd52ec7729fefb9920385438e886da5cf2511c282d122f1f39f2f8b94fb0e6af3c7859c9e5b36d57b2dc4656f1b693c1f3de07e1cdab80bd9d7cd215e6b80029218dac20b1efe92fb8d8a936a60c2a5056495af29220d67937949431590ab832adcbc8ac6f8acca5f6c0fe175a287b543b5dd90776b892fe1b24c3f8648739451a14b384698c41e0debf2960a33554894746357305c4911859e55bdfc585e367761e5d80048443fcbe079de5a184fbe429d06a5e06aab2fdaf4909e74bc0fffab870c9713173a3fb4105cd7150ced3f289aec4b05e5c521b9921bc0256c946d8105108733abb0301cccf67d849e605b9c2d1dcbfd115b22e4efa078d5e2629c3508e01c791d3d022f485ebae6ab144162ea364cc59f1b523c2c6d98f67f5ee54b49039d86d7a1fc1253fb43c64b55db72dbfd5bd0ef18c3232ecd706b796386a1d353b1669c822c5ef88c9c902ccd023d189bf0a9101aa8fee564b9ab6c0b9cf908c312b46e015da40ae9560b370137dbaf7d914c1cb1c94454505ca959232ce6799109faea6ec0e7c26983d154095f45b39a3072e03b80c8750ade364a22387b902b1331694169eacb2603c959972fb7eb646319ed7fbc94d07e7487c3e5511441ab1b9a2cad1582c81e6d22697d0cfd5f62714ed83e581d094ee8ad250efa7adcfc24809e34743def9079bf5c901bf29850ca2a0a77727f0e3a7a61dacb119def6e04399d5872ec127f7216f6de97910e7f55e166777ae97ce8978eee4fbd9d01e0b940a761a243f2f669896bf2cc0eb62eb4e6fbfbf3cd18f0609e009f068d67800372f6d871cddf3b69dcb1cf89a8fd79d3f79983daa785169cfa807ba1cd50af9bf632999a6b944852b3336c73d3e88388a206cc7e0103747f4faef99a3dcedd4931486a4f25a9d44c29b9f94d24203cdf5e5c48b4b96f319cb70b22b541f4c948dca0f81da4eea132c80309c7c4e8abf9941964b1f08e37b3336ee0f3e063a2976e39adc2fd3461ce3f8aee5b8483973c01a85fbffca43f3d47d08b7eb6fc3fdf31a311b784584ada476089419580d634f11c85b784a9d57e38dc416d26108710aff503d92c3e19bf5f8ed236c70bc49077534d5da120e9d30dcfee264c4edf66e2a66b26ae02397752da770533baf3d16b316d917101aeb15446960732d07239d5276679e8957bec9dfd408f2542de097ca76032fff642c56062b823867105bd1f4783eb64e70da8922c1ebf23d8bf4ddb120f172b2796d8778188fb0986f6b28da7f700ebb532f4e200eeee3ba18d34b031d57fc0b6b300b783d34ee565738c7c3b29f0d11ce067884da94b9bcc6767ac9bf7f8cca7a2b40bef383d95c982d2d725e577eefa22364ed42ec96fe4ebb0524e850f8c0a025377131b0ef5bbab0295a051ae927b3b6c12175d7a5fae431f80752d6c36fdce066f8cd83e505afeaef108b46e587619a7ed262bf90d3b28a63784ba9510c1bdf2fbd9077e708d7ad31f055da97f5db834516a55a3c255c82e3d41cd2509999ac21f58f96993fddc0473413098dbb91e768e4a736c5cdce2acf59a46baa6434574623640157da870d4675cf9e507bdb62aa62aedc57039337cf24607f24b4202f3d9f92a19ab081c8f7f099bd7ed7f7bc94564e4ae768ed28bdfb2b90620f2febc51b0eae0f3a70346b20b30c83d2c7fa119829053a6931a2a01d5af764c7a3902bfe36d87cf3c249edc2b98758f19b08f2584a6ec2946b270a5728b0507cf7cf5ce38dc4ac265ed63cd555fb217c039d872efcd5b6ff882c58db05ea23b89bb60427b6804c3f90324044d849bfc54a9f1d8ddf2ca1f45da73265195087ec9232b2e114bdfa41e8cb5c7d86938ec62b8bf18d983aa1af6b6da4b7d13b2db31cc0cab2406345c1c39b9344042758fe50e8dd844e4402c54c16b52c5db539f3133e1e3cf19070ced9a8c73e22afa0f1626421b138ea64035912c02a52dc69cf368a6467268fd2562f722a056c065c3977420eabc9c3232c64ace4e4e8c3f9ce43dc73b9b6fab30313a47c6185ea8ea26db519aaa23ad481c624e2cff5357fe4c34216927bee4b587a3dc2aeeca71b9e9e17c542a70ee985803bbb75877c66e06ceb708b6de4413d7df6bddd7e9d67afb9ca8c32999889778090825d702ba2be4b09dd2b5cd80ea66de467cd0708991c2e87626a95e923d288c47190640350251b4511a747343f5e34849757eb81d3e7d19f6975e7dcf6619868f17f27e38ae5a4423cb858af48415816d958cb6ca15ba4498115978ec33cde85f9b63f95b0c6c2f9334a9f855c7a7c4d7c648bbf31a2ad922e95b46aeca820b095b62d26dcb573013a3c7379eec0e2b9f30aac191104391e8f192de594b9be0106711447343ead0cb8965c731f25e6aa7370db25121c7f655917e534ce4ac630c1eece72ffe78e8b8f0921880825c47ce96e3d6ffd7742546b740f7b4afc68c8b85e8f59655cd2101ffecdd80052213c7d5dcc6b9c98801dcedcd0aa0b43c630f1fcfc5804ca530eaffa4988405a357a5d5006acc73936a1697f08e6e5a063d7509aac75c7220db5cf908eace68641c689731f677372973e6795143963d000305f4a53053075e400821961af25b3b888905e00f4e9857aa07411e8fa2196cfcdcc9b0c69b91dbdc966831ee026e24922c1cec8572c12694f1b890a3fdf20b645271b65a52ebcd66ed149b606e4ba387cd6e104a50a97c792fa7cad8aa1007ae3dc6f566289ed11f45a2263c3ee9b98e90b85f6332337257063038feaf5efec503ae28396bce3edcbee5a619d0f74768bb64fbb2d9aa60cfc330b689805725b68b6bec14f109e308837ec899e08644bcb12d4f669ebe68a0beb948beb2ca86684ad368d05a028c8a79500b06c99ecd5f2442b986d558f2d70046d0e120c13a52120cb714cc1aacf256fe77e415a99c20f09a14a49ccd6faf9659528a93fe8b5cc3e262f5b8ce2cfd0975c2cfc0411c87999f274ef78620f098bc484374e631021355cb5db86295a34932c65c90796b2dad323c8892ac87ca6ea02f493e36671ce3e0a80dc9950d033a8a005a8fd125cb841100ab38bbe28695f9707c2abc1aad92ce1e6d90e9add9d8e3c7bfc9e9f1089ca2b51154a5860f194da846d7e1fdd2e97dd25e2591bf04eb4262881c759cebcd28621c0030ab787ae703568a2983a6db91387f788e176cd6724b9a2ea65be1024b760d94c0ca99ecd7aab0324eed4df10aacf3c6beedfd5915234dc065b26f7f016fea8e527563873fc302996342c8e0ee2d3bd8b53ec78886cb0461d1a7df6e5fc9543c73562f6d61a67d641c75146788c73716f7a77190137a32934a27a184f7b9ca893afd6e6f60ba7c92ca8ec41c650d7a23542ebadd33b5d6fc9a83d8dc8023d2e3ac17a68ea6b9dbb283ee7d355cbdd981aaca6c78c068fac324fca60c100349b01fefddcb935fb4c43d53369531611f98e6f2304a29687e519e37a43c75bbddb4075dcb23799e2dad7e3269450db107ae2807e9a31b3fd823bdeaab573d24715ea269c80a3cef7ce78f97b1e72df8409bc109690e451085b0cd5746422554ba367b9fbd43cb39710c2b9ecb5ac12a843bcaccbcc971faa4a2e5f498f84ee172c10cf8342f5ce774056557ae3e883aafd0bfe10d9f43f131bb51f8d475143af6cdc58ab95cac3f439a8909340b5dd7c9bb6f2f3038d8dbf181e217cc9fae7183700a4694fa6cf6be96585f747da72c56c8efe4bdcd98449c43658f22799960963456425b3060593be7ee6fba64fc3ab216dd55f38404e1153850db3955304690390a862225d4f9e6cbdb2a81e5c1a93ae8d6ce20e6f85ccc511e8bd4c44a3729414a62063bfc0af5306ca8636a12f56ed97b4a3423b5f7d733d12beee2dc4da517eec414b722f8ec80c5d68c550fdd1635ad3329da5511f276affe8228ea8ba9caee64432b2ddaf814876458f9e5a524c1d40e5ed993ea477060e959948a05383c91f0c1c74c5f826f6c1e66ba81858e87e6e97279806e17f10625f445a929700c399719cd67dc8063340e118d92b18df3bc8ae42174d9384e70e04542c64e70bf54671ff1fa47d1b7873a063e67951dc8d80816f330b1f4eb29c5cf7d9b63e8553f991b44d116494a9fa61fb363280eb05faefd02266ae90825af633006558ed5bf1d6f2501b49f7c1bf8f1616d7903d42546d10a1ed4f83a41e41e58cb232d3b9f8c071bb38c89b48372eb0d7edbe918027071e0e5000639c311fb1d6d0a0444c4234c8e9b6d9b536cb3c21712584f5d2f9336c7acdb8af8d31e51f48e1e348c6b7a2753c45a28a6a09e3b3805e55897de0e59d22f3a7ae563f8bfa57735ea581ddaa5c85fd4cba5f0d220e828141debe45a32f27c1f3f4c9da8c8540fdf89bb9854808fe17eb741935eac9b431b7ab23377ec4c56af366b070b06273fb4efe1c95d17437c2367dd881b6ba8e16ba2d01e3b33e2eb2f3e5527e7689f3632ab5b5655a60fd1144542e9c7c4b9a33fd195d489129e17ef0d19e38e79dee5b5e09850b893e9f3d213432b84b0509ae85d4f20c8c00887b6de810e1ff988ef4e943eb881bccbc85e541b94e15efa1f3a02e47535111321604442807b9ce8126ead0201454f355df5c0e0bc13572549c61e3dcb5d0dda83e8649b7e11d867f08b8b4d463a8d8792b4ef7b4afbaa309c235b123f673d65aef7780e65937fd630bcaaaed750e597428fd0a1696ceaa3d377acd29a1ba0a439fe38f3c2ff64cf699c78062d6eb85422f33492d72bb3c2cf1c5d522389a33fcf48e0f842c35ea414d6d117b473f020570a9bbccfd073247a9e58909bb39db6c5a7fb7698950de0ad9a172c03a6641621512ae1fe02ba81afef259967da6ab7628630d1b02a2120d98cc56f546c0bc7bd0eb7ee9a7e46f0ddbc4114989cb36dc9700990e42949608b531f534c6e7b22f2b40f7ddadc19517b341d0f0ebab5f22fe86ca0cc21951061b8003a062c34af2b83c6021c3ba84bf3ef6e0f2a62b7d0527b8291c03f472af1acf9d3ba1aca4ea447c073bde3e657bca8580dc2db6ae4ec5036c54f8a0574dfd51cf19c9ef442a6ad71e62c8a2fdd9cb7b98a3b1257c1524f27a7f0f8f04559e21d4b45b27a1a831e69645b7896e7806dc97290dbd35eb2d848f3e47cca6051b99daaac60abf93af7b9232e86392b241a8dc2e59d1c4b7e62216191158f3778b0bb3ac13586193aeaa2c21843b641fadaa651f26daecb2dc3d74a89406b23eb6add2ffaccd5a400f306096c568cc0dac6eab4b2b552c4d3579c202ea623cebb917d07ea2b1f17d1b1f4f308f376c1e059d7a41b5daee2806e22a2d8b05c48f10ed40bea0b2b855a99d74a200270b671cde78ac0ef05f1a44446f0455226e257cedcd61ea170c1586e791c67996760b6071ab4646ae0f13e88d9d6ffea7150599763075893a9010908737025ae5a31bf1a8cc2bf590932f08f26e9d353686d1273583ad1c16e65b60b779441b9070d98cda21a121e9c65b3ef647374416f7c35e4117be9785f6b8153888b46202e5f07d25100cb82b9e415898b8db5cc68837c84a4f9e5b378f11fbded68dab69ea3e0d56a29cf32c82443fa19ed73175e40a97e36f9944325cf135c2e1876cda70e5595887dcdc566af2a45c6876d26ea7fd60d580067909723c610965bd12bc2bbb4a2788b4c58bb485a2fb446afaf30fe5c3d61b942ecc524e38acc9a14fa9eccc6906b52773383b3b8e94cf2434f1a4a50b9d6dff7b44113e662b5ff02abb69b17486cf6f016b9ca62a35c59ef2e3c2eae4f048246b8e3d5fe190edd31f893a1388706f5ca7913b98b7fca090fb1b6e0fc17fb2db4e034cacd89dfdaeff367943c3eac4de7d68e839ddb4bbc9299fedc5e52eb9665e87ccd0915de44ecf0aac68033312b2b6ce3603bf5fc25a6cca30c36de6ea0254e2472373be08b5f666e903a46ac61f3dcc78db748b689fee5e62b129fd769defdb0f63372979abf7607ede096e071f0c61245c821f98fb18c4e80dc7d7c9f74a8e14097f3d03b62b04d68633b678a2615277973dbd0b5cf170e759c414ee2c2e300f855487c1f6b1859c146d465ef9dfde3c74302e276d4ed647d4e7623f68e77e96cb3cdd7a1223cd6c756934ad60fdc2bfe49c5b91d8b4ab0b5e5ec7a0c0825a4201bcbf1c7e0e1bee98032d5a24899e37b444631a80dfe62d89022a25f4d2a511664c3663020fea540fa3199da4e91bccf8c0e69e38db59e8f88d202b0600fdd2f7b7f491ccb436d2de5de4a5d232a7327c1725df73efdb5d6accefb237506d6c076baef2a7d2aeb0e5d6aca91e26a6c77840b487dbeebb1c922c045e20aa76c6c65112eeb935f2e02ed543b605d63b24a845977a2154338bbe6a0796f25dc488e5d2def2ba16dfe4f01131838679e1af86ed15c427b2f8d30f6d3542c05ae2cf5b32886563365cc725852fb72aaade06787ca926b1dcf64ab2c7119f8394c10a0728e997e2f36d113ea26123029764e60ca5a40a374f87f208bc2e599c8305203eee79264c2b1fda6683029c9585c8c9fc0fd3def1a6d94a836f26118628d597b5f2a0c049c19195b3563cbf75b0ad57822f4614dbdf651514952fe8abf891775d7b26c8ce74b2af7eafaf71cbdeb5406ea70295843e2e2071c8a07bb8758ed69e357ba0ca7db96696a6ac2b4add4ad6766f0a39bb45c8a6f846f224f2ccf71008b8b55730fb6de19e746a4164a256c47b6b7d217d0f65bf85bc593f28d8b8008c7b6aed84f9ba004fc6dd23029e4f2f62b9b2b11438c0109f5d71652f86611ee2cd984b4571bc228d991d2758a1de9870a7ca92acf208b48fe7f04a9013c9d707e627ac7965032d5092f17bb0af1776a52a1867e069b22575a255f609b674adb5cfa71de55409217ceea8f126845fa96f237224ffd557557fde5a1ac3d06220fcef808fe460d6251fd41d8b80d7c124b948be81275452a29cbfcda9d9dc9a8e34891b273a6c138d033bad88ada5511c93047d531063f81df3373da2aae83285b7d99d6090cf8a3d1a9e0c2f9858e0938cdf6eed9cf6222149bbfac7a1d664e8a1be9106478854c9791e714d10952072af588ab58fccee70df2d7c6de035f544472a833ad2c4a3df173e31d933a8653b47f3a5d69dac2860fc6e1baae7d82b5ca586a0269b73bbe8cfd2ba6bf1b5e888d53be4b0971a485fcbb0422297d45ed2c98ab945e995e2e02822aa1866604292c95f48d0fa985e7cd9aa5fa6a5147a77e1d620bd9e148e26e0b5263f1168599cf9358de62c0359d40da1fc98c216f81668c949b060bca4ed13d62bdfb5f68914d23eb0aaf880bf35668958ea193636742b825a45d313fe9b375ca915f849ba11e9514ca0297504f100b22d391723574059893389350b6823087bac9d0187b98b8e91fedc80d7c3e914c358634cee6f8925c0d857b082bdddc9bb78216dfa10efcb39cb91083769a6e22ca0578adf822ed51059a86a06c70c3481de91996e1550c42ccb159190c021a3290903be0fa196912c5cff12186d7c87690722f4e69f00d7ac9ebedcab9424dafd5d48f0c587a6dba5abc42ae89619ac9fa5455f68eaccd7da0b544dcd1b2b417da1a40d78859a4febce579073694d1d88f32323fb247505b6cd4e1f243c8bbf23971c42643da33e348ad3cc48d3d83d0fc847bd076ba18c6d951318435ced9e05c5721e371a3387dbacb8dda1e9ecb2c588c7087f97d00d42a15d666cf26aa83053f30a2d1782cc905e617adfd95cd6e29836e1d7bba9bd8f05b8119ea5b63d222356220992b76ebbef3229f6cecefd3e60738618cebfceefdbf1e78cfe93cafa40bb74b0bf7b490ed1213a16eab390d055b86661b84323f21ff37b8cb773ff930b7da697283e8341f76b050851b193b9fddb37145fb4174f2ced023cc21614a102198e49198a43f936f2e0fcce93a46cdfae132b290c204f7b7f920280f781c0866f16f2f8e4fda49ba21bc1658ef21d80a09d8f32d26628d931a83115331971f845d3493a9944810bfe7601c3b34f74894a7f4332e32448f3c51579249b27ede3976535ed9c9881a33d62fd6c7c4655e1da7c8cef9fb32f953ba6eabab293c57bf5275529a23bdf6131187421f5117f430abb7c2e628cb8a2df87b5bd23d6e270b7841f4c6d0e4569f93038c013b05448ceba9e3728968e7fb7d67320c1c6725b9b933734e9bd6faf7d89820daa1e73c656598facce0aab325b9e027f7c60320868b0d7e51e7979d941063ccb9f9cd1a6671bd0d678f7f03906b71a7335984a426a750ef6343c26bacf0d12a8c4e5a60348acdb04ddaea77920649e16362d350195c53af8add6d46d39fc5146806ff9445297bb93cfebf49d9bee87d5641b4d7c2c3fd327d619e3bc759689d0b79d7da805b13ccd195592deb6dade6ea45eac29be85c1158e6df1872c8b0d8a96b5390b7dfe156521f36b3069570c569e1a76ca1c3ef113ad8bad9e839f8d08e84e4259587fec79159f2722c32a2e6cbcf55e41ed9c5998b5d64c6592c72acc37b0b36b2860c5a012bd686378877508737666979b04a7c42a5deae9381e551c97ce28497c4101d9ea2e9460cce63a810723df51535cf7b898c94cac7df11b3df782b4e3ee1df01d8a0bfcd21dad159cdc9352879fbe3455a169681a9c477933b6261ddeb6cc5cb006086ee41e324d387271f4adeddd25d93021fe214ea4982d92c738dff824dd1a4505c5822628043ea09ecd98c8b7846d2033278eb34a2b4488aed2ba031d82bff6a2034565e999e376e0c0051acadf92bd82bbf8f9f57245f28cee5dd02fb46f8e892763a1802b0a0c8ae15692601ea776576260232aecf2b8ce180d9342b1be0652008043fd04f55f2dd4f7d0e49d0a577edc2465d6a1ea5969d7a70e78063775acb791f5cf55173e882a93ca5469d2662930c467b1757eada96b62440a9aa4b01942aa7085e30a1c2ed2a5478184a33ea1ef03f050f35a0faeb1c8adfdbc465a0bd3bd21e83e2bfa3318944d4da3c6a8fd4c1b5c6299c05af9f599664003c6671d1f5d1cffa852e392e479240f5c76771cb2cca73fb88f004ad3b56b876bf069f4ca5e41969d11f6f149a8299426b42ab68033f1777c6147c0299709ece3cf844fa9c17ca45beef3735aee9eb7e871bdf8b13a80e5bc9f5163c9cb527a71de4a3c021183e4c21134d92aad6a168ae444d5589e868a150f1beb930de8fa537518a57199059a9714327775082cc9b3440ce1b986422705d047e5c4b476a37d5fb6d711091e6d61e7499c8155f42f2e8d0b6e066b7175d8cbe929962b56e6b0c58e18725149573bdd7452bd62a15d0ffb07e4c8671cd7c807db6a60c3d8eb64d01ee863baf7671d197dad05d13278c3666091ed2f14e1f524b5e82a324849ae34925b62f51a1ea3d74a48ae047bf0dd30d5156d06c5e30902ea215a2d92c76ee8fdc570c8f1002e6b4803fb92649a318dc0921cb1014d555fdd762ea5928ac4b1462103e7d1490533f0051b7bf445c4c6017563d2f0789eee6f1f4a9ade321138a20f93978164ce114433839d211d64351332ee867017edde68bbe02a59e43b3e7977667ed5caf879e8aff74bd8df63a595ce0e72ea0f5d9828a160e2cae4c33e39e34b51f34265baae2b7f472d7a596a01b96466c61ca5f10785a96f110d3c7ec5bd30a36d2a357c0ae2eb31cecc68961b669ec3b7c08d016e7fdf589238dbb77a88d8e715bc263d2632ce7c6c47e2b8ecf9e37134524033128cbf5177181ea50dd3064fff75277b3fb03a046adfc25805e304e419dcc647145666da299bca9224a025a2bdfe44010231e69e9c1a114cdbc94d173f69027d67ba64bf1083e4e82ad5babe17a16ca959fb0c29b50b6aa70bdaa4b204d0c8bdef9333497308490947139ea2a91c3047676ae2adfd0771d46113a666147453b19e489a5744d61b4a6e2588241188ff43975c76a6132221a8a6768c325c88c989827ca47f18e13bbecaaa76b4256f4db4037b9d2d68a350876e2e58806b6a593cd2c5ff215e441874f13e84f4dbf659583f5655629b518ed4b9162aa3bfd517797eb145e084c0206d9891d0f52e6eabc44802c18bf670e34bf41603ca2f1e4946e76d5b44c14b2af00f3c7adb5db943a0d025ff0972ed354e13a6c93b8326d6c9cced44d91010a064b79440b4df72d577a29a144a197303fb6d44689c0737e10b827d3e27c65c97b7947e9e1d1200b571954553672426810aebdad484b617d0512b506526b18239326ef90c91e8a725ecf75d34af701ae803c2ee006615149afd977f5406427a479a293f9a563b406debc5ebb3021ee0bd876d41d94ee8a33b49d27711440a3f8a2a4cbc7486e17a392a2b8390b5a6787b5094006a90fe00fed8a9b821ef22087f0afac536e23217975e64a796f853d16203293a72561dfa6e71a5b8493ffb1b2206d287c70dcae7fcc5305b0299427683b90c42313bfaf0dfb425b9a6f6f0d768b53d8d9a7b9a96c5a85324d7bee311877e19a8c54707303903649f14445d8dde9bc10a7cabcc5de02812a2fe227927e097b14b30774954ee749c100924af6b6abaac82b6db44973be1470c30a890e4d3acd2dd1cb2dd5c7edfdfc9681056a487da715065949bdffe01429daef2568a8c7d179cc0cef755aa8c34b8c24e7bee1b5e8208741914be3f7e3a5bfc466f71cb9beb8fb2b2725e7fbfffe66c96c4b5afc098e2f2d2ce9460c019f8819d3b08ebc3bb8ecda470a0b7f3e2228d17d2ad4f54600f696831c4826a2c7e95bbbfb60a6a8a0af7fedd95777801a56889c89284574afb7e4f610437b66a6d31fa0caa3396045df352146088629f4df6d712bbe9f32178af2e9be6cf8d40864ceebcdbd6a9bdbaf583f13ad76a3113ee8e4720502852a90abd73eda927f7d17e856f2dd655412493f45b5f15206e704a564e95e25303bc229d1773a193da1d45c271b235a2b9087b26eb0e1d8eee2572503c7b26b1e57cd789e6398bc6ba7485ee607366ceff5ec5a18472d0aaad66e57dba7598c6ef68bdb13de6fc85a8fb14003078467247a19bec69bd91763e4b27eb6db996ce72e23e8ce4f58f7193877c3d6ea24032cf6e8e5a7c5620b374be2ffdf179f106a3d476ece09f5952101f6e2e47b99b14b80d563cd9f8dac359c88871f79c7320f89f8df9d1c41210995965b607f6e5a9d9bcc3bb0a0fe36e8c85d732b514907c0f54d90d2f8441a4ddea8f60d0540a656d15744826ed1eb9309ee5945532b202f9f7e5b0ce4297ed3828fb93f7f1d28ae5beb9fc6fb644e8fe199ab8597c304c6d47023cfe831d24c0cece09f27be482d5b4fee24e8bfa38731398cf21b2968965dcfd5b30e91af27a6eacc7adc20812629590d3d0fa8cdb740dbaaeaa9d16809ed64a0f647f0cbd9b80371180d5915b75cfb857ee1051dfcac80f8d2eeb484de96a8d9a399fef168b8a0600ee29ef6896b7d67a449274c1c9bf6634a39ee1fb32a3d6a817a18c5b578001168d72f5af687d13d0c091a15a48b4eafb76eca7f98e3f1694acd45cb8f29ce008af1e51211278455af781afe71f329e7b96a58dd7dd46014ae8cd18fd1a8fa942e44f9ca573e27575685f8513053d000698d508f5a5f16fbc26a792995be6d5a731b1f1a33807b22104009ef91734c94e3253c554e4d4363f55f36b2d8bcf435cbeb9350a1b5dbb58919fc60daf84576e449f5aab2bd69ea0a3a04a77de63d9a227c381accec92a6dccc1057aaceeb6c331a2228190ff02ce44c8527d829097188794473919c8a218e8118f3c0a175bca7277998ef19e0d4a4d160c96b2dc574c503cc2b5cdb34973db25b157ec3636aada609a6930a935b914f780ebe5636ce1622bfac0921b2a31f9f6a18ea5bdb118b0269a08ea1bc44c1a0f02bf9d281dd8c3ad735b9f83fe9b325350ef14cf1df03aac125370696772fa03294a584321f97534cf6be15bdc12f251445589b819462bdac993f5cf07ee0e8e74d0c12f598fdc02726c81c37e593aaafe7255e987e5f152e05b4a191c4a0d130381c5d0e7b702c16f281809efddbf69d209b4bf1b70069b8e0f10eac07eeb741374eb80b06db180a29a1875588ef6e8cf6066939076005388142ff998f80118938945653500586703bfd7ca33ade0898674607b75a8f0618ee7fd2520cd16142f3cfb6eb71554377ecf730f465d2344cc2988d23565c5693a1b4b844fda958450abaee03c370208dfecb6e6ac5430e8163c9ddbe853ec5a427b01083bf7413d471b68617f9a39f2a00859b3fc703764def0491595c32fb5941edbd937541a331884371313475221ba3ccefad5d9a3cc16e09f8c514dfd4c2da943854545bef4e389b88bf46c3a622064c7fd46a4090722364f24dd32bb2447ff19707eac84a331b6ed4b0f6052e4f0a39c08fba3f332dd0576205e80849970b1bb5476976910939d93bed5d704307db2cd9cf300e01b3be97f63b9498c79db49e85611251ff71c38b7a02d7df82c28ae21f9cb339f973c8bd97f881231aecf4ed91cb0b83c285296637f21990b0e36b4719217a6126b88ae73afb6e4b7760e258db08633990c0886cbf347b8e1ae0616cee203c195e99ae3cd1378e872ac83ddffb648a02584f7a2cf3c806b15c3f488d8ccccccf86c085c85b45fdec8678a4174a051052d163695c3305553d34d68fc78c6b2fd82d5ee83e692382bea686dad6266843cdc6b0b03ba5dbb4503093de182febaa0b4f0a2404a56e870c1ce078179d6783f8608923bb813924da3a604d25813141d809c99ef628837a0a5a72e64cf1c76f231ebde9c44c767779a2b3b5f966a31c99926b53dff1d8a4a22b4283fa61a79624d6b1090ebbcc8bfdababee5d1b6b27461673b3c5791a18a0dba9a1f1723d20699fd2dc4879d922f9a064c3d18620c0cbe7164e2aa54b6dff3701168041a8ff251bc2df99705bfadaf2555f55ebe02feb9cff3a0748a4d54b3802ce9b5d0c173511f338752a42dbd72c51b0f4f053201bb0bfbe0738df1ffef2c8959359cc60d622cd722aace0eb17f4e90e5080512a65b2ec6d9fef8b74737429f826ca809cb4f984b132595c6bb650bacf9eb00782ce837ceb102d566acc5f70ceddc3f86dd320dc3cd009e805735192947621e4eb0844918b2232b61b9dcf1f4afc581f5d2310b5f90822f573add09f88408cfa1d7b9baad3ef30078b5419894e4e6b71e9a25b98cde37099e9a6e81265f9da5e29167f120626edad4618fb3ede7958370e38e1ca66d7e296a7b4218af92c503fa54ec3ec9de593d259e298469be1edbdb420394cf50032ec073ffaef5a60b3df127ecf31c21270637bf45b879632cc2e6b693c61d522f49f707cbbe3f6989b71d756e7dbbc39f44737f809b0fd6ad82757e3853b09141bae5ce42a00f5b84e1857a0de72bb17c456d820902cfb703c74717a471bdb2ee56ee70250e6dff3ef5f79ca05182d321cd5834f49baee94c0379dc157de6b4393bb30a17b739638000de08af62a79c3fb9d7408b8038482016080d166b17ab39de5dd9bb9dafb2c3eb1d7464f29c664f9a049c4c12881f61ba20eb63d9b8ce4233cea792a33e2f42eff946fda3dc64aa2b88c0fd5443f2365a3740ddf6f28dff7b0b127b9a5d99bd506f1a26dcbe601c6cd0559fec71f3491854f716d1d26e4ff73358b911075ac9a5a1746788045d0535b0c29b9dbf524671d9ffc98d428d5bbe57e4afa340c7737e297a0713663fb9958e30b4999830d8cdac47ee10d455642217cf0d6969574d40a0e96fb7648724d876b3b0b54d89eb42988ea15cd9331f3ced73e0683b9deef5ad53d3410173bfe085ff53c6997b6e4ec176d08f2ef05c3ad1903deff828444286ecc4e2770655812e0502a8d76e8cca02d1a873c7dd7b48be8fd31db8a446508a595f85317edf4fb6abbb6903a32b00b73cc39d3c2785f717e5ef51a6b86950944aef3fc70170c1bb99ec2476ef6edd998e4bf21ca354ae8bf3c58a56cc0444056642ba566ce729836345e5f6ce57545cc8341d34202f56bd1a25aa23c76e5c9bb9c54263039dca8dc53eb93d9f0fcaf0cc6506c035f3a83f4365ec8624122dd35193a3f32ddfd86cce66a8643454c1c49e0d9d1cac5e85fcf5653b812bc31731d74f04be205cf63d25af85f4f9e7fde9756d28e9d8f03f1592ae2519d23da77f9dab68026f1326d51e8da1608511d6997884237b41966afc06c38bd822079e83af134c2da9fae85e18b275d1fa3b81db13f3492e7e56c9307eaa6122f2d0dc5450fa0e0a97c82cd1f5a5ccc71d46074a8d8c7ed89b21652d21f3b49ac23fa3e23439de9bccf4d426eca11567744c53d28ba7022ca2c4fc8e5e2cc8f2d778f9edfa2896d72f71798fc162cd56db6fae32256818e96057d1c64a3541178f57ed23591b92044671278e9af5bbf63337ca8e0792438df61a451c73787f0899f5aa43ca8e9addf99c1ee36cc5891cbd679acc5eda8a4f32dd39fc1dfce7c205208f0aa3b8c079bff563ae9b657231e2ef79a06de559b3f32a0cc2a4e8e6b1de8ab225feaaa844e860af003ed24f7320004167dead1e74ade69c4c1823a1b4e594246fd1f647be34f955db77d22bd983fdf90a0caaafa6b646587fb16b04dab5c2ed3a4c4953f88ca61f08645340cdf0a3a3418b890ce1b9d991f5d0e6ef149c1c945239856899cb9e7db31f3fecf6b43dd9e8a6b796931d94d5aa079c44e8328bbe1b5a77ba5e9803187faf5b014bb1a1cee76ce9d7a7e2178aada1090054c3de6b3bacb3d6e6cd5c34f1d331a2b1cfa3685909a6a989d088414b9cab5a7c4961c10e110adf9be508d5021558b2f57f966b45f1ed6b1ba3c357f5888d751fe09ceedb20daab030cc182aba0de494973f15fc2ea82e3be17598c27ececb1e8c9ad824380951e5e9bc79cd409ecc1c5c340df461a5d93bb0f0cc78bb377c27bd0f5474bc93ff5337fd8136331f600b8a1d7408375de669f9dc6c96cc690ce84b1c41acaf91c162451753d23a86382c1d35e7f79d9cc47f1e5ec9f8fef4775d20cfecdf215dbeddee3f4c4f9973c25280c5486e155c4a09a74ac387f3634394a271e3da79a7685823eea8e19560c19222d37adc98d39d9cc551dc7e73467e44ac82cfaf185aef82518bd824673d17d547580bd9707feafe5f52abcb00523f99707d46e12a24f90ec4b15159ee192585055fea8d4b64abf77938ea9ab3c6133558a9b8c1b81cd82fa43ae111fd89a2c530faa6fbc6304eea486dea625a3d04a6aa4ac1f9e4cf8216c0bbdc2bdc93094eb49741b1c13d09b5e35266893cf45dba8f7fb78fe5d9039c6f565379789b31784697c6f0c249c32a8de1476f4983c1c1b88b4a93ee8d39808e261b82b513fe5add43eac601e4742e36cceeb60ac26a4707242de42f0b74d2d1a9255f53077f936e644ea17ffe5ef9cf2a96ea4bc0dd37027655f5bbed3eb62b754de3c6fd3cb32e68bfdb7bd4db5f9f30ed9326de4e76089371889bb9bdf73745e7c5ebd200dbefb7ece001904871973c3448cd5d52f476dd1b92a469bd0a1c27cb910b26efdb413be53cad79ed2eaa63223f5aad30a9d3c2c16ad45a64d8b76b40ac61d1f46ff32cf02d6788e783f0a8d98f3e4e2ba0446fe5baa16bab0ce1172a35812a951f0a641aacd80fd7391df06124ba60f0da93dc218a889a9025e1bd8fd124edb697d375aac6f0970d8793941fe1035d7dd6e295109d7a05d3d47d14381a14f5dfff97d11ebadfa16c4bc1ac52a2fd4446ee69f73664c50ea12780806f421275a07b0c4ee8eb05d7b421d80d3f5a715382aab5054912e606d386f74e5f948cb62da02b4fef3666fdb5820af7949adfca2bdec1fc8dbf1b72aaa642838278df5cf5816c63f94cd43774bf4da2f57fbb326dd055ec930ae4ce64539de0ee19d9f3221e5e8559f1f9bc1fb53f77db81430e5d690dd5c1abc6c967207c960be59bd84bc068dd5196272497ad06461856a75d11a523201c869641137418cd2b6c791fe3db29e0a0c010481832fb57e16d01c24a4d3235ee96c7dd215fe3bfcbcf5cdf8d4b1add34e3931fe878d8f61afda6d301aa11fd1bafcc79f4aec72da7ec6c0e0858c188caf62fb6105ce97ac7d610a25434d95db7cbea9d42428ecb512245777eb6688a66214b5cbf1671733ece27c2d7c6f69e9076d93684f1ba42c3ac99b803dc654e3f6330349c6c9b4191de7fde98670425683e62890f9bf1d0b23df53979aed77cad60090d829c89a4a48f19183a1472ac71e4d89f7d5d9809a4720d4b163b1470a030e46c09a254b6d59acb1a806771431db2abfe8912ee19bd36881aa5a9fe8a3da0021e2b39166c5422968d2b03f034be4a31c0f3dd0b612be56dc0b208ff76c99e1ececafbf9a7380547123e698dfb3f2e01d7a41f98f4d2b2a17b70dc5bebaf124723f9e932d95396880ae69244b28ffcaf36c5b38ad365d5db31be224f55201ea9444afaa3756d4dff786275cd22612d06cd9c99fb7bd01c88c9079a968b19031ca465d99a693f7ba28cedb4f286fbfdb549403142242131e11f8f28b431020c3c4fcf4804bf0a76bbbed55fc73b5f738a31bb14489b53cee3077d679aae3c70867f44bcdfd2a8ef1e228dd5c240524e9ace781b80080a77f1954214b00129d9890f0d344c7ffb071266c870d85127b5fab76bd1b3cf989f71768bd75685a069dcf77631fc04e618325d5f1da8d8ada50d5235e83f25f4a0dab8c0de80dc577fdc048f103ab8ceb5fb3b68154480b91314ec88aff91f493684ba331f50f148b62233c7645e189708c884e03b9efb2a2b9aa424066ff0e9514eb92dbfbb71f054c2b4e06629d25fbec372d4e2823e79827e9a1df7583f02246f6abeada4d00265f759fa24a6ac03d3adcdc087cfa06015365fe5e5397b71f24fd4acf0b17c511cdf291ab35aea856b6d71a803e5a363015f97429ba1cc430dc1c316bc74de39b5335e984c9e4ec85c30f163a44c8c1fa170840ef272e9e31a2d6bc1e4145e872f54f8c436d16ec4a610d4c640677af24cfb393d88ad13154c7f3ab6345771134c105245c5569f1d97570a1cfbc3e76d5442071a7fa3276cc2691f7b0d069617574c618dc766c0cfbd2b83e14c56f6ed2d5ebe104278326b03363274080f54499f711cbbd18e2b0c84cea3993a5fde04dcc1d93787bdf692aa413029987ca2acb936a3dad36b49868c616054d6d74196ac7124e7bbeadfd0f57df22d4010772378e1f99b93c12af795b401e32e278eff8","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"4efbc568565cda9a7680b66b715c2b13"};

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
