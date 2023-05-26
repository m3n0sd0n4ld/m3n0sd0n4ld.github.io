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
                background: #FFFFFF;
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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"5b96d2bc67b0280e2ecac715fc9d656241eda40e6f48eea9240d69794a46175d47c62cc6fdc749fd6c72d3439e27e0d994ac00c0656df7c398276ede580ca8db23c59e1e8d24a583af5cd6e2ae87ee29e1831f7a3efa669cc41c6bd7313279f34a19d3b58f916257b256f3c5fc1e708d569035ac59fbf58a6ece32ebe361f6377e043af172ab1533d6c9948afb7fed17f367160c567922ee4628a60a728229616dfe6daa0a14ad19e4978099a0e1878393b57a330121a8446459529ab3066e939ca5fe7ab1e758deeb8fb8d3900a41662607fa61ec60f41c8ad310781a7c4cd956621d148b7cc834a9a11d3486937dd743d9653df46d6f4ede333c26a1dfd5405219d006442393bb2b42f90bbfae7a7fa78842b5ae3909450d738979d2e8524bdd4b943ae29beec2c0930b51c82e1ef33331f072eb9171d46b0a102a3d2a7663c72e94ab4bf687bd5eb8203d4f064189204e2f3bad906d11b2381f94854917b63e03f9bdd8a720ab48a66fc8e616da3983254758dca3551e0475c115e36238129063c47fec72bbb9953a0d85b92cdce974ad7b3f9814733cf4dd73a7eb65c8b9aed25bd29043b5c183826a18b78381a6434897e8d647656a483755603c4826f26161c6029927b44c47f82020f3aec6b1e54b66ec75a2fc8938d4ef8994cf6920cf0d544f0185b06ed5e8a71539d1b528ea25b6ec4b767ffce319fb231187e0124f0e794bfae2ba12753f88869c8f9cfa7bc30bf85e8624df818c8c867164f58914a621d1d61c77c3d74a894886dceacf92d7067399344a45c0126098a4cd5b8ac8b1257123a85dde9d7b337680b54493badb17aa87439a14465191b218c4eab5866b3a7df35f062562620645801bf22b17abb2db7ab0f18e9b2c06d90635bf6179f5f88a4caf865b5c745706b36db829d20e30703d40f1d0194586847c1a49b5dc7e4149a1479293c573e945c7ce926d95ceda9390b718bd23668bb8c3c43bcc08eab5d02c84f51841fbff49234203bbecb6be5b27c18bdb58d63e2e428643426e39214c225cc264aa0e4f98d63aafff6ceaea36a992ac4d7db3f1d669e367f1d03fae64819ae5d75225b3fe71e72fe48519fa14670e3d770c0303d4d54dec66b10649a02f3f2140973f051557cfdc79d5b29031ef2a27b3f9ea3f16d1063c7714216306692a5558064b2f743dbf607456756ae3a6d7a479255945b95662c7f48e03b8154b3a5a4b231fd7fc69dbdb894cf84fff6888d4dfa53a434b000e06e183e2c82d54fe963b0c9c7f3e47c900754b6242c67065e11d45d5b3737d988e5e702c86502c3d693a49c14b1aa8883fc92d2bfc5b2cb6497aec6f5b2eec69772075ad3955c75f98eacad1379ac30b4878f215432d591ba38cfe7c2e0c88522664149fd889495187c129434aa164e768e2b6dfeeedaed8289478a2c8138fab4af2da17018d5ada8530eff76b24233e56653a4b0d2b91275cd67b0ae235f491fa560d6af35b60c6960eac2171007678c459586abe92e82b093c4177f9f6bc3da81311e91dee3db3447a5b498838ef52a5b6987529a63aeed508d5817be8886e21362faa6dd14013f5a04d37306259de20e2b5732a25e917db8c9904f312f961fe3cce3a28df4f5ae6cfb4d5db40c3183e87f6015f2ad97ce54ad5d80e385716b15f9d0ceadaa3294315fc314366e1fe7c8dda6b19685814f2616fb921c9f5117a9147ce9c6a3edec8a5a79ce7cb967b8e2d2c1c4d71d0fb2f781cd5dd922485eeb3ad9fc36727e99da0e1ba1e554009d5a7b0c6122e8944e53b5b29803432dbcc8a686b19c062577f8f4e26daf9446acc90c973b8e6124de2ce947b5f738e70dc04caa61172d034682a273f96dbc4e0a24836f46ff433f1328c09376f28cbd65ad14acf0fbf3ff7b9a1d625313fdd63dfddeccf144b4e5a1875cb63494bc7c33de7d3876a31fa1efd64c2a7a37a21ceeb8a4b0f9f1b24e617647f3f68e257571fbec9debfb611d1538a597e97cc941cb0d17ffe457eb71d979681e5f0fb8527a4d67f752b75894a77130240ce2dbfdc581e64212a7a449cefe834f6e171553a6543dfb0273af5cd3af6cfe87890e65aacc8bf37df4f809e80329b5d7808defae49086b289a5f9619e2cecac3d8daca8125d4391816a564f78bba344d375d7fb961c89ae20efa0a52aac0a204d1f382e9c95293e38af53ecc6f05171b7a52fd9e6259fb349cb6d8e2b9412b6adfd3d8454988292e5925ad4102c05c9beb2c660aac16bea5569795684bc76ff74ba15189e326982963a202ceff3613e3531dbae61ec3b5bf38e7c461074323e44c451671cfab84c0786be62d6b4d9d47ef3d6eeac17335729461cf1c4df7987b7176632a4f1b3cb95eadb3ed2017c5d9a19d54a9e8e58beea19d60463572e8a942272af992edd3b0b4737f3de2135cb7f8b11f24c3b743669be4093f9e6359caf97aaf2eb5e895af3815481dc81e80372c4d99d9c079ac3dbf1ddb1204b55b4e7cd265d5e7140c44d0ece51387a30d61cf7bb67a10a02e9947e411ab2a2444db31e723bf8fae50d7fac4e22a0a3d0a9804b7c4528e10a1c0a51354ed4b9d6ed91e759055ac6ed8088fdb26d0b2087b521d0177bd988cbc4423b5d814ebd868e9bfa9d364cb494ea744bc44ad99e8d9275cee8d4623eadddd348f7d2b524b8df9fbe74255d5cfa428a2657ed1f0fc5fc5b16bf5d8c4d7fdbef178cb3672543c3bb375efb812d8cf4661374eb172e7b0fae3018ea67f05a610bba7c3fa7150428038a3824d1d09091a5796a8d96b7eff2cc7cda3753cc9ebbb548479767453b645a8fcc3ab696e545135beac50d4af6737954d42a59423c9cad74a5366beebb488910bf72a07261a9414a04885e5873137ac1f8b80b47e6c06e814d0de3f040af216fb6424a90f4f5d2fc4ebee48065a356004b906af920ec57fb18919ce86be7049408d035dcbca5943b3fbdab1bea2a3e91c563090d4137c7eed9244875164c73c39dc3ee4fe05913e4f13cdfda8c20e5a5a673a5a4a4e22257410436a52e7bf76d6668c2105849253428989bdd2db4598151874e354f6e3403bc08f403dc1aacc1875c5f1bb199c4506c500fc329b61e3fe1e81866b28b51b10a45ba9bf86d8bf1e2ba6074b9b72b9e3298f06d2817886ce9305cbc022a2c52d6f537d30bb2a5d46d68c426651ac2e4d2bee5958489ce149e372d9cb8d7823260199309019e2d2f10b0cdd12b01adc873f64747ff1f1e878dffce172e46859e951c809dff3db176164463b177bc6821dcf2b82f69cc0d8126387b9455d26cd579c89ef3212f3e77ef0c1d601d3d44386cb3734fd24279fa4515c0eb03f4a4f35fbf7301b18f11236ee117b9df1c2909e1b731da73b5edd8e4fa42c5cde1f3965300868b9d3ed68ed267f4107a174739d15fe9b2a79c0ff55e34a3ef06634be1bcfff922bfcf0d5f600706c2598995853dd201da4dbee155a4f636711ce2e8d21b55ebf029d73d44f7b642cc36b3e785039fa12584fc5e0f64e587b44123dbd2e74e767efbdf7ec7e1fac30bf51dab01c8f768de5d1e2afa8601c475b053043f11b092e79c0b8925f43a0cfdc40142675df440064c050df20068d254528744b5ab1341c122e1cfc3df09e3120698fae87f6ef82c1e83ec4ebb0809ae826f591a1ba80a89cc210c8a5308c3b28538119fb5ffdce03122cf22794245e5067e7b92850cc555fdc299cd8ed3c030b5f7ca48ffc7eaf780ea86719a520fbfc9175808642ae0b9dbb416afb791bb8df37c2f7b92e7fd81a62a4a920c2eb5110a8d466c073960a6ce985ebefc9b59bcb18a451512f9fc8f5a3e22dc19d908e0840e0bbc3f9e652edd61fb1da9797c955b9760c88c1cfd1cc83f06504b8c17d80b3ca06aa2791f98958613c5c55289f0e3256d9cae60b5d26a75992974918d6eadabea9ade98fc307f96ccc5e72eb96d46d8b9dfb2b19dbb9fdb528ff1bb852b920f230b0daaecca5f285c09e6902fb04801de3ed239457fc8889a5517e390bc6550ed6db61691c974beb3093a44f2dff6efd569e0b392e8a9869752922bf0763fc0940fcc2b840260070dab768bb13f24e4426d196c87197ba9de1813decfb1d9e19edf0c3259b9c4b45cf292a1cc52e57d96e9a87589d80e8f4622498298070909616ed45784dff81dc248efaca4e19596641c38a7845216a6e8f673feb5940a3b6592fe37c724a48230ca3f96410c020024a3af40577982ab9de589da8de41058d8f338ce7c984482b2726cbc47c30e62794ba26fd38317b7af8bf42d924ba84c0e0cdaabc828a111ab51f276f8c6efa41061961f56a23125674e7e18de25e0959a43a75dd50d78815fb6b9d421a2003839db5106950cbffc0cca5f15350aa77189cfad2763106c350ebbf1ff8638b2dba15f19bd051f352187e6e482c669c4b1c6580ec26400d9756467f6e05ef472109ec95ec06eb2b292d2a7d4a9edb19b025e61708a5e0737d7156a58669ab98c86f1c8a25b78d13ad2f628e66f36e37a9a456d6de7dae9bd70ddf218f9fd1eac0a5cf8a20d6b4a7fc9b1d1f9346cdf9c1ccd8943fb87195d1f8ed9e259e7ac922c57ab40f929cef0b099f87c0b2f9dc4ae3dc2469f3f6ac531ccc30c7dcbd2f8b7a26a165b90c505a63a2b7a9c1f688ff9b7d55ced3c90c9314c9dc61f642c8680a84cd79ebf489d32a48079462985268b8c89915201d995a54f8453db952b2d24e02692c0568931ab97d37b24eff7dfc9ad60d2bd0927ba10dfa58223caa417aaaf3b64658d58365e0d4e07af19374c48f956300e45656bb7da2c36dab5bc6fb09c79a410bb96a7140c376425f16eb7c2ced3942784c877b11f35e0b68ba8f061913584d3f8bf3a4c65ae985747ac49e406ebce29b49061cc505087ba06b24c415c129c297eaae92da0a10b69dbbb26707ffbd2ed7d4aac12c520128244641180269110d3a70655fcd3af1b34398356b4b3a1a6b595325e41c540c29bc4c239c3a88cc143c8e891403961ca92804e68f1c08808de3b3a8da0284a4853337a551ad90277907c1d2509d78a1eaf052916542e560c8857fee5a6e6bd18a9b12a063179dd6b92d1d7b27ea4e02db71a559833015d606c138344715faa4a447dcbb29900e7b5bdfb2794e5a12a52b4ced375904c01b78bc3bad7dbdc7dbd82fb6c53bc21874d57f819c40075e0a098f56e0bd92c67267a70999cc9b41dd9e48b704dcd728f281295d706e84b0cedfca48eb4a680b35819e87ff8c747f77cc8da2fa3c77252cede698fc5ff791965d80a9ffba8e3b163045f27f9e86faff858364cbdb47935502f942f330c00249b80a0cdc18750f0e0818047ef027cd8590ec3e151f3d7bffe56d10626fda40961733ef853e37d80322acb7ffbfbe18b227d840b1fc4d5f5e17188809ae494e19a5e13808a70e667b63fa923111454bc6a4e1319ac2f9e9a29432c6a7b6dc6b158e36015f674000feee710c320d45a414a703a0b258c876343e98df83a2910bd9686f06a434bbf2510b1c7739088aca72a2816dd277f2d0157064936be9dce1ce01c2276404efe2f68b22005007ca459a3fc2d80491fb031975c347c755e8c6b2930ec1f9af12ad4110042999cf52ea9c701d4f289e549e2afb23e1b0da480d383ac4e90fd53d5cf85f6fe042bfd21262b68966737c9b1cf6981dad1e127f46e2bf4d8240c4ac924fb58559f3d6b565998cf5b3a3f77803154b61fdb47dab2e64a37e3bad91f4f20fd85a179d2d9f278222b395c543452e64d9fe1041fbd9b4bf1b3406caceec63f3c565091859a53f93cd1639f5b742ddc6cc58428eb0b41ca542a419e65eb31c632bafa4c4d1a21fe7f30b724847a3b4d328fbdd056322472026e14e0e742adc10eda37a006224e8debe8d0bdf4af76a62725c5a6929dc74507347ba78dbf5e54c585b0a74a7211d44b162afa7fabdc2b933901a2e376fafc355e79642d7e7363b67ca0b94655421e2a2e29c1321f80f0160b5aff32941cc404512cd6427a5621e335e272a680635cb02306208d6155ca8ae1608bf8fd073caeee0dec416078bd0c2c6acc28f9df3a565b386e0553b86414b077bb9822460cab4fae02871925293d802d0b9cc99deaceff65ef9fa6624688898d8a26f38a3d1145fed786d7781fdbb8c2ee6afdf12904f0811e2a45eaeb207876dfc2ddb25c744f2a9ee8552cd801ada80f897967cc03b0f430521856869387ca2bf0fa4ef77f7bc2b2cdcb662bd3e358343b6cb7d0d57478f965738d1a608b07c780532635685080c7aa9d83e9dab22d879154d4dc5a6cb0b67ef41d2dd4f4e13339d9686396c13dc00025be8b66b84670bb50bf5ab4ae4ff2db147a48af0f314801398bfaf4f6b26cda99e85a85ccabd539af682e59d5af34dda032f51db77d178ddecb9895d4752a6fe9c0012d9f5a17bf5eff1328f048d198dbc43fff689687525c0f037887b602eab0c2b63d3d3bb6ca34ac7ad72b41897979e58bf2c53ab0b9aece32cda748895a06211bcb16f548821ed9f70ba938eefd8cb553887e1aa1b32bac76e059c8ac87bf48ae6c7fd1bc15be78e83c59ac45f4edcb5a24a011746b3e0eb37f6a5ad6186d3b0af086700e3e7eff0192805f7dbf4223a3a80b724d1591703ef2b3dada53aa1173badfcf7df366dd23eeeb4e7c5c1c40355d68316e2a1599c2c012e3664a6cea37e78dccb6236df07d3fadb3bb2f6e705432365e7a2e24ead453ecf3bc3885602ef8e785c61c595f83bed986cc0a6a77ceb70a4371d3c4c4bfce2d670aadf9bf7ac687905118f0405546009788cad9a9479ecdc544842dafc7489e8f6efde075055610067d9bacca9f606c676517169185538d3c4257eb2573a991829f2be0b1c8d9c5d02b9c91b5b9da37295b6d46355f7fb7db02507f07b7b9ae4d5824efbbf13ac988e8d8288d6ceb6f73acd8e5f19f54a7e0518015442dfd1ba7e3cb3b467a5ab6f8ca8ce1dedb9f0ff15552053005d33c8b618053becdb4ebf2da27875848c311b144093560c01963b985f857ccee478aa6824f86a8ad8d2e26885f77f21bad5c626e35ed97e1a044e71324969bf21d1ff596d71c11bd508ebb0f2b3a24489f1d01b4e5c7c04124cc6f664e69321fa3aab85a4c81d69193b79cdd29f9e0b92bbc10b41b4e91826742c90f3f266955c9e751253614cf5fbac3ff5015cf92ade2fd8674dcbd1f98d4dbd538d950efae1850ff423392724b17a6c558deb021d98fa7da9b13cea2c68cdfbe4ad54d2f1437b8780b18ed42059310e30db9b7b511f8b81844432e456893b40e824a6619ba980496b3a3ec9cdbab8f901162821d7e716ee0bcd6285618bda744da66dcd2acf91a6105b25b85722414524c03c8128dcb0bd96c61e3408dfba3065125f5676730b64eb5e3923513ad732b2dfcd22c6746ad048755060b2439049bf1126327cecf3bf74be65f91323a13664af694a407d248234b7ae053f34c75a507eff80ce5e62d443d905159b01b250bede89adba222a4a15cf2626c046f48fc3b85fe42f07504ce40c5ce86ed1b92db43692f446ce293b8f3b8c7308fdc427ccbdfb27068a0bf8af89cf6adc2a01b0f0a1e53aed240e100b020da51205ceb261157022fc952fb90648215e98648aeb210af0ec8a33b7f379f0ce2600137af2178835d737cdf3034f4efb3dafaac349005d9f3b36ba2caa2e7d90eb902330572c3b1d1c4a2afcc9a5b8d75386358318747c509574241647ccaa44d70d7d19cc1debfcdc5a292f2d5c03db7bb61e14504b422326a52c7860cb7674d86fc06c6aa70a96b6f5714ae4a6370e39c42bddd3ee13426eeb6410c86f4b4ffd01353fc2a29b732d77d7fc07eb1f9df70b9b68d096cf35e42c09363443ea4f26fbf9711766a1c66f254438ae70b297b78b93194295afd827ba1c6aa09a9cd1848e51dda799fb10800b21c357360a5eae747cd8871e90aaa153994400cd5c3fda6054053e2bdc63545fc1ed90be7362f1759303049c534d2619fb6f17926a7b4f4bc98ccb73210c54aac47cfe03c847161d38ae6f74a7cddc84c70c88e1c5011f308fa8a55a98a75d6d995575dd8cb449cdf1d01a438d980bdb318ff0627c5e9233928ac0695814429c6bd9045cd37c512a2dd623c9b505827a98e5773a12e4f9fd54574d07ecd3ff035d3b021a5e01f617eca3efb6c93c3a23211a436bcaefffb1295dd31aab0375c49d0a5ffe5299131feef074260005db4fb586b14f0901902453416c8297d2ac28bd5142be736682e07ec342c918cfda99a7d2d1d28362a02bd799e8aa7ecaa2519d21cf12daa757719b91044f070b365f2d64af50ebefc397a8cbbc73e786c6374322942467d331854f286423aed63f9122675b09b4b081772fe1384fc7f82fd723f358712ffecb1ce017d7be7a3b134cc967b457787e1e241b8b18a5d454af9ada589e3e9cf6d80127e36cdea2b124c6d1b48c1a73d5657035eb63dd89e05ab87f2ef9396c97a48884f51ef0b0c6ed1a6c034cb12d5bcd7b99cb4ffacaf94fc266f40ef358b5d86fb8c461ce344a3f7c140fa4006736f0b3c3f087a330fb9218f55a8318e0f5c972ea906230d80c7ac994eb2467224c39229ffcbe5c97a689fdc564a843133b4e0c697fe32fafe614b6455634bc1336f75cdfaf183d72c1ebc2923d2a5e1391df299b267e2aa0ae360d12dbee54acdb7add97e46c20ae418e69dd07202dc8cb685a5e29dfe5014e2bf1d15bfd5543711bd04c0a4ff772c8678908eddd7af3b37ae737d172a73fb11b8b5228551b27f8adbd0bd0b13d33d723e3f123011d49eed219af4521c6a019fc6aa3e58e06286fb234356d28008b9f88244d2278d74a5428ea011fdfceea7c3ef47a4d168d4a17769cbd65d9e10c4cfd77cb3fd63034becda61d9f597db5df379f9bea7919740dffd181c2124491802e290dd49ef6e58f671c07ba6d1867d80bb3c09289601d5dc8288dac2174ce8647adf81fe60012c57bb70add6432846de3646c1c8d442433fe107db6f565309f7d36cb2d8e4912a6dcea2c162a41c9b6a0a899b86dacca39b1f78e7fc832c88d64c691d3dedf9d96751d918882cb821fe87e8f6ecfa57d5ee919d587c230e1c93839f0b3fb5c88aaad95050ac7c49c9c2e312f3ffb1e5b032990cba4563b5f7eaa97f04db1248747c41c2553ed6c03350237601bbec889fb562f958b9701924eb6a38aabb911974e521db26fab373e85f5a3c7814c500caab72c318d8d0ca6bacda67b3472b8c26adfd1156744e64e605b4d94085682352830463222cd32c088d0ca833316ef7351fb8a2766020bdacc705901dd1fbd853f5f348287550a2a85575421e168b5e2d1a827b1afb0c9cf45a231c2441aa96adf43bdbda8e9115f59f1f2e330ede4fb640b27739e438f576e842859595a8fc6647c591dc6f635f1b3845fac061531df216e9771ca7625dbb7528dd0783e49b2c98f5a701a8aa95bff167a212af0ee6544e3fe1f669d36b932eecb06928b5f055a36d4a668df2da3449cec7997472628db541720f4d80218c6e71047c818879888053fc770628652fb16d01f003fa48aeb3e0911db086c101623b3f45ff84d6984fc69c36de7ee48b40a8e113601c490fe4768f3c9e57033e50611f3fc7bad9aea24313377762a85bc95b4b065d0e263e10d1edf14fdc8e063d06b44da3aa004a90e219abbde3b2e8e710f40aef11077de4ffebbc7bc39741fea2b89b099e7792eca214db7c33d4602055d4fc1ccf186dd93863c51a493e0f7184262dc49f0e45b5248129e17b142f4d6d116786568679d8d7230ee7a03a99f57f5550a4c5ac9e915c8d95df70bb4f5c8ece448f8f2eb2a99d818750b3cc9ed7acab7b895528532ed0b3aad4a01a31b20e0d34561309f1fb767c88b0dcc7ae3dbf7deabab58193876caff321396976498090ab860e0380118cfc64e7568f12f3b8ccfdc4953f584bd29fe9d846c13ab4abc999768b98c7e150757215fe038d9f36f5395230422fc2d240195a7018a974adb8e5ac5a8df9bf0e02cc735e903fb9039214270b1660a86cc27120fb338e1d1c60f5363292c802992f654b97a0f7213377725eb2225a53ce9bb8c25f705c6d01448efc963c4b4b084a957bba55107382b633f7f1cc79c68d04a08ed327f106d8dbe9d83dd4d1f832cbd256e49ea66f913169a22763c42008ae17e8bc077b799d2cb6ff8b9e6d0dffd8a211f86652f7068be8c7d715ed5de70429a6315ae6afa79795063e79a69bd4647ddb907e7a7eaf94679b7d56a6dfac7c52275e5c1de9a730a020f69f1d4b96c91dacb2cc29097a7c328545c8d786b6d2761b19c3ac308992542d9f930ef3a595483bde3e28330981c5e2728c5ba67e1b45aedf71d2576f6ba523850945355885133afe8ca8e4095ef5a97ffd1100b939da3d5cc0867ff2d925dd7ee359f1272c633b3e7f745d77c89c74150de6753693fa5fc29663f1afcd6eaaa3c0dbeaca9c51ec61abb11fba2c1b56c1c183d186906250ce7b36bcda8ab55343e3676583d42500f8cdb94a743be0c23ca384dc3b2a29aba63b31a2aa225e7c1413b5c26b5dd23007a12fbcf0f981aa6511ab62e8273f4cbbe3d18856152b60291f98960e7b6becfbdf3bbb1d0bad39607668986526c86975ded0fccc2b30d31ed078de8c8aacacca82343fc7d13919e591189314c063a1ae62b2efd9128ba921770010cb9d37aeb40fb7061146c3b79062764c44d8ce84960ed107ecb1e290229dc636ffa9ac4160da7b87435628d613e804e34817509d5b1b630c7a7910be02d9daa4b372f18084ee50ec09072541893235da5309a1888f4488492f4ae9cb7685da551a73404f98f121c725f94565822e14059b391fcfdb1674046b25564731df678483097564fb0c94eec090e9afdfa7f93d5484d6af037b268546dd8b45b9e0358e5dd27ba2cc73a9f1b9264f0b7ff998c456c72ef946f1914465108309bc9ca802141f2c39dac9fb9a5f1ef309d9b63a25e98541b8e0c44fa621d2631c4be731e2668b985b659a0af62672ec1e9227b927c89d1d15a679f3c2b5ca687e9ae0d83a0658aa02a29cd77f77f67ca64b18324c8e48e687d43e3a628b9dee4417739c873956c91bb578d5deb4e181a06963e639159352f05cff07be2464ee9d0308b0a05f352de010c3e4292f0c6199efc4cf0f5a9c35077c05b0be15586196f2e271d753d21ece2297badaa955ddd0b85cc8360e409d529f865e91a2488a637437cbd1c16ade0bae166486497ecf135c7a960c8ead8e6a69f4f70be37590a1f7cbad1fc007073d483d674f615f2801ccb010a20f78feb65acbc5a655d935f892978c697bdcb4b97eedd0fd3bc046349213f0095c7c871ca2bc87628b273335b03d2d0085de102a893cf235ef53188a316959268b4f29657b9812a35e50e9aabad2556a9726a3848993b4fc85da7123519716de53a76eb8c76efde2a4ab527e4f2fd0a3ca7beb713f278582a9cf91c4ea6a4ad19ea3f6919ebb14ef89a8ac981f60ec8c5df911ad6e6db174935eaa0700988cb98d7bc72485d6f96117624dcf25991598560d54395b5dfed67ea5c2b32169f0e8ee005390cee1719b156376d1111b13f5c9567b0b528c7d4142b57d134df4e67d97c09138b6b0792dd11f016830811429b6ddb8c51d3c4dd8e15b58c958041c1439e02b7947e9c0cab3607c0f3959e6bc749c081ae431419dbef5153f935670126e986a765efdf4a65410a0dca2296abf432f3fe6ddf949c1f95e392213e8272c50f3103386c43fc23b9f3cdb05aa224f4a67254cba4e63cb73c94c64c0f0e13344303b4c23345b400e362be7c4bf37dcc7a54ab24783150e8a501161d41734c7bce01b1f2d8f85858872588a9f9eb7115f6a3946e89e6140d41ee2e6df626bfa9ad86c24514cf24df46a8c149bf19003b82a4766bcbe134f5ad65dd3889f3076469f849315a7e72a0994af4de4220e9e551f592709a9e497072b628c92fbeec50333bf4cc776f3648b928c28ac4712ec0341c0881d0505cf4b4caffaa339750f1357501984370a0a0a3074f1c9698d3ecb0f20267c68e3617f66d3e2d4af2906b686deedc568491164149bf266d2c46dec22fc41aeb321c88caf427ce5490a62d6fd7bb9d4aa2f630679d95c6a4b62edfea31c4f0063f6351e4e48c6e1f0757bd554ed99808a8fb626bf4dceaf977d5c77e483b4117977cb7e1202136b24629f02f6f1f97457511c2a7d4b9c441e8eb9c5aa818b6d81e234723683c3596933ca7b7ce3d0dccb343b646435672123852fdf199832a585eb731b2ab7d2c179cd458ae86963f2898e1da0fcb19885be7e2c90b94ec44b434f17110a1278ce28ea8e8b1839e836ae950dfa68c3f8633e09fe3f50c6d465b0ad725d9a548a23575bc3b1920cd068d12a58a87a3e5576b2bcdcf6eacec12a7995458a8fae2c215c8d4e841904ab61078e62fd50cdfb08cee2694eb814c42ca4bfce4624c7ec21b1f501c8585868fd6b1727f6cf73460e2218ae56a3247bc5d43e95b1c6b80475a400bc76d82af1201e9ea945957758d51d91a1fc03fae3152674d5dc9df4f83ffc7978af3ad345651a3c0434a2349b26cdf3c4dec516cd22decd04b9c0926c81a7b72d02eb0e9b58f735a81ca165801659bc266199e6a49641fc21fbb56ac6520b846d08d050e1634afddb5806e30edeb2262489a4871543487222f8a8da2730dd69eeffb0981e5d1805d0a63adbde0e80a0586f11d726b3d3e9120503b455274917b022f055e53f3e29f3fd6d92a1b6b76127c2faa9338effc65d7b838e46b9fb1bccdee17a70f627ec39bc61ebf34cb63ea63ac2ccb5fa4dffc4b8a9040ad75bc513b327c200d0f61466d9dabf17636cfea1627deedfdde1783d8699dbddf2af7a6bd7f045f05d517116e814e6aa90aa8bf06d9830dbc538153e734f11dffef133e2e85b4bc608ef67c412680686aa0836f5efe0ed3fb22113f480b56c44c628671c3c7c26bcff67ba85ff2fe7039b928d58a6d37f6da640adb32b0ab37a91a86f0b01c71d14fd9fcadf8496e4dfd0caf1ed61d88d130dc35a89f5d30f0a6aeef61ef81cd27ab9da329df74d48456a86aaf4be494f6c99dd1aae156a2f71177dec6d898ead90606a35d8163406f15d85cc08f33a1ede8a4aa2ad3784c3e37b3a19cbd9ce13b93e34fb142215e5fd9599ff22a78b3966cfb79e8e5939f7956d762cb0a5750e429fc54cd7e0c27cfb6116ec6f07c9bc41bf9cbd157dc30c8708a0a806b5b471f9c3fc6804358ae8063a9459e66e88a67ad156311b4e916f779e6d5a338368f08b86bde9bc66593a47e6787eb3e74194c2d5612ed51263abe54643b4a14b24fb19cfcfd55f7da0e79e727d88ba2661e3317db8cbfac35d04e8538033c16acfdcb990c578275f8d3425db3ce15cd496114b094adc5d639d46a03bac839183dbb2d2acb7ea2a5037df0375805e58bfc29a7f558c0ae851e5b73860a819cfce2f766e29aef65176ef70c6fab49ed2862395f874018ca705a0165c6375edc3aff1a9cf9edcde1a1a341ff5796e2c05adc09b9d2e6c71aefc9fb7d944ef96a44b54bfe2d33160f1afc3f29db0b4af9a20e2f2d11e452bb0e6ced6ca359bd11ff33b524d597bb1420724e93476258c19e50a1e4804ffcf8041a19f2370dcf334a56eada0a95b6816237ea0c5289d9ae405a9178f59fd1f6c5a90455c3760387c8eb09bf9a66cc41b30084d07a15d648141ed45a80d9d2247bf2ea9075292e56a6b548f6a7ba4ecd07cb0fdc9820a75dd560d14e7eed4e33c5994e1b492843900e0b05e9c5e79934664920c46d7d73f63846e962dce00b9855c46bf71705aa5dafa2e9b26fd4776fe8439846a7a7a23a1ee54881b69cd8205b6470474d84c1fd517667146d5d406bcaefc0d814289fdcaa7c880fe25c018b87929ba118aeba70a1677fc53e69ae60f8ce3b02910924e600be3bf93a8dc43007c54039d9e378450e0cdde15a039a66b5b69ca109666429880c77bb969ba0e81c79586a945fd29f3b4af54b0d276a68eb759cec617468501bf7c315fb1dd569c63da5a1f44e4126bf3d178e3a9248ce6c10d718005bd33a1dec7383a13f4c12c7b4cfe4a09c5699cb5e6dc10219e666d32ec7024011a197d701e5c1a85c5066f36e49e8f408a9f911f0021b5cd7c3b88e76a2f1874ab6dc8850f467cf0d0662f2fbafdc74094d090f227cc8a078a9115e394992d6337fa70600a4c71a46e2e972178cff8f7e1dcc58145cb3582605969e0776755055ccfa2a818b3b11df3193a07253d06f873d3e42252e5d3b95cf571183b6ee29d0fcd107a0617a27559610d56065dae0fbf818a1ec973d9e97ceb8541b4cae7e211e0a5d3ea9ba6bb77aa5c8927dc9d8937d77bdec7f9317dd4650c256573ca2f36d115a5291174e3c5263c18b2a471debc6b68dc09644663cc0093fddf2e37d5de522203f31124a405178835e1c6227ad2fb45eb1945af0399511f45ad877e35daedf34f6ca35ab2e14b87bb61934e3edec513bbe5ffeefdb25c285d88a30db8680e69499f8044c3fbf6787414fe39328187a9bc230734fc961cca025fcf13f8756db69eb59fc2a82c11020a7a52020f74b85b3af4a4261288df6a9573f28b1d1e81ba51e9aed0d59f9ee089d27b50a0e9267937347bc43532c6d917c2ce09165d546578fd05d8d4935f8d3453f5a37c4297657811bc0074d1586835a832539176fb85cc842bf0c44dfa0260558faeeacf691f689e6e7d7842fc3d45461ec071f489f4f70ddbde0ee6e28c09c133f4adc077c4d3962ca01636e29df6b41d6db77e3a129f564fb0d318f5e7667718d781f5c846109c402bcb2981b7add24a87e49b0f3b10b40d2011a8c56424f4063aa646995222c17f13b64ae33bb2ab953311ac8909a2ae7af4ef96a7b38a855914a04c6b489688fe822da17240685a992ec1fda6828c3f0993949d691a0f0a5a4734b687017e0bb8522245fede65a1cc4a9f4660ec4d15a989e08f72fd976c2dbd27fb8620ff32023a8074752d7b92dee233bbfca5cf9bb0221a261bb05395969ae4cdfd9252706ee660141241f26e9c7789027c98e213a1cfae59b1c9cdaaae7573faff2ff3b257a229b737084a77dc010d832cec8120b82aef5834b5f398454a950f73a13374e964fce00ab17c7e45ca4432e87616c95212376640f032b6207cbd785859416e36f5153a6e7d4b03d5814ad33203f28d4d4582fa8ab5c07933a618de5b7455e8926eab03a95fac387e4ba780662df29c61c5113ff03bcac70e579fc40f6facca0fb76a2b8c0fa6730b2b375c4e6b4cd954032067c3fadaa68c3e39d24e6dc59ad48707fedd78e32bfe833af1121fc28934aff043f8c99d325b693754509fe54b8eabb2459babc8e35187c2483a8798e85a7f6eb854cb707b9785a23fe6ddf8c58afec6c8fe2738df788e094f5e9741adfa5a5ebf681e5ce2260bad8a74be29abbabd9602870525e5d9cab5206660d63093e34b858f6863cb46baa21a20bfd14c8ef06b44efd8c21a2ecb58668b2a906ce1d1c2d7a2ee5ebcd4694d82e18b0372501d48ee00d07dc42ef9a1d366cdacc966259eb3cbcc96abd6115799399e80e7f444b457f0b1c6bcec86cc080ebe124de981ccc9ec5bf1ab423311ab9fb5b07829b6b7495318b71fbfefb8d5a303bcd3ae78dcfffd516e241d5f4d9ae6d867a7b354230682dfe9b2210e12d72c94c8739233d06017c1e73a5848551f75b08f2a579650900841d9b427075ead470e89d830545fe988c6d4300272290adbf176a7e872663836e4781f9aaaf77b341575ae0ce80b6f23601dc0e7f6ccb7c987350ba91fac3fa8dc7d0bc5613f6a23af5f9d08dc2d843deaf5f75626b3c22aab5a0e5fa36ea17feb1046dafff2f5a4afecc491381bc9df157d550180baeed71554dea0d51a999157d59db1fb87d961cff11281537b462349945a04c24afc0c2060a1db32dcf75014813eaeb1bcd8fd7638f05307cc3d2f7f130930e9c45cbbefcaaa35fcb2bad5e7c00c55786202b05c048e90549bcb35e0d0e5f3158c6a89d86b99f5d679cb31ffddb0f69a6ef0a383066f6d7391cd8ac4a22124e49ecebce2afdcd7ba07d80373e95246fec2177b0b2a59327cb6171e3725448370cf0d17712975ccd63c587b973fa338e8eadfdda68da419a3711ac7af158fc68d0b6d37088a708fbb5b6f6c27b52bc845316121c8773556d1a23ee3a104f1e22e43b16602e85a54a101bbdea493b2fea0db5692ce397ec51eda7530f4d64e257d746cff1e8a45a0e3500a95ce759e01019ec62d7efd60b9f8f5b6345de0f8fbbe53ca2bda2fe339a5803763186243054e94e13012ee22cb847e3f9bca75ce9add46740a52e1c11bc9c20b2766587175463d0c8ce0a1f2774da923ca5bd6b5806e07d3f6fd518ca73e5796743e490241b939b9e9bd2ce3045be22d6d09e2b4894b26c292b6c46f591867fd3ee039bf75d8c27601543829f8343b63043362f753a6f280dbd9aa2dcf1ba85bb0f42e6a6b6b19a3b755d75c735426252b4a6c857b43775d136b233e7eb5295b7d458d8d5cc420bda0b5113de252e77636cf1c57850604f45e5801602987adace8e8798a39d166bab3d0bdcd4fcea8884b70f4ce24a63f44936b05fbcdc385fff4f7dbb532476a2a9826b47d78ca066cabf6eae813a61f29a32167798d43ce70f732051e288e4c35324e11836682b9173d06236ac0d9dad5a8f548dbec2a8d290512f5562f90b8123051325ecec00f94cb1501826fab57122e6e5448f60e374f858554ef703006d5755d1dd72484dae8ecdfb0e740cb3e9ef8c80a04e5da050cba25eb692cd84d4ef5b70fbf256120a53a2298858decca7a1acd88a2b27e5e2cdcad671c1c738e100359ae169e40361edf3f963b51710fcfe22c65fb720c68fd7ceed16ab59861c53e7f96d907b13f84ec4082b8d8dfbbd5c1b355d73f970ebc8ffbb4091552f0934eef8dc5d7a40ef366108d1ce2e6f4d72983403f2d3261304c0c6989b135714df6859f51db7f93ae0184de8560b9d7c8470ad0e31667543fcd52b60adff4f45a2e1f8f330c9342efab171b6e563cb6a186905858474aa0f5f0121b8e75dfe1ddad44a24e9410dbc89d682e552fe73be60fa599087636b01e6bd06b998817c16da99b59cc52fb9708d31c8d7146ea3e7eb579556a0f33b7f7d3838fd759a1ae90b9d45c59e544f5cf24a3167fb882876179693908615101939943ac6d892e6ffa338d532ef75cf54c295a733163413e9d7d2d5eff6fc06bdb74a0e88bfb6f42b641bda8033e27bce842e1318d60d6a7fff6a446360da8d3b37ef3f5fcadb03c4914476c0370426c1ad24d488f79a2c1f934b7ba9a99876637affaebe9e67c081e0f621dfe90528a3e8f58c454a1dd2a1132b05c9874fed5f4bb61fcf50eedf3ddec031fbf40fc897c756e4ad1c0881cf1d012028d21fe5f92195e7de929e01d26e267859c92cd643985af1b295b1f62c10c771e284528dae96d63d81997efb0329721ef383a7ff88ee6faa50cca824599b832daed70c1a9a16f380911c571961353fa327097df3bd46a480855151e59ac068d10175cf2a720f6b2e79e09cd39ae78e39beb8daca96361a34595c363bf39f2a6972428ed01040f7afb6270cf827de2937cc3083e827ad4b46ae2c97884b6b38c64d2568ad4e2a9c2166652919460889679dde105e9d5c0ca09de5df3f737a72cdb4c81df711659788e707c2889b9e7ab188190e01580262c1823d5192c2fc3867818b5bd1c3397b1a5484fdd3d7edd0d7814e3bf1e1ca7dc9d327b7eb27db573681bc578b92f4385d214779876dfef0fd7a9882e10eacec0e14274e9bda63fcf478a1fba15466c674f64a61e226c8532ac364eedb13e7f8bf81649eee54dbc28f094093198c76960a7dde67f49db5d80151023f019d225eec764d9e2d4a934a1fc3d904223d105fdcd907a44c493ab80db84ae1fdeb2d641767a6a88e9cb55dcd8bf32b4e73c269e4acafcb54334a8d82744b84186e76a5969196b22a11dd9df2b4ebe3e19235449603dc974aef8688586da62ab9e3f346b73fd75303d66871fd369beed52a81573997af1cf66fec5b2045136f77c95b6c3cf3e1ee7457e96e24448a2db011e66975a6bc82ab30962cdeea9faf35d42a1b294da330245bb523d1b68cb8849f6f57680c156caac500dc6de421cdc6a6b3338405847e668772df62f8b50a6a4118897b4d15121a7ee13303189cbdfee94d551a2098720f176ed02ed7de562fa7fb78200137961399fd9ce2787e715862520abdfb2691e257e30ff92dfe85d2060c722a900b56e876457fb273cf4fa9fe2e657353b80af9aa3e6cc1de26a5d2af5e617e1b56ac290a923718ca67c697bbad38e30cbf7598c5049b76326678493b963d0ad2af426ddca8c3a2a17ba150f5ff1170e5a43574d2b948a8941ae58c223f6131d5147ce2ad02bc4bd9caa31104b9bc944182a06dca7ccee26296a0cf5a9e8533572ce8de0cf5be9c980157877d4489c71aba0ea309a77e6be1433dbed72d3628dac3bf8f338a23a8704c581f32da2d18b35a6895e1b28277f51ef85f63fda655f1d3c098d3fb3e950b0f0a02b3607dbc752a1508f176bdb77cdaec0b07ebfbae9ac3c875a534ecf7ea8bf099d84481de43c80e2322f705f73f3c10c70a0e3dcfe803cc562e50f3a803fd12e6feedaa09a36a3e52403e5f6a0e5d4ecadf6d9ba1bcb68c8a7007645c5a5f793eba7fb9d28212472a74ea7a0b7820d71a1c5954017484a848f24e81e3b2f12019dfe641fb6083ef60ce8e724ddc6c29ae2fade27dc35e07af94c6b49155784e8b7322a0f7b720b507ea19d5e24c47684e6e7d1c00aa0e86760dd9dc4098a24eab92a89e56aa4448a5de76362de7b74a65033c022c608ffe7db14bb0db376e0e0183669c014c10ba2855cf9183ad6ac0fba21290e36dd47e6c78d6bde7d10ce17787d79ed8a73ac2eb56353b3e937b945f5e2127eb2710904fd6e2f05e4ac1d89dfff9af108a1526b6924ddb242f0b5fad999bb7380c3c96aa3774ff6f15d8e67c5c52aba3e8ce3f57e7b3bcd75713947e4aaee90017c7faab39d0a9e9d82cd6b1162d4a799ae73820ea4f8bf20c60145d938d822ec5d6ea67a8a10d8c53afb19026f3c6cf40321f6ad545b8d3dba3f9c83369ba462a96be6421f2b37ad49608d55ef5ffb09169069493b793e102a31e2cca6748b3e7553a35758935ce915025e4e2ce6fbf7446fe856138c1d251e7ca911d2bee8a06213dd5296c308f81738d686046277203dc885ac6845f9a04b950456ae7ac5643ce497ee87f7b7522ecad768cd436b9be8236727f003cad577b992316a454de9a0378cc7d9ac8a9e134cbae09ca295ac1fe74694f048e75912ef97a9ac0ed23725d9c82fb7fc623694daaf02206e216e80a51e424b1018491b7fad012d17d74278a1d7685368714148a99784d2cf917eac08381f8e3d1556d519bacc44259221fd18bf128e7b16d61a2ef49f6b036fa377a4db703ca632f13f2e1080848b5b60448176480754e0797e3850b15ee547ec72c31975cb77f3bed8c0ce63e416e8d06f376cf5439558da6a6620920d77b6c98a1b86a2675c622223e9dd90ae1772b5ccc8899128884d2978532d95ff5c127443a870ba1176c90dd4dccd06e055abba4f28817bb5e7fb9c87e36ac74a8c72065817078792bddcbe4fca3198a15eda7c2d2dc54f46a59d58555c2e1bfe1b7cf409a677b147f18ceb0733fa8125d52aacd6b4270eaeabe74c02eb0cb3026d624581871a492ac29b324a137c4984cac8dbdd817b3ff872ea059c5133f22f5ca4766de6023b0dfc8cee35c95d188b71ecda40806d5b3fad59b616add6d27e93bc8e82244b60732d72f10b04ce93d4535bf187a4386b11d7df41f62add4a6e5ef2d38961fca4d27363e5b20ed48daaa720d1fa7d4f1df33d2ded03c0e17cf9a00b033360ab3b6271351b3937fb087e0372e6905be3044a7739b9b6511bca0a9122cc6e32cf0c67d07292cc613dc961dbb39ff72de5e6a5fab0c842ecb009a72cb4811b28caa79d7b2841b5b694e91c104197d2aea263599ab3a3c8638b4aa008444ab9f80b95e55e0a258d174eb7d1fb338c03a472e69ef1e83f53729a974c1cdfa68484d6dc9f1688fb5f9b3e74b6f5286b704014f7a0b8bb4d86f762ab4d82612b92b465849cf8c02fe0a564a06055f253d91dbac8e817328fc908bfd467ce89c79a12ef4521d34e9b8ad4052a28b72d0376f1b1b2ea2e0561e3bfdf8e170fa64c3982a769bdcf076ec11403e2646b825666108993c26c105f655b1783e7b976c53581b38b41275b7e2f8ba74c6df829bb416f888a7ba411d1ca5c54f373348ae7ff93e6cab8528eb4ab57f41b761593d00abd8710a29106cae34694bf2dbeb112077ca62486ceddd399724de7c92412de19f44cc61e08a834ab7b1b82ce68a2c6e1cc68d0f09607c1eb91a9877f10bfc421685f52ceb8df976b12c0890a3ca939b3ca91ab9e37fb01e7e91820d535e01cf5d252df14b162272918edc561687e86111e9d39d05b5e0d52fc53172d3bfb605c7a3871558f107f0f3aba5891ed5319e0d52a4046e1a815ee11adad553038f36b6241a924efe41c3c80ffeed74ff8a82be16304c4b53a0c21b93531d62c0f27baeecb0be4f5a3e40ff898d73402adaaafe6da39e4dd3108a3e7c093734284466b56183ae4564f4d276e76cc0df2d5198be427ad68c15179d35602b51d3268e3df447aa24c77fc85eb76f29a4b0a6c3fc44573ad94c5bab90b6b3252d143cd3b352b464960e6b1399e569bb9affb15b27c6f1f153beced8f8621430e1b88bee620310db3da025227df1732a14dce04f5c52f282e5a458001086ac0a54fe1fdf504318bef96cb28d33c1dd4cb566c5db4c8f14f9d2169010b4fa3be59c5ea9d4eef4436d1c20211bb9bfcd57e2317fdb2ed6e8219bf187591660240efa6165a133e1a9a98b8da4d4e8300128a5c575781b59ff7182d8b7b6ae552e36a7fe7ba5375ce717357c095f3110f15b9649a4de5923ec63d0148d2f07b4cbe0f31dbf11a28bce0a2287f99c58e70b80c03739d8ecfd096d22c19715b22287fb77c57c3e09f1b1ba044312e36e01eaf64103a189d553bab8ef22c3532f1f3ca7db12d53ed1771982257c745575f584aa2e4428dda733e8a5d71bff711ccaa7be10a15355171404e85dbed83ca659afaf8658eb6ef397d79249810bbe9008af9bdf6ad58d9d411e65707d5bbff7c27eb6bff460d1d89ab1808989df7a105d973a16970637287c90bf3f7ecbefd56bbf5946de75620761ed0bdaa01525f2c5a4c487fcc651bafbc9a1c9650294146ee872625afc7f27fa8161742eae0c33949e8b06ebc123f29a4ad6a391af6888320e95c979faefa76c11b5db59e326c75354f7ee8ad7f9be01f5df25cc9122979c23287ec8522c0a5440ec63c5bd69ef8ac295c5cc542acd83edf1632879dad7f5e461aa7d9704185c8b578b680f25687054536ffea990734ea1d97729992af6a758b429f64f1b7cf69d05be98d349d6148f385315339de56e0514e3f35de96b780152ab1c27e2679b0b084ff1a41247523ea67f5e86784878809004376404aef185f2e01524de29ee66dea7d8bc7bd61a5f6e459981de138abcd4b2c5e8c8807dec29c074da48d0def5096f2b64c190c52729d5a99c11d9fdc3ac368f802b9e0baf23c0fd17fa145e8f528d80c16740f52034ce569bd01c98643823df1f42720ba1d1f3d55cc37c9cc2d35e56a22ed2378a49e0ec187e2305dddfcdf4d247784a78bfe5aeb13c6e6267e1ae79d0c226782a89de04836b4a2f2713ccd03497a16777d3b837315bd16e4ed67376a05f94e806abc5341f1a39c8a8c5b64844dd0ab638255cb5bc1a450664a2b55b6b4efaf6c74fd5daebe89ef1448351b032b4ecc40bb7930a16bb18e4f3422402f2d17c03e4011524998fcef9e234b1a2b4f1696bb2954bc23a0cb3b17dd5dbe461eb81e6ccc7c204dff8eff61a3066604e03a727a7dbc88d897e04447206fd74c1ce8d080d0811be696b6ad6ef43de7ca8a72c030667b7fb5457f888a6cf19fa467fc579e538212e1cdf6ed1ec39c7ad893e9771d91faab2f118d83f6097fab71b86b2011a7144806898f66bbc3960b6551f19f3cf71137f8bcfcc67b9d6e17cd29beb471f9d4d29f9ee5eef44d6c35f7213e5210660ecf43f912c86886449da6205af752ff6827f19984c382af2aa87629a9a4d8c6719275eaf47113fcfd49fc8fdee630661d3fbcaf4ef8d671875e88f108242e36ee87a6d0a7da649259a899daf1192174cc955af8359464d3313be23684540fce6523127f765e36b3110e7a2e71ebef89b070935cb15b116ee7d8cf6078be91b9b3b6ebe330bd4b5db518ac89e6c81fdd753a75e4f731f25da7e47c06f5e217674df5a08ecea2f686a90f180e1f7159cb69c1f4dce5efa8ef6a08540fa5c35b96d1b36d43ae2cd903d011cf85460475f7f314b0ee929cacf03a458db503a641bb8da495553b662776ed924bf34afca3cbf582dd4b50c7c732d2bd34253864c18318877c2f49318ca9e21bf52b74072582db2bb49b0a85c56f0fc88c4d4f2618ff1d19453bce5ca8cb83361e7bf45175a2112701269908f5c980d39c9a65a0087e704c35ab570fbb2fe89c5f779ddb2f45e62e28e13faca18575b6d3c0323467cccf0d0db2886bda687cb96e08dab3b2876fa57782a68b45ef4090d22e3326fc4e83aa37fa4439531337e2ac17c9a6cb8efd11999c9b34205bb1f0456fb1767073aaa0a925d47246257acf11f396e0c95c009e77a1e521cf02c4e5c46c7b46c00995fe5660dd3919b5794584ff28439c25b562a88076747104850295cbd193ff508049fa86ab024bcde2585759b6ac148e946d7904fa3d5338cda2d7b225404e9e778f95a4d96a8c96165cbf9e4369e4b54abf4e8e1f4bf04c32186e42dab963bd40ab67f065924650d6d33b2d559a503eb30f97efdf0320a0bdd776f28291b861f65133c05a58f25c7b0f3a2a231c98b23eb4ea41dfc5445f82eb2763352255d8916ea11386eaf03642cb91a7dddec515ab481c055e13451974b7b91754f0fcdd5902bad38be8946a3967cc664393bdc1f99ae0280295edbd05f1754cfe3910c656487ecdc24d1d2527e391f611e460d9bbe950e991dfa8bbf4c8c2b120324eb0f6dd2a623de06f4d7c0260a2b52fc0254890cb7cc803d2a8892bf903d11974cdac65af76ffe6ca2be18b82e78179d0f80ca73539a1a14e2609cbb188927d5e04b6ba8211c8c65c6c1f51a511710a1e96e89f4fdc35134a4c303be410f32a3e3830bf3c2301ab464e31f7f36a0d410e095a2f4385d6b6987b5714a32b9decafdbb4306eae47db510f9a2c7b22a4cb8087859c02f751b3ec3cf86d53475e7487d5536f7b34005217ea99ef5fe788ffbcb054726d2fc418f5c0508b18dafddd304f06f45728bf69b54405b60b167be8fe85f5860e8eefb9a4fa21f0312365af99c634bf17cb276557258494d3b86913443efb1b5355e563a6297faa7f677d0e4fded6364dda08c2759bbba770e088980ff304c242536d7aec92228981256e7a3011579f5d4c2010e983ee458324677a162280275737df0de4baa0738a91d20591e40e38aa86343c594e13b5c64dd28c9c5793fa03d1bb16dff1cf5ccefbd0c883971a2b5e4afbbdf9e1132e78091ab060bf263065e72e2d684fac945153fd68363bdac26ebe76572f9c094e6e758378ade055f1b16bad5be9a8332c0dfa42961522c4ef232e8ae12bb909d7a7442778c6d72043ceff1fcf1ed62b07e525f1ea5d1cb23bcdeb0edfc3c2852495ceb12caab4dfb22fc303566d013479d3341145dee11ae4cf3832cd802f7578f1372af330900eeac14e53a0d75af3b831e0493b974a6975b34b69d466cd2c47b001b676f2acf409adb7b18258846f57817c3bf8c7ff93421040cdeacbbc2a0a33a125e1f1925bdd86cc35ac8bfd4b508724f0b2362d1b8a13d99df80de28585afbd344f8e6297c26dfce80c754d28e9bccd463417dbed3a41be33b2c80b618ab5c20f5088d9df098d24e403ebacd8a45e25dcd1de1205ff08d17239f8fd7a7e5c341a049f521d643dded5412a40cdb54a35c4e884a146e1494e190b7b460cbd29c2ee5105f5727dadc2213046aea6c1d7537617fa4010df","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"3326571339d5bf72661c4d438fb2e527"};

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
