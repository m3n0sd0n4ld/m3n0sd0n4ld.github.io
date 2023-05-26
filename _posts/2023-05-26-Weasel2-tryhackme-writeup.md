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
                background: #6C726A;
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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"f24908fd65bb0ec910307a8bedbc874b42ef26d1a80e65bba01605b6658b4445bb6fee33d2b8e233042d75192a9c307aea4be878cbb86ef9e87fb317d3a4cb9ac0d4436693462860705421cacacdf852f9d651f8035391bf8e617f6f6468f4e1416ea522fa09fd2e5ae85c358e362c88b9f8926d673683d4f1e6f7ce2c4445a6952761078558d54a11990bd4383f08b3aa57efa3038c2b32190430db0cf90ae76010d9bfcd4635bad9a6a1f39914c11ca4322c873e3471b1d16427d331d70e9226dd69caa56159fa8daa5f483518f8d549fd4f4f13ceecd5c98087a4e7a170b5877aa25ef4ea9ae2d0a6491e78717cf855d7dade799ef78e0e4017bcce572a80eb2b86fb119519c390b5487060ea5a844f239eb26eade1757a2969a83493d69bb10042dfc4fad3545a999c35dca4551eedd985b4087a9fc6335ea3a752139ef86b8f7b7447c8ebc69918b90fddf620a604a4f33babbf589441371a63454b44e70c7b66fefec66702e461427d1536b86b9101a6a06b09af38ece1b25455e47fa19fd091965d8854d4904e00d0ebec441c4bed6fcf84c7ae3b0675f5d211e8bc1ee68925c6c88e29849f7b2806d120786a884892f2142af619d319f6bdfceb57490bd107ff399b25c7a4a8f15b2d1b15ca7ec61a46fd801a68d1257664f496463ff284a397b297f4fae9ee8abf80de2745a555bf48fb84a162b3d195c44b253ccdceb04ee692de79c9531771b519f907149d15296d99e2e2a5367886b73c3cf1d652b1f7672569acecc46e9633aa9736974377d464633ab716e1211b951ebd9adc0bc725c5c93820196731e481c7cc54c6aaa7b8e3ee683162e8104f7f10e3169d3e060adbcbd65c94a5b2f86e035de2c8d376f735d62ecf7e657899551c23087e93b35833a76eb39ab925d4df6295c9cba6c0c4d3e1b1a09a4609eeddbf9e493de94509831e707c535eb0f54044f2ec8ccede3211430fdf5e1285a61583a66a42083cfe424704d8a4260db5e8000f0ff5582aeb6a3bc6adb8ce43896c0456b677aadeb5ed27ea6195036b034a6ee96ec2e43a591e9ca79257176ed5121c954e1598781ee8bea700ff0491b05a83547c1cc48dcefd139cc7545c4e781402de5fe87209c8339c022c832f926382f17a9028b0a070281d5e35587aa327d536e7c166f4baf0d79cd7b8640935a583410a1e6c2237ad1a7bccf253b65c590c2c305c36f7d676b49952a02bc4f595f05042221d7dcc415b148df5653e56baa55d949687baecf1e92ced9b6bcba3cc4eec779d4d7378f9f5a46b0400f469128957c6cd55354efae0224ca73116071ed3a1316fd78484a30366d41136ed07a7879b7e4706a720b3dd46e70ef04a61a53c09106a19403b6b749c8d271713f18dc31da20550d8bf05f9b425920a5dc5013dfeef44721982ea67173215fa55fcb41c9db7f8cdbb1894bf2491775466ee9c3f142313fd6d86a32f066356ee20996891b5fa583a543a9f9b9b711c6664a54bf58c8b68f005b9cce8acac7e7951cf849beaa45a08c9928f94f2fdfe39113d3eb6ee2ede0d3a240281bfc611a203aab8361ac9d017e4e8de089a1074d4605d6fb82ee3b8ad12fc9b703e726d9b31153f9d99610cbeda40e90f92dfd821454598d5bb2404721c2562911638a1ec2e2333d5d9d84bc8baeae6c17ee610ff13ef5cd267938924bdfb3f8b1b08b70418426faeb1bae6804bf2d7513e0928cc8efbd3f9cd070a508eed8a51bb24494a0686976c3f91ed7620f15ffc35929d5fb61ff69297c653abefad28e2093cea512576cb85049ea9b4a37750ef91d316d5b901e557038a6ef88e3514f5ec251870b5d939016636665d23e8fabe329b910a7cd41173552ee9b8e8415f70de6656d1810c264996c473615e95f5e06b2a75008a5635416db4bc0fde419da058fcc9e778c68ae1d3ec0c980d32c8f9fa459a75143675a5f4127ad790ba2ad82bf0b7b8f5a5b22a949f82cd9cfb0016a079fa183c484272945b8c9e4f41042fa5ae585a2f764ef152eb551da5ffae2f3d0e301e2a79416fd11faf4ba92062753983ce6e96b8e22ffda448c3fe50350cd266324d3cec569856917e2372d1e85af2b839b4df11bb56653dcf144f2f43d098bbdeaf9d8f652493976ea73968e0cbe892f623001a0c0221a13ce41b64aeccc6fe7aa2b083235acdf70d3ca2d36763ca034104aafbe9794bac284c9cb8c1d08fccc74536821dd544b901e99ae13c4895cd72fbde8b0bd614ec40c18d72bfffd520e4ad8726aefa64c92480217217c014511b990a288097270a9caa4d88bc480fe6754fe80fff5a6bb8c255b8014862ca83aae483344adb2b48c84c1bb8c8ef31f96b66b2a172d916ed1a6365ef57581ae3cb6aa088e37a80033693951b2c63f070a7e4ed9c7e27e3c7e2290c6c889bc7883286e6f4d9ccd999eaf8ddb0bffd4554926db6ca7becec81b7584d52b7198fae39e04cdaded1d8d8375d4fc53fb44871669f82abf7fec69a4ffa1d1a85d6dbf5f318fd1de3ef2c106ce98834b348ef93b1728c218ff158594ec00ddef25cacf846d0dffc4f449c686f3294daa3c89563b01c1439a29fd073dc8d3ef55fe4546118d20ddf7b06b30b18493af2035fb6447840c8551bb42afbbbdc921a00f2b5ae72f9f70fdffbfcc227aa8f0e0186865e3ce67cb087ed5d12e6c69515885326ae38a3993b39e211f0883253cbe03b084242b4281ec8e21bc5bccad321ec2b99294aea556f615fa9a7923501130f2db919f254f79c1b4f5c64af67d2aa99cbcf0f0528dad70519dd025ab7c963874d47c9ba9f966580dc339d67c2a93776ece1bd3e3331165b0e049d614ffc32add5b1a45261ebdfda5d602c422cf7e3c78be47bad5131a553c2af7ddc1265744ece4aefd95df43cc8798b8f76b402f03334c052b8290f1a827dff8e9019fd74d1ef8336e00da5ac1b8de802942e3e949af695b9dc92ed71c2b79c7c7858536980547e3a5bdd8c4a2375522cf19df32e25487584af5919a5db75089cb9bad61fa30624f30d95d1b19c317922e45f86d5d7ba45f72ab6653c8be0ce9ecd80122022e7e5660ce2c89dfd9698bd665c8c952b0535a1b1281058bbfb858c88d000e129b400c02b1501e12737fc285525a23c17da4897f4653d62e4388dfdd809ea55cb452107bc2f9dcb2d12380e9f56fbfbf279cb0e1455f7f6a98d5e61bb391d786da6d51417f16a38800534f0fbb3b16b043102828440a5b238b5ca52ca17a5fea7ecbfc6e2e97507105a5939117d22d6f4a6e7c514c181b387766a86aa1d835c3224baeffb191c984cf69698a0068e95c1963ed51fc8da5fc1afa79c76539bddf175c8ecdc1146dcb862f442f621c7d5e8c85f4d10dcaf9d89cf869187ecbd29df2265d028d83c798fa88df9511e65806597e5366799076db46f7219a97ab58ececb97ecec122eecc2075d4e87e81a493e999c971cc96d0abce33dac3f92d215265e3cd05c4cbd5e6d252b6bb49011ab2f9d00c0608dec518c3766173d467a540b7c39a7457a93c6232b8d9697110037803b6dbaaac39749eb0c228cb47a41e59869c5589e62c34e3bd2a10b9cf8f8166f9c7506f180de051e680f94111866c2d838328831b7232e6da46bf7cc4d5e2e34e8ed71b0c4ef5cba6ebe8572bb37d143599b7aa52bd791d131e46c16889630e3ee11e958997b466aa2f7d5001021e194b3804a497d0c16888be4e5b19bb89f59a191e0185bed1081f334e4da80292872642e9dc1bf8edb15ca87dc577799a4a7953a9d8f74e50c8a4ee0fdb614df1d24e7a9f83d88aeb94963e52541c0aa4d2f677e68977210a91ca147444a84c9eb70a590890b763c6c0c066c67b3b7f5523b617b58a12be78891e4a87734f688b62dbd57945855a2035ff2c1a6d87e6b8d3d976243f1a9125eeebbd58c2191924917166479338707a2d4c8ce4161849d03b9e06b3129a1084dcb37f16d3f85a2904ac79c33bb483bd4e31b4ef2d76087f527d219a34cd821ed3a6ce89d03711a8cbbe2f8d64b41cc45330cea82078f8064f8965c8e10ac2c63be727bc31d8df54672dea003898836e5548b34161c3aad2e722689fd12e9508124e42315bdc671a00cc77a35d3d005463e630b1a003009a05823bc6c80974abf03056cb180a79699745dc83c7ef96a62ffee3a0f6e7ba88fcf10967073fd42f7db8dec735ff64483e8b2a06f3efbdb237d36ab6ee3b8b608f2318b7077acf823aef28ab7b0f211c54dc4dc1a9ee72e7d7a42d84df10aee2a50d119862e30d2d6c918a6570ef722bf6b38cd60ceef28aa52a35a864c1c3cf514b0c9e6a2fec9c457c33704987f4eb5cb46cdfbc9c5ddf80b80914b83c7ae71f5f75b9008d7e87babf3862e9c5b9b85097823e1c6e7a062b7820f7c1fc0e6e5240c4e15e1bbc3ac3211bb1f99d6a6452e64b3d450c551fcf9d28292291e30b407253284817bd0f73d629035e4076b4a8ceba69f4f40255353c07e20ee2e2e354b57abb73c23367e017849edcf4ad0b7c9f63d1bf3d24fbeafd7f6d58b5d8b6afa4e8fe6cb9d399bcacc5347f7ecad1892d33b53d67af0fdc60fe43a6453a0c430e79082cd6859134aaa36a7b303adf18760cd4d2e94a003fa9f48a5601d8ac8b119cd803c33046cb49295f539e3f6511a2afe351808843ba9614560325096fa350b14c382599e85a72359e25a70017de349288fce22d815be296724a90bddfe4a0d6c806d3145867e5ad95e7a8523aa2f5518ff8451e18196f27e6f46934fad3df26cb2f1a8dd3cf70841f338465be4efab5cd11f6b4579919877516c0f7f6e9a32e71f08fc4bd3f2e7dbb3c910003a17b89fc537a19566b3d9026aeda40ba1d38d23b7ba391daac9895eb5a2d26623b43b7a651a0c5b8dc32ad0acbf959ac74f45caa3030e672ae71da1c7ec3aab4b1f7f695394efd256c4a540e0097b9da938f289d4bd36ab1c0c3095b25ccae1f807f744ec74831a4ff99cce36d4fc27d8dfe0674b352d57f79268f28ce76e7bb62b46eecaef00cd326048444f6d22fda22aec2647245f0e67851f53af9d9863954e2a99b087ea64e1b4785723d3aff5ac0eb6bdd12f20b0154083957b08eff899e0b9f587d5099c108d5c2ba6d7d01aa1ed00c4fee4937308a4d6158d874ddfadbf28143bce1a7a2cf08df1aa263f67501a2ef6cf6017cee0e571701f62e119c09ba3e3d3a677f67bdfb0b22273429ea241b79dad5fd683a0e967faa5527333208e019482f5766e7d047f36c0189551eed0706d355b4ff24fbc44321a9ad060e8cc8f127979ba30bdb9fc56900981efc087802d4860603a3c64d6b10ddcd13627386fb8f230f72a0ac3b7102b4ac791e8f0dafe9ee5b0eb08144f4fcad8c3aeeec4f0980c82896b626648bbe4531f95183049d2c31e5fa0aea1439293c25cefc9cddbeb81d5c95ecb06211ec6d720491448eddec1da62bbf1012d40b079216185fae0bf0e22dc145b2e6748e964e4bfcccba0dfa8c69de7664aa11743788df02186ae787fef7751dd9344cfa1fd39ddeaa35766cc6b826d891f44f53239a69ed320bd13ae7708da3524bcb8eeaa540018324b73885614b75d09f2c5602f66796f22870f4c483926e67332e7782bcb31d9bfbbc17406bbbea475354a372ffb6b44f08d2601bb30c344d27813678bb7ab4a6d843dc31e115f9a0df7bbafacd0a2750d51638a34690d31fa7cd0056516cf9b111876bb66eb4dd3609284ba42f15fa1561beb46b108af0497e1c926e36a4c8592224a704c9e1201e6729668e432fb019c8d9f7e6f835b000225ec41982c1ce7aa51c25184894970f4f134f654a798549e8cd2fd3de66bec19de6eb31a5c5bccddf347c2e2bf868bfc30aa7daa1036ac81b41b554d672198f15500ffef2db9ac0f624527cbcb86f83e508a09a749a55b5a76e59824912ff607f0b7defb83fbbf5998447b2d17084f6f6cf6c486f0ec1d02141a321d87ef8092f22166fb097f232d35e3005ab99e87cb6d3136d42784444de186f8b8cb7976e542ae7beb8fbd770ce873f88f67f128d9dd60800fc339fc8ff8674673e14e94b7d0b0a371e6d67f40145c13ba82c0cfada6c7458325c54c739d2027bdc83b8e2cca21ed559368b2485c160f81fd1a1aa3be594cf08ca69c0d8fcfeb8a53a6abdb6b8a039d2215221758a89ef320fe932426a1c1e1480b142db60faceafc99a8f8c2d038f4c989d512b511ff6695db6c3513ad2d7295134f10a9081c06ea3b6fdd4b188db54da5d314d56286f41768e14a897718d6f9d3d10c40d2943a6c9bc75f80c9e3e3b6f5e3951e9f0957a7fe23560ed482a9a03a8f9b697775bf084d3096b6dced326011977d20a879e43b492335fb36623a039f60df88b0a508201466a9e1c0d8ba7554517639ff67bfc630a7d568ea273c1d19681288f7b01611db33be60598165f7917725e7dd2a7f83987a27bfc5f168071671058f866485602d108e437b2a8515be7ef7358e14143b933741796f3bcb95ee330857eb5d67595cd83103d45d97d287957bd7b1ad16550278421d15b20ebd44b4bb06d7039eb7a16de399a03b7b03127353830d5a06477e3138aca62a6f9e70418a8e790270d9b34558a047daa6b91256ac933e33f8b1dfa457bfebb00b1fddc1e3f970f6214918efb6ab665e114b0bacc1cd064dea90676841a772bf0971fd3de36bcc9002169eabc9598e80b8ed746e0081218381866ef537b2b8dbe654b3783dc5c8d7af33fee513ced1626cb93d53d1d61006a7f2f8bd55b8ea2eef7f44784ebdc12c713faf156368799ddb8188657b3cea3346734d1f4d95f5e955ed95844a22db7cf8e72fef098c1cc5b99698eec4bb6e2cbbe78394f0a9db425f67427710159dfa0b119e22e6599219754a2b7b23bb5d10d32a475d14637171b63eef87019aa510a21b2c2ab5fec5d3ab0e48e6591bc08d49d4722762b0eb047b46fd27ce509fd8b9b7cefe354a392d429fa90abca3f1aba493ddb5800776e1ef278d0e14990b33e95c858e35a6acd4bd3964d29177b793f7f146cebb9f0377f49e40ea7e5e00bd84e5a9fa573003ed213b0baf994be22a1228fc67a03cbc309b671cdb10f3862968011b404339f246f66c453631019f11ce0944c9d525df679e686e32816bc4f965b71d97f3d88469e6b0df26febc9ae89d9c6c1b3ab16f3786b3fa97cb7ee281b216c4caaf20785b66876d47f53da1b50090f5f608947eed56e3b3b9518f3b398787c079bae69d2352aab06845cf8d92df11680ea51eea31e2517574e42284ab90f7094d51efe33b9fb9c7be6870095c109ecde0260306589e7f9761b9322c4663552cb2e96119a89d77f0a21fbc8f63a6d2b126f9abcf38aea77f4c0bd2da6aa8a900dbcefb3360c40ea12d065c2d76e3f575a08994c250935e2120d73a0ebf161c9c0606af985734044155f12d7ed40410a3596acd4efdb413191ee5a7fcef0bebb938f62d394e7817a6793b68f454fcb337d854b8a813eb658d322bbf9f2c2a5f285ea94b06faaff07d3c843ebfa6934adc38f590af4da377498043d8720c52614ca55342f2d4715710412fa371480b345c4d9d12f9616e5b4b316aa11d8ff4d1ab436d2a7a7b883bac6d93d4c48523d3f80de26ea27d07d209354631e3572662ff4e46cdd42c4ffa88bbddfa70a24bd78dcae0b6b6948fd33038c63034c4350c6698ee0da6844244410a59f6d1b958271f6fe0fab1d9196aad7bdfb6a2e12186ac6b6140ebafc14a52321fb98cdabb2cb859a92ecdd548aba86212593ff80fe86571b6ed9268fdb4cf2fa9bae7716036e1b959ecd0c0bfa10916c6fc99f376478ec5defe59652021b237d1787ea3a7f143c72bcaebf549775043c6905620a203cfc7152603e3886d83ffdadeaa6c018f4b0c5171c78852d869e9184c23bec9291a53ba0739e61868b1238102a7f60280ca036cf49428477d98bc0941e9ee94900a8cc9984840a03ff9343c1ec9401c5cb12dd7d35d2cccd625f19a56062d1edeef3fd8c48776fe4d893621c3d8dc90249a30bd2723bb6d2a6519aceae32748716cc1b2b201fa2abd28b6b8debf775cc1796e0e63d7174b483c6f906e91d39ae37756cff2857e21e3b5fab2d20581e11e5e9551a1bc12503a131a8a6cce9c1f0f66983061b1e221ce6c0146d699c2982e046bb86ab4f5dd265ccf798d08bf5e967b4749e40747722267b008e8a6887c8096c797e8d212ff3a1d2244f9bf79cdcf039fd7c3711d6a98a965e28bbb6b0935ddabc61e820dce9c79365366de5292a6e6935895f36b5a43191708d5536e9acffe36f4b2f8ceaf1bfe982c37beb3bafc3bb78140c84b25a847ff99966b4a85372bddef4f818b3ca6be8954c7d4469c0be276ad8f4e4b9c65bd2d5ffe4d59a909940de16be6086bda26b6ae3d89ba0cc2fc6e6e06b7eff038ff419aec0276b0acef8537cbf61abf0496280097019dee3d4985feb60207316b18c08ecbeb30fc53331baceca0c8bac0ec1c1bcaddd4f76499944fe760a5ee5e34472887dca10ecf35f26a84c2590264403286450d887642adecf1382f90df77dbfe27a7c3baacaa82059e11820709d3edfa5d62b932cdad93aad1a98ee5dd23a7e6d19f9d1480220bde8bd7aeaf5327b106708a465c3a33ece1fc98e8c9d8c3a45bd2a485e5de579127adb79b9091edb4b485de226b84d20b66dd9d888dd7b26793aaa5f44daacd79f9f1e0b24bf8d2566a87a4fae369b75153299a3247575283250bceb8b557ed285d619c44c523d95610ac1a67b0e052e0c1df87f1e7853291fc151a8f6ec27b48021f4635b9ca0e22b6f4f2c45057eb57635291678e08b738ebc725928edaed33d068753ea4cd2baffbdb7b9e5db24ecf1ce2303bcb04c346adb559b050646d61f57e3307fb77e2c4598e2c1c2ba9f2d4df952c65e653cf70a3ec6e3693f196617e6e1965ccee8ffb9ec1918c57819ed8c7ab76e674c67d42765203cc9de20e4d90e20a9bc90cd58986d01b81f7096590c4f7679a5e7a710a43ed05f1af25f95c4ba6dd633cb1b142212d4f8009d849f1b4be05d11b7f3cd18d82eff742619de5d27f1e584cecff300223c5e57dfc1d7ddee1b992851dc548071827edd913ec1a69933d692312cdf42bfcc3c02f39f2a2e6008212e32f0b4a61d3a49349ac2633e5e85aa9561c05356704d427214c46b4c7f37276c4c7842979e866cc43e32a07a1da5f06d56c83e19c80b63422b54f0cc17e447b3fb4a6ce7bf36019fb861d05a49a77889fa72cee2f927a07e8cf5eb75c59b68e288f690989476fc66e1060adb1a98469e9f38251ba26f54d236fca375357c2ed90a0dc511ce57cb542f8c43902f5aab7f7dac4fd5f824952651381b3cb3493c53fa5e848a2a132ae639b9d0c174a7f386ac87d8337e588ccf0b0ce12f6d5625c052d889896246461025802d2de88272d3edf0bec6455847e8c1f9ae14702d570940c221b4a106cce1afefa3a9e03e2b6569568b7f8f6508a4edd95c78d82b96fafc6c902bb4c79ff4b58cd520ea350cfbd629ce0fe92d53a532d197a573654bad0dcd65a570e2f789e66cb2a341757d9fa344cd8f710ba5f7aa00685421a7625c042f9e86d84b321104978d1a913fb8f2359d5aa4611635ca70d1587f00e2c31c7e1fbe44e1436cc6e1caeb9b435f5d0fb11bfe24f66f9f9e65f6955c24c7a61e21e0cd561387f03d913041bd47804d28f70119ccb2e6729524369c6b1e4fe0d00b7fc9c0d6be3cd17a030f63c3ef3bad9f443063bd1082d2faf033f854d3d3a33293ebe67a4352748183447f472fb0165b4f6c1baf25cf1f9cd4b45d34742c400e94358811952b693221020707c1fe576163d1ea88e017bee41a43838178f8836ef1de6332dbec7238c26cc376816a83d175b39c402f6f13ffc63cf3509ecf722a67596299e90b75b5711d068b478d6993ccf2fa3eb933681e5c81e6d6965e96b0a6b51c5c52e4b6f9803014025778258c848f5aea832502b33a2a422ca2bf7562c6739332d962d521741f826a9c2d3ad53ac7894ce0199ae622bcfe599e7e82ac1a71ebc5b59562653c76711d1c0a2104352a5be5892f43b63b610bf0649fe739ff08409bdf732ea65ee6677a8335e00a3bd1b71e633e95a32cfef243a75556ba854cb119139a6dab3c34aeef2fe54bfe0b589aa1dc9b8237787503c9106d1fbb16afb0747972c37a0378c922848b00517956cc2be81c29cedcf11517a92523b9f22a3d1794780bf658876a70e9ef8403c735cce1c3b9aa0b68ebedf0d4bee1bb8a07729d51becc21b784348ea14be91fadc7dee1e022ced16fda39683a3223de62f9dc7f82d84c84003dbba197a5a128fd1f63c03a98992f08e51b98f44da8d8e1dae9d63b1380f0797f75fe0886cc34ab3e5ea3e6e74e0051c87e0ac823d99093d0027f6c87a427a8b08252901a011d8640ce6a655164583d81c51d87bd2d657df844d636cac66f5490f06a31145a5aa4a528060afa763eb7f890563e638ea4014fd46f9d7d80212b0d0910d79365c15283928ba0f494eae57719ed2f6f95075461e4ac0952c5efd9e9c84a4c82dfdc5fec504d449e65851fd34c2363cfcd97b654a9b3d2a0727c5ca7d1bded0c0b6b946ec0fb6a98573f56861d577407c487009489309597dbb21814862368fddef6207cd7fdd72d4b7542e03178a51c9f03ae06497562ef0a20f5631328822b78b7f74bd5a5e8d7d45f8b3d6bf1358856d73e9c4565351e33e92266981c63a71572f433720a37bb90c8d3026111b5084e198be60d6d45302bbf2fd1da864f8664d6fee90a2fab02a090d468c5570b4d76ec80e154020cbac0232f3d289b1c68904f7a586a4269c002ac48d6aa5fc809c72315bd5c5bace959f05dd60a9d3e5b6173edba02acafa3fb68e70cc876c87f47d00e4c6c7b8c861c9b987d2f26ce8b58567642d871048f86312798c2ae38ff93a80b594a640bfa95bccc5b95e2d637223c6ccfe13305282560d8adc053a0174bc37883e5083cccb560c9addf4c9fac225e078d175d254bc35a6bbbae4204a2e8f1c273e3cf23b734340098ce10b7ae464a3d8231f2a66292618a44cf8120f24fda38eb7615855f2a1de75e2872219a41fe5948993df313b40b0e86283b64960c97fa4965311731cc8da9318cacdd829cad9dadfa11171dc3da8ff7bfd8ffb6c907c720134a64bd39baf2302ab838bb83a312c04bf1accc9add2070d1adb0da353f031c02783e7441d82be7da3a73c406b9244707c6dfbdc94bcdc27c0be7bfe56520493a7dbe729d7b649fcaceeffd8c3a6da64cb8f369579577eb1d40a331dc6e9a9e573878dc449e9bfae7c44bf59761f9473699516374499bc92a0c09b83745607bea1a611d2a67417b466359ccc034c72bb437965b75d5d732a2f3415100ba5d859de871c3a7b6b2d6566a122316414d019d918209d42390911a147472a34635fb4f8658d14ec5980aa9bae1db740fa787584b1e47492f7c69c0e51025ddaa46a48532eb1475d0114250d67e8133c7709a3381b8c94bd39d68f929e0cc4e82e322a93fb512dc79cf17b6e44ec5a314bbca37333e0bd4929ccac0e93ef9bb2eeee62481c1bcfe7788ae2bbfaa37aec0c2705578bedacac551b0f8ed120380363378e62f2f34359ebdf4ab2264277993f894864cbb0406f53e5bf7c52c4e34f42c239e7bf5904ee50d99a5d029be72719461ff696cd8cef5c3c1b87da33e70d6d82213bc2d7a0a9b0cd8fa809621149d30ef5112956ca398d9c8c248a08c4014c94f31fc262e1e74370b846f8c022181d59e5be37f05655b3fb893f6f817086a8f31fac69a11bfb389016353af47b7d0fe54352aebb3246eef4df368b5a558368be5e6f62adf77aba5bc636cf73a14a19b352d8b98e18816a6817048dc635a51846dfa179cca952669617ba6f4890abffe2b1e9608f74691b078794752c09fedb175a1c45ed51fc26cc7723c04806e7c3869e63b4d116b5272e1eebd07a5096525c03bd09e9d992d69f0245d95fffb4c4c6e7c360e845a0a2a561f414f3a371e7ff65bed536cb7dd119713c85cc257926b2c60287c69735537a36615341b48d0a128d9f98459475d251fd633ada6cf69ee933b7afd07d2b7e7d4b94b4e93a5c9d2fc021dac733b0b40f3e44ea37dcfa726a85996be7bd1d5920f60a3217ded47f435adc1bf17c5fec0e9906c2da8eb444402c86f3a185336cedc0582078d4ef8377eba2dd3935e9ed486e03a0b5af47afd5dc4336f7ed95d9d60adf355390d518e6b2ae99f69314625c990cea2a766de91fb188a9853170b4226b25990ccdc5b3ce1a4f088f9c8d6c11a6dfe10d6c262b6eb1e4f16f311885eab7fc04f5aca62a10546dd1df37c8616cad8475ab220dcd07a4ad92dbde3d37458fdd78de1abb16375ceed53e78a2b6373ebdde1d63232149efd02211e13d260d40a5ae9acfb440396452b125e82bdc16fe1d0e53d6fdbc04f60bfca705418e598b7649271c6979306631c20d7f70b73b6072d6ef733fcea017e0d3b7c30e4f66bd403138ca4ade5300d33aa72a119b9fc9d9e899de49451ba4d98fc0092dfb710b3a4107016f131f33c06ec10d98d3daf754a7d338deb0e5cb0878efec2d7b0622933019a11538e7701b7898008673ea13cc22c590eac7e69b5efb208dfd876dfcced8086fa4d756459a8c6afed16ed0c9a6a922991cc113f694376956a9097a69524d1b1d5645e047eec9047336b31248b4f94c81b96eb0b678ef34b7068ac0317890d68eaaba364038d2890481dc9c41ec9c410debb313cd5d312aa8763bc87908cb9818b1e593115df4c530964d8b3aec503921473de6ebf3568859926d09d7331271b717f217f106d6c9eb6fc255cc8f102bcea794819287928e0a61089bcc5635cbce9a1e4e7bba75cf7672f0ba284ec615d2ee62418a8329663ddf411d2ceaa26cb7ef3868d70c9925557c64b8938db4970ba9f6ad4c6bed1856ac142115cda2f02e8aadc7ec366e85308ff0c2a7a7135fe992e31be3f221a88ed31e474e83f8026a9fe3e203f37e566d993b4223ef310f4aa1016b90fda1368421768ebd50b75ceb27addd72a2ae51ed3a102b64bebcabf246ee235163bc0da8641385d135cee644d8275cfe61d6cb67e071d1aadf56045d424984c918d510b3c0f38ff61f2e9ac12e4d2364ece3531bc86a1785af8e4b153d3c060cd9a863bc269a10a0f5092b2895766a853bd984a5483605a9786acbe2eac98c56edd9cf709d827988178af944b61ec76d03beb900bf1096b4b53d0dd555f6482d300617b0b5d7b3a5171dbb72eb4e9f8836f230e3e4185841d9a2aa135c6dd5af33a6d1d34ff39c90da90782db8e847ad68cae222f7dadcd63cdb1365b681d939b5f37b14f98f2bf09754e1b3e03a688ba80745b4eaf64090e0242abbef54f9eb7873de57eff6d5f1c9b59075796a923be4b282ec4d571ed2fc7a6733a261864633a6663c118ee161f584a0402f24f63b0849a5b76edd2f5450e1e24624f7a7540fc7c59b7839394a9496fc2919954de9cf167309f009eb0fdeafb1323aca6c81095e6d4d316d01c81ecbd914303a49ab3e04ed70a291e1bf764ebbf0f1969f60c5aadb4ccebe3b829fbf154015857b3fd451c2b4d80a6fc2f2b4e2dff5a50f2efa3417fc23f1b409d00b17ed6ba5dda72e4eecfa8dad376b5cedd333c0fd52a50b6729b54566e935f33ae458af927b6eb08f88b883f4f18b177bcdd26b6cd1ae243595cac1ec4f8193b28dbe6d597a3b8efff1f809a1636665e5c64679abc67397c196bb49a86f305067d5ebb17542a1576679a6f9a04b0ab989408325b921f763f791bf56acd8456482bb06bb93d35ad9d613ef96c232dab94fc53d9876dc4117428c9c3e5008cf5ccccf06cf9f8221b659ef81e8b0467f752d29e84c64a3240899b3d07fe5026b7dbfa78f5821420a613b081a9fd8ff4284be18cc7ab48dd4e4525f6f87f33241295f0fb05681eaf0b45cb9572942058d8f1401dd0537e33a7bec19cb053740544078aab59ba69631ff362d57e80bf1e18faf1adab2beb3388259a333cedf8ad446062d123aedc9e3b8fe55aefa584e36ba4731a1b89276824c967275c49652a06aec2cb1643faec346a7c503487301e9723226311044182ed2ad55ce187ea292f08d0b9a5fbceb21e0b05a139ab6cd10bed97281372f184d90e72b90326c02873b42525abfcf45d3dbd24946976aa7a5f9d7e102353a745b91aa2104631c0818f738200d4bdff17670e838179f5febd1151fb6deaf3a94384d18f794701ceed8585d9b0c793c3776c8f158050e4d8e4b67d89bfe5da5883fc57fdf1c0157a7517417a90de91bcc73fcf8f36eb47495478d2143cb36f755cd92975ca08272a07c4455bc735c24885bff19c9c73cbbc0e8086a0e9a333fbc35cee2dc5862ad1425ed9665b0ddd2d24881c0682b4f2e237f459cc55d0e9a1b19c7103b748dcad66a6a8db8b336c568e486cd089b5424a70de9784045e035b32e838c3ac23f6ab2a5631d133d34c67f6538bc8202a9be5d66be60218aabeca3798695fdbe9e79b4d92c34c1408e4b9460ec7f8f5e19058487ff169143dd797bcdc2dcf2c2ba8589f9cc766d685cd2b2222aa3d2ae48309322f6941ad625dc90eff32f28e9cb8e093245eee22612048d65b9ee8e6ab6ff9cdb342e3923622aaf115d4236f2bf3a7ecb11017f19d7bd4331aaf2261d588facd08a2e8a1b50989d2fd4ba3fae3f7fed79719b848320b7903bcc18ab62e6a601d7a9bb1d1b5e58cc18cd4c35eac7333bb14897aca0358d9e45feea2ec3d6e7ca2e754294a736b9617949153c063564420853d0add79e86c7d5bde2c61c1cf24f1360b85dd9864154f26e1f0273185b23c0bd6c8089ff1e497208c6f442116eec2848398693f8fb457ba1bfc984ec59cb362b1ece2ea393c6a385b5362fb781bd55a129110362848913593a1625bea1d353e82091b9dabd28e82b57d343b010ad1af0cb8f44e96a3d9b176e31d4643639ab3f5929898d1112d2528ca7b58139c6233c603473a2630698d187c95617fe29cdfa6a6dc9d0acc4f9f1507a9d8cf32eae5ec3b71dcb5d7cc1d46d4e314d0904648c23d56f7cd137640ac399d0d56a1805633d7edd5d32ede185417a1be630c370e98c9cddc0fc8bdae9342f9de82c5fe80476923ed45e6e424846616e85da4e5355f86065d0831b414e5796f04b54d72959c544c8c9b91fc35b1f8cd36f85ae171959e2fb5e24f38bebf989281f779dd0fb21acd9175cf02679ada699061e979554eb8d7216a640fc45eaa97453583c0decef2e74e8706e25f2bc13d77b782ad9591870d04f5d5d04850067b30ad6e872293faca85d95e91d932967f04598cabaac0dbd6c376273e99b6e1445d9de776b487e561a544f9043cb0992bf8351eb62f4a2a25f86df11396e0d0df123aed007a9586afb53ffe4ffb992d183a1213fefe6adeb8b62b30f45b5fce8ece70a83a887f4544dd93d89d9c9f76498352d84d9c042e830030c1945028d218d65c6e1ac651dc39c10fa2ff81de026402a998bebb9629dc39e1699f0f70014e36891ed782bda001ce8e972670e08ef27cf32e524a7d8ce07c2d5f04d7078767cdea03cc12237659f240a0f8ef0c03d90cc218d5e6ba1da19e47d5afcc29a97fac7b32de2900eff8656c577bb70c7b158368f14a62b52295cf19da35f46b7c3e6820cfdc58a2acc0f4cbc87b982e333e695837652eba033b921f4e0531114103fb451fa6854e027e93d69ad69cd2a1255def64d9c9f76dfc3563342828c1e7f668ebf213f812835a58c3ab08af8d5323471868ab899bb525b56acc6a33d44634b5cdb7bf0bee8da49b3dc47030427a74b6cc3b08900aedb18317e0df399ae720a23931eecb5b9325b2364c0421217dd190179e485dbd3ebe6e53112200d3131cb604373e464392fc5832583d279ff6b9fb52c5a5668fbe0fea00103ae929d5a6aded72335c187d3592620f8731c17b2e7d1e8eaa2a1b62eaf378f70215b2f27fe975a55bd357d6b4bb9f167dfbad857213b562395ca9031994c5ff51312d47a44a1d9c15136fb256f7c3891518718ba0333b81c3fa673c4ea21f8f3a72bf94d7c9da9d3d9f9f7de810670be62ea9205fb0b09960e543d7ce766a029a21f156efd0939d025097f2582accc87f1b6838e088b6642c59d5cb86e4d23eb29b808740631572bb6eff754e1369ba9b66069a6c3db32cb907537656ec42257883207bca12b403872559f6991f6627cae172ecfbcfc2f144dbaa364886cc0509a4ba2d24b33f5dea20ee6902e7fc47f7c6c76ff13de87ae595ca1f9b179219af7581ce65dc990fdfbc8ea32921ee1d251738370c66ae9e75df2980ccd4901d519c35f45aada892b934472f54422a1c22c9b651164d5405efebd9e64d36a63b73f48c1964a4418f6d6ec73e62b5e704c854c8547e55c1cab02f81dbe840064298e1e0d7fb538f9638982d57c3e66824df6205c8e8e0b9c35b970a8b6869910cad603fb9b88d89a16baf6051fe4d5170e72d1ebda6ab35f05100bcc42dc359d5be11fcf2df3a3312cd0e41e739f7aa8f3ebef3046465ec6f20c64bc3ec77f5d29aaa8b4ba1704b43cfcb35078a41d440a1ce00f65ed57b5efdeca0536e8508ac5be0f113b20cf69011a6879e278b868f6c07ac55db62e5d4d9b2a7efefc19a936cb0d70a24813a40582edb617436317a1200afdef946d5b5dcfdd653006b766c4c6461df1626785839bc84f9bcdd58095595de889cce7360b40abc407b88eb6f0ac5902e42213155f3ace0c03c6491dbe799b7f666d73f88c304093e48e73b01f2167a675a2935e479d890535949e19feea9a29d128df3adacef8fc9bf3d1fe9f2a1aec44bd226eb5ec037b69bb3629b54b1176c297641592cead747c28100c86493ca6f9f3bbae37ceb6547b7254b1a09049ddbdfef03d8d908598161ee665590eecb9cbf1c3bd4bd375cc28e3c23713bd33ad006d13b535fd73ead89a25b34e3419fd8cea47208324350fffac3bf34c778412765f2f8ac3d89bbce8e4874dbd2d7b9b5635752635c64a257bed5608c3b4f9cda76e76260bdd534fb431470071f0a9904bbf01d336b388ec286147fc29896d21cd61b6e6a45d506d17581c9af8c66f4751cbc4b4c42e967115f8e8da8055fe07f5097c20540eea15f12a90b10318862bbdd24503c62964761c355a6f285fb827b3655f6ecb5f3703d093556d95d6da11d56405cb4a01a81f1d7e26301e239a60652c1c43c9f611db981f79d2bf72b9aeb50a8430d7ff6b0d9aa3399b171f5448b2c13c354e252f49515d8fbacf28b774d741b84696ede445acdb0230873d727cd430e1c7b80618c82ca67f5c0390c47978bf945a7e97877c7bc22e467c922423c546b1028a2518af2da881887852769c9e9b861bee7ac692fc9f3fe08713aa6f5b9ace76e004fdf24c88c4e13639c5fd69d2767bf30a2a65c37b30fd55b528edd0c0b6b472a1f55b35f8689095c1f317c7e54549846955cc7b0b43b985f0abf7531d5a1c34af38acf7deaebfe8af433879cd81f3ffbfd428cb7e4694a784bc00431f15fe56788130b3c8c59ed9f84dff285df4cea45ed170eb6398d7060f8d2ddc456734c14cb35fa0a071e03c4d4e526f28259cd09d07fcd4cc721f5c7dac780804c00ce030955b63e3208ce2b7f6a9e20f31981e64e83327cbd1559c4eda051f09da4aca467916f80a507a50ea6c075b00bf291ea025fd5f4aa1086ab260091e07d9b69e50e83c8714df10c7345cf7fccbd49c45a5316089d7733e14ec4b736c9e17923de926ecb0399f8f014ebcf6f0facbb96b1ba8af096405b8ed83c3f97c5ee2bf420da4594102d9234e96524322492e74ae7a63f35ab679caa2ac7d0f9a4c22ac86b8c2cfa7e302a19aa52fe5936b8552fd7e8b03135953fa24791d548d0e184e66d94102c2ef9f8be90ff85111d089e912146dcd6c52cb0c360aa6ea9b5d5119d6bd3e02e0b8fcfbcd9796213424af02e942a2573ae7f4a64335333e4e4b71e607c05e8154b9caf18742f8c87e220be46ce30005ef1e501ad598a7a49d6f034dc695934b36945f6b8ff9499a13eedcdd95ae32df01471661a64abda096bdbc9d28d48304b786611ee4717c28e0aa9ba202c9ff824c67c9d0f3823290e116d0af95fa13b20f02b740bd40b75fc26931f1ab6ba8cfeb336da9e52608c5a237752b94e6ee1507fd285f840c5c7b731b15d9379a92d8e89f485baf72491b5d2c22aca97f26fdf476dc7cf1fbd45461f058060057ca32a306fc0853ecaebebe01ee366658895a2075b2ef18bf6696ac43165dfa66938fef3a80ca6b79e0d376cace568163675d51b5fc831e35ec790c384584ac9be3aefeda7d39dd83fbf51131984c22ac4738ce051d1afcc72bfc03edbc3b6035b612b82ec84adda8597f83efadbdd7f8093854440ac0ba9414a7cde57a742f641626e77986631a412ba393890541c7204f49b7d11578cde5a56493a77cbd45c0fe9d76865df953a6a0cbe9bf074662aee28eea835fd77b710b1e07aa60cd3abb22ac076e425e68a5cb7032cb86435af6e717f4103df6145b201c26ea3b26eb68b90bb41e98c388d7762a7b3b1503bc95e5795cca3e3b8a3666c2443441178f6f73b0b540894c00fd7d6a9c2d1ea26f481f6318da19af7e870b598f6baa8c54397a345ac8f20e3df2690ec57e4aa6e84b5eb997eb024cc738410711722d3cca6581974935a809e247cba93253bf357b305f58c6e84b3a6a667ef90126baa325c90a29877870182f9ab5c01dfa6bc074496b6875db6762cabd934127c9c563ed75f8dad6a3e5516304d4a9b24d07fe7980fda5946481ba1d7130e07e43d8f9d9f5aedd74fc78e8ac8a57949a9dc4eda3dd4610529eda39bec2415e6177de4100c1bcb97f033d0de3c21fc9be6e6138af191221f089044ec738f89ca305a15cfa7f3eccddf5e7dc9f09fc7b1352aa23ad535ac03416e5a74f8d4aa18351d2975799209e90baa3c31638d58dc611f3d487d610668af4ed2e3029aad5202ff883f2205836a08b6f537a3c8894eac6b72f2051747c0f89fa8d9d74579a702153e4cd406c8c927f31372c5bd0c06fb1b45f98f64c866fab1632d6f4c7428864dffb0cca8432e13e7e674b1780f7794c3257d2c2bbba06e4a1f0a61a6de521f993f412155862e4b78b0c93c9d3ee789d3258da2e096514ce9c5ba67371fa839727f945bcf46059cc532b764f286d05024ac9f90be3888e0429ffe88f7f824ff3a066f10a2f9be80bcea38874326e4b4cc01928229c3f4e822c01c88a93eb08d315fa682c08abb9d336c15f7458ef796e6207b1d6abc43727e3ea9b9108891d84d6ee7b8d0dccc5cf17aa4d358166d75a6c4b65acf270a2313fa9cf868607e5f1d496873cbe28accf470767b6c9a682c10a8941cbce78ca0d747324811c69ac654b7f95f61f27f2709c09ca4ae645ca033c1882a279d753b70964d570bdfffc251ac8ef8c8eef979c35a078d9176a4ce61922636590b6a4bb8fe4044f1beb1c703944e98b310cd6223ec7aaa293c8bb5ed653d87d781946dd3663c49b0094767eb086a2d39f85f14e7099b6b990ecd9f2d0fb0666d26397b9e04d39f9785a2838130403ebe6ab397c68914ffcd72bd57f18a9b1b973994a384267d069cd5e2e016bfc7b8662d23a0ae2b623dc5a3bcb8ef3a403cb1b9361595374a53463edbeb32fbea368d4f88c155ab26d669e2a04775587069b468fab8fe1954050fe330030ed406dea5a5292d4f9f4b60b6b1bf66e4a8e2f36ea4b72a673575cce6e3e1012caf3160bc01d5a12a2ea9361b926d635448b8cdd12f96d481909eb6751f263a97523180d5ff3975741eb471e624ac0ff36b922c0cc6fe3b6b28a5e1c8872dcb1d77e115f05b55b4a49df8c4f81ab45483bad96fca7e4f1a7a3e763a77602be0a7e1faacb955fbf0e08191219d235056ed0121ab983c315e69b968aea39384c678f952fb3386b5db5ac31487b196b92563bf1703aaaf5233fcb27299f13f89b94bab4a959e296e100c04fff87e8d715cdc52d5072b3d3e38305094b0f85ab9ef7829499dcb1a343681964f16d86b3cda105a4ac15ae045a98cb5bc0deb51b3134776bb716b3542c890e0dec6dbea9ae05261f6e572fc813bf46e87a8b160b7147c5efb616fde351b69ae72afc564ce1fbbc3d371bb4b43154b8bbb3a1085aaf71819512df460398886c09de7c15ed7bace25c928cba60ec312fb3f3b074713ec4845acfde522926418d0911d406769f02182bb67f4218ef77a8008aa86cdfdb1e88dc422e77ce76a88297adcc50b23d21f31f6c0d0e4da23f57145b79b28b524425dfed9175d38107469a3754c49fad3a544f265cc5e1c8229e986e0e2fdbae2d6c46ac63087daea7277ea891a8071eae22c489da25e6ffd0c487d64cf30198f1a845dba044d04a503da093209d76afddd0c2c28da490be6301182ab0c13ad6983038aa9eef659f5f106473bc74a9e61d218dc1e5f144ab7228f7a625f41758c4e807c98154c3f3d734d29762202a8873cba4ec7b8f94b551ab9af144d1572acc0da6f3506deeba2d300ae65ab2aaa0591d235bd63da956a3ce5ab9239aa7e81141e719dceb006930608cdfdaf5e5f25aa606f330fe943fe687ef74b14f1fb2c086af7fecb3c618994d279d3e5db8148828574ae8a8ce62943d7be865661f87366bbab86605ed5064fcec5d445c3fae241aea457fc2e63fe9dc42c177b5eb4b46821ec9ccf2827d84de21b7c5431b80a237cddf0bda6db0e20c84874bd9eb79b9c269f30fd755a20f20c14715ba4c71c9630fc30dbe9b3520314036d379a4e6fb807f3b38ae30098b7c5e208748d32f8d2503765ac9443a9b10ed234a3444b306c5b3de06c7bce083ccdcd2c038042a46aa3bfdcce36df26aea0b389bd1627cd4f8301f90c38722f3e56e17c68bba47946be0742963f9ba8f902b05776b8609cb486892288cbdf7030c4e191d39813229f4f4d767c362c8e33f56147302e0b0ef57530338e3bc3b5345a3f80fe28f9a424e18e000b3a540cf2101bdcfdd25f78920785c3c3fa28eb58a3d426d914fdf8d6b50e6633566be11c00c557584191af259ea7b317a125d8fe0b94ce88c052043e94401075ed9de1f17f530fb1fc8a57bd35e29e5e49b8e979f341258f48924ec7d361644e61faab9fbe9665763da217e244e7df1a6830a41f5495114b722cc886c3920a252e587f7cf1e040a666d5feb80cf6774c95a980aa6ee7aa544c0a30456216a52135f1809dfe59ebd2087c2d0fca6ce43ead5098f14759edd388698c6bfca4ed9dc0353d6fcd0f479c42efcc21d5dd80951dd9bc94bfb1923ffc805e3e1e8a98c5f0df36efc38474605f6789719d16bfc00f5d4c8effa35fefee569cda7e56ccc020bb61e342d22fd9e4aedb86e080234e7facabb84988a5853ce5a927070761b9eae767d2ab9ba5ba99cff476abc33bfd09c2d80efcb1923fda28ceea2df0188797a585ff3ae49e22d12560a426d61674674dcaf4a8bc0604232d932b3991bfb7ec687b92390017e4a1147dbd9c0719c23f63eeb6a76fc64a36995d8330d4dd88b4286ea1f40cc5b15a98120466b1ca7d89a388da75cfa8e7ccb5a69cec3cbf77c10bbec4db6caa7d4d9c21925f937426b11f431e1fd3cc683979cf97540addd68249f15487e9a5cc4b8efd6fbfbcf5dc170c99206a8a6ca2d6a98d1d9de481aa24b093afdeb1f593be9a844b6ea1ecefc64c76ba1c9c7fb6911aae9ef08337f7ac1357e6dd298a5b7728e1d98440e1ba0e5430cc6a879686cd272745d1e5e2dff26174305bac336596497e420c4f59c6718c16449292b911ebce398dcd379af459c62276873b9368471be580b87d352c5e2ef3dc6a5fa100ad00d8f6644b77ad8919b7e3b495c7b2c19e2da0fbc8fc08a15f52f694eea49c9836c03f37ef089a810bc22dfb85c90ec67784cce83d8e1f8b42fc6afda6ba5160bf06e82ebcd001f7c77556e08493c22162a77a47e3cb0cc7f8756ab95f668b26a59f048ea356648d9caa37bb7898a2f58bc7dd48a2dd2e5f69ef16b46c457d583c44643e8231cd87a3a1373a4d3ca013c3c123884a611fc685ae996388f44d2bf2ce3b453d9c397a83eae349770b95dcf9fe59bf5cd7f27b98c3115951d515cd0d8072e2e97461625fb9510fab92c065632d47e19d14a62285af02d39fb2eef20ef613cb864e4a93c4c6344a5520d8b23e479199d394c839c2264f3720dd0a2f7023966e52d9c7c8207aa21c60574bbc27a55f5dab12c64d9d04b26f349ea19dab5ea18fd8d918a3f4cb879808dfd4abd745fba338ae8db1eb64fb3fbbe9be39840b88b6665463bea683447e0ce259af5810b06f8c283eabb8b49b8e4a0a162e0f4476cf15d95850fa8c202aadef4d8c214eaac7a1810d29da6b0cb624a1f101f3cfcb3c820a44c74ba57335521271f218311b8357e6631c83d3e609323ebca0f685ba841d03db84e3dd313ca075820a81baced10e9a63944747e4a9ddc6b7d2d4fdc3283fc6fb85d15b5b77e16a40b6552e228e2fcacd7268e5a1ad98be8d20c22f0f68ed62e32ee2128461acab0c2cf4c6d234119c6aeea2af783ca65a4f8631935426555184901ca9fe3883856bd21d337b94e153e3c008415936d45e6d1bf19cd8c085539cbcffdf81b255bbfa94d4c10712221ecf847eb1b0285f8d372836b861d52c3884abc12913d8f81efba4b9762f0c281a076da75cf1fa94b8087344eef5a3c5dd64eb73f03437f49db98d9e5894054176d598a0262b489787355a76320ab314d657f34b910d3df0da6380960ca3daa619542a48f5828b7cab850585072fdf892014571a0ccc8fa3131ce390b0ea26dd037ab253ee0d1feb7c3a0b92bc8bed8424408db3836ccf046d4d5b6297bc8fcaf8843f9adbd7ee5cec237b62879df03c4aaaf88912b8110c35eb5a3a5dda33c307d815b843c62ef861dd0856205c95c06236512dc8981f73691e0e07a90f82f4f527f2557cff5c88eb15a58e2aa46f873412c61cdf8346d398d7233753d676b04fc3cb7323651b54561bb25f3b7f46fe6a2234d8824c83ae646254e50d44da3f57c0d2bdade27d328fa353b1646b179dc9556930848d27b7263b6ab799957b345a691830e6894c39cc055006d000ca8d877f98086c15b125300fb96c8afd5e0eb7f6a69942a8df703191cbaf334348dd446f70b251cf885892d4fa3840dae43ab830ba4863df56817f6387cb9adb2fbe34e7a3b6e7fd0ac49ec4143a4525e648c9d04eed5a2910e89d935d400da7c6307f939789a57666dba86ce936187cc67203eeb0198bba19a23b93629161249d9b66c5376e8a03c04149b6ae54d1f02425a6cdefb60cda197af58bd9c553fee7fd8abede8a08a8b5786fded29c62db8810203a2a89dabc8eed113f8a6f4e8880e137f8e6b031074547257f9b56eeb0a8a454be18533c87b6c1e240cfd34cb08de086f82b1983d69b65db8ef2a3510d0c8438843f7aa95a79d14091f528e78dee4373fae2b8d773a3c5ca068825c6c61c4fb15509e62f614aff306da8fbb7b4fd0d8135de0419d16dc1053fbecca7de4c2ddd5f98f0ae5d7860c1fe3aea96667ca68c72a4fedc85f05547184c0e36c4a948b98706f2de987131aff776872f4950f136b4fb65fb434f7ce96901aa88fa787f213aabe2850f5e8dd5da5e94d3fdf864ba21955a384028f9e133ce57132223eddaac18d8b255d321bc6d330693605f321b7996023637ecb0e8b36009b0af80eb2f6d6624d4ffb35eb99de82fa44e358f8ad6c825a372ba3aab22db88033f483c04ea5d598410ae55900080ceef40b62d73464c62e013d042586be394eb48e286708c7060fde2e784f9e506d058a37aa0a5088aff47e6b3af52e7d30f272a305d811e46ff1287b1069fd0950bc7c9e25c34e54f80cd88f33f626518d22611faa38ad6bab6ed6405b06be1ea6a162ddfc949df56a2d743f7be07b6892fd35ccaa24f57b8db43183f3a6921b33b12b4f1500d075de348de0ca6740f9f84872d93fabda5cf115d0d5d24f255b97003ea1ff4e894e95ca37323540121a0d82ae4fbb3ed2b037888b1a871a31609a3be66b8b0496a4dcedb123ba7a983e87937a64372cca4956f61d928765e0e11219612614901562ff633e9b98eefe2f8c3dd5e821aae2e680b496774680","isRememberEnabled":false,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"9269c70a22020cdd5055baad903fbebb"};

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
