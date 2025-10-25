const SECRET_2FA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1";  // 2FA Secret provide by HIPAAVault
const DEFAULT_PASSWORD = "SOMEPASSWORD1234";    // consolas sftp password

/**
 * generateTOTP()
 *   Generates a Time-Based One-Time Password (TOTP) based on a Base32-encoded secret.
 *   @param {string} base32Secret - The Base32-encoded secret key (default: STATIC_SECRET).
 *   @param {number} [interval=30] - The time interval in seconds for TOTP validity.
 *   @param {number} [length=6] - The length of the generated TOTP code (1-10 digits).
 *   @param {string} [algorithm="SHA-1"] - The HMAC algorithm to use (SHA-1, SHA-256, SHA-384, or SHA-512).
 *   @returns {Promise<string>} A promise resolving to the generated TOTP code.
 *   @throws {Error} If the interval is < 1, length is invalid, algorithm is unsupported, or Base32 secret contains invalid characters.
 */
async function generateTOTP(base32Secret, interval = 30, length = 6, algorithm = "SHA-1") {
    if (interval < 1) throw new Error("Interval is too short");
    if (length < 1) throw new Error("Length is too low");
    if (length > 10) throw new Error("Length is too high");
    algorithm = algorithm.toUpperCase();
    if (!algorithm.match("SHA-1|SHA-256|SHA-384|SHA-512")) throw new Error("Algorithm not known");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    base32Secret = base32Secret.replace(/=+$/, "");
    let bits = "";
    for (let char of base32Secret) {
        const value = alphabet.indexOf(char.toUpperCase());
        if (value === -1) throw new Error("Invalid Base32 character");
        bits += value.toString(2).padStart(5, "0");
    }
    let bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
        if (bits.length - i >= 8) {
            bytes.push(parseInt(bits.substring(i, i + 8), 2));
        }
    }
    const decodedSecret = new Uint8Array(bytes);
    const timeStamp = Date.now() / 1000;
    const timeCounter = Math.floor(timeStamp / interval);
    const timeHex = timeCounter.toString(16);
    const paddedHex = timeHex.padStart(16, "0");
    const timeBytes = paddedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
    const timeBuffer = new ArrayBuffer(8);
    const timeView = new DataView(timeBuffer);
    for (let i = 0; i < 8; i++) {
        timeView.setUint8(i, timeBytes[i]);
    }
    const key = await crypto.subtle.importKey(
        "raw",
        decodedSecret,
        { name: "HMAC", hash: algorithm },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, timeBuffer);
    const hmac = new Uint8Array(signature);
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binaryCode = 
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    let stringOTP = binaryCode.toString();
    let otp = stringOTP.slice(-length).padStart(length, "0");
    return otp;
}

// Linux cli version (comment out for Bubble)
(async () => {
    const totpValue = await generateTOTP(SECRET_2FA);
    console.log("Generated TOTP:", totpValue);
    console.log("SFTP Password: ", DEFAULT_PASSWORD+totpValue);
    return totpValue;
})();

// Bubble verion: Call the function with 2FA secret provided by HIPAAVault
// return await generateTOTP("samplekey");
