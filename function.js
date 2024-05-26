function toBase32(input) {
    const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    let base32 = "";

    for(let i = 0; i < input.length; i++) {
        let binary = input.charCodeAt(i).toString(2);
        bits += binary.padStart(8, '0');
    }

    for(let i = 0; i+5 <= bits.length; i+=5) {
        let chunk = bits.substr(i, 5);
        base32 += base32Chars[parseInt(chunk, 2)];
    }

    return base32;
}

async function totp(secret, interval = 30) {
    const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bin = '';
    for (let i = 0; i < secret.length; i++) {
        let index = base32Chars.indexOf(secret[i]);
        if (index === -1) {
            throw new Error('Invalid character');
        }
        bin += index.toString(2).padStart(5, '0');
    }
    let hex = parseInt(bin, 2).toString(16);
    let decodedSecret = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    let timestamp = Math.floor(new Date().getTime() / 1000 / interval);
    let msg = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        msg[7 - i] = timestamp & 0xff;
        timestamp >>= 8;
    }

    const cryptoKey = await window.crypto.subtle.importKey(
        "raw", 
        decodedSecret, 
        { name: "HMAC", hash: "SHA-1" }, 
        false, 
        ["sign"]
    );

    const hash = new Uint8Array(await window.crypto.subtle.sign("HMAC", cryptoKey, msg));
    const offset = hash[hash.length - 1] & 0xf;
    const binary = ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff);
    return binary % 1000000;
}