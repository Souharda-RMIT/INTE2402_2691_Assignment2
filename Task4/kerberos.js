
// timestamp: 2026-05-02T10:00:00

function hexToBytes(hex) {
    hex = hex.replace(/\s/g, "").toLowerCase();
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function bytesToHex(bytes) {
    return bytes.map(b => b.toString(16).padStart(2, "0")).join("");
}

function stringToBytes(str) {
    return Array.from(new TextEncoder().encode(str));
}

function bytesToString(bytes) {
    return new TextDecoder().decode(new Uint8Array(bytes));
}

function xorBlock(a, b) {
    return a.map((v, i) => v ^ b[i]);
}

function pkcs7Pad(bytes) {
    const pad = 16 - (bytes.length % 16);
    return bytes.concat(Array(pad).fill(pad));
}

function pkcs7Unpad(bytes) {
    const pad = bytes[bytes.length - 1];
    return bytes.slice(0, bytes.length - pad);
}

const sBox = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

const invSBox = new Array(256);
for (let i = 0; i < 256; i++) {
    invSBox[sBox[i]] = i;
}

const rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];

function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        const hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

function keyExpansion(key) {
    const w = key.slice();
    let bytesGenerated = 16;
    let rconIter = 1;

    while (bytesGenerated < 176) {
        let temp = w.slice(bytesGenerated - 4, bytesGenerated);

        if (bytesGenerated % 16 === 0) {
            temp.push(temp.shift());
            temp = temp.map(b => sBox[b]);
            temp[0] ^= rcon[rconIter++];
        }

        for (let i = 0; i < 4; i++) {
            w[bytesGenerated] = w[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }

    return w;
}

function addRoundKey(state, roundKey) {
    for (let i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

function subBytes(state) {
    for (let i = 0; i < 16; i++) {
        state[i] = sBox[state[i]];
    }
}

function invSubBytes(state) {
    for (let i = 0; i < 16; i++) {
        state[i] = invSBox[state[i]];
    }
}

function shiftRows(s) {
    const t = s.slice();
    s[1]=t[5]; s[5]=t[9]; s[9]=t[13]; s[13]=t[1];
    s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6];
    s[3]=t[15]; s[7]=t[3]; s[11]=t[7]; s[15]=t[11];
}

function invShiftRows(s) {
    const t = s.slice();
    s[1]=t[13]; s[5]=t[1]; s[9]=t[5]; s[13]=t[9];
    s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6];
    s[3]=t[7]; s[7]=t[11]; s[11]=t[15]; s[15]=t[3];
}

function mixColumns(s) {
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a = s.slice(i, i + 4);
        s[i]   = gmul(a[0],2) ^ gmul(a[1],3) ^ a[2] ^ a[3];
        s[i+1] = a[0] ^ gmul(a[1],2) ^ gmul(a[2],3) ^ a[3];
        s[i+2] = a[0] ^ a[1] ^ gmul(a[2],2) ^ gmul(a[3],3);
        s[i+3] = gmul(a[0],3) ^ a[1] ^ a[2] ^ gmul(a[3],2);
    }
}

function invMixColumns(s) {
    for (let c = 0; c < 4; c++) {
        const i = c * 4;
        const a = s.slice(i, i + 4);
        s[i]   = gmul(a[0],14) ^ gmul(a[1],11) ^ gmul(a[2],13) ^ gmul(a[3],9);
        s[i+1] = gmul(a[0],9) ^ gmul(a[1],14) ^ gmul(a[2],11) ^ gmul(a[3],13);
        s[i+2] = gmul(a[0],13) ^ gmul(a[1],9) ^ gmul(a[2],14) ^ gmul(a[3],11);
        s[i+3] = gmul(a[0],11) ^ gmul(a[1],13) ^ gmul(a[2],9) ^ gmul(a[3],14);
    }
}

function aesEncryptBlock(block, key) {
    const state = block.slice();
    const expandedKey = keyExpansion(key);

    addRoundKey(state, expandedKey.slice(0, 16));

    for (let round = 1; round <= 9; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey.slice(round * 16, round * 16 + 16));
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey.slice(160, 176));

    return state;
}

function aesDecryptBlock(block, key) {
    const state = block.slice();
    const expandedKey = keyExpansion(key);

    addRoundKey(state, expandedKey.slice(160, 176));

    for (let round = 9; round >= 1; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expandedKey.slice(round * 16, round * 16 + 16));
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expandedKey.slice(0, 16));

    return state;
}

function aesCbcEncrypt(plainBytes, keyHex, ivHex) {
    const key = hexToBytes(keyHex);
    let previous = hexToBytes(ivHex);
    const padded = pkcs7Pad(plainBytes);
    let cipher = [];

    for (let i = 0; i < padded.length; i += 16) {
        const block = padded.slice(i, i + 16);
        const xored = xorBlock(block, previous);
        const encrypted = aesEncryptBlock(xored, key);
        cipher = cipher.concat(encrypted);
        previous = encrypted;
    }

    return cipher;
}

function aesCbcDecrypt(cipherBytes, keyHex, ivHex) {
    const key = hexToBytes(keyHex);
    let previous = hexToBytes(ivHex);
    let plain = [];

    for (let i = 0; i < cipherBytes.length; i += 16) {
        const block = cipherBytes.slice(i, i + 16);
        const decrypted = aesDecryptBlock(block, key);
        const original = xorBlock(decrypted, previous);
        plain = plain.concat(original);
        previous = block;
    }

    return pkcs7Unpad(plain);
}

function runKerberos() {
    const C = "Souharda";
    const S = "Shraban";
    const studentID = "s4118798";

    const KC = "26c6867eb2e659318202045650cd2132";
    const KS = "9371f1adf9c69490934f86977fc9a916";
    const KCS = "00112233445566778899aabbccddeeff";
    const sk = "11223344556677889900aabbccddeeff";
    const IV = "00000000000000000000000000000000";

    const Lt = "8 hours";
    const ts = "2026-05-02T10:00:00";
    const nC = "aeee3683f994e22130d378341c7a687c";

    const ticketPlain = `KCS=${KCS};C=${C};S=${S};Lt=${Lt}`;
    const ticketHex = bytesToHex(aesCbcEncrypt(stringToBytes(ticketPlain), KS, IV));

    const phase1Plain = `KCS=${KCS};S=${S};Lt=${Lt};nC=${nC};ticket=${ticketHex}`;
    const phase1Hex = bytesToHex(aesCbcEncrypt(stringToBytes(phase1Plain), KC, IV));

    const authPlain = `C=${C};ts=${ts}`;
    const authHex = bytesToHex(aesCbcEncrypt(stringToBytes(authPlain), KCS, IV));

    const serverPlain = `ts=${ts};sk=${sk}`;
    const serverHex = bytesToHex(aesCbcEncrypt(stringToBytes(serverPlain), KCS, IV));

    const decTicket = bytesToString(aesCbcDecrypt(hexToBytes(ticketHex), KS, IV));
    const decAuth = bytesToString(aesCbcDecrypt(hexToBytes(authHex), KCS, IV));
    const decServer = bytesToString(aesCbcDecrypt(hexToBytes(serverHex), KCS, IV));

    document.getElementById("output").textContent =
`DERIVED VALUES
C = ${C}
S = ${S}
Student ID = ${studentID}
Lt = ${Lt}
ts = ${ts}

KC = MD5(C || studentID) = ${KC}
KS = MD5(S || studentID) = ${KS}
nC = MD5(C) = ${nC}
KCS = ${KCS}
sk = ${sk}
IV = ${IV}

PHASE 1
Ticket plaintext = ${ticketPlain}
Ticket = E_KS(Ticket plaintext) =
${ticketHex}

AS response plaintext = ${phase1Plain}
AS response = E_KC(AS response plaintext) =
${phase1Hex}

PHASE 2
Authenticator plaintext = ${authPlain}
Authenticator = E_KCS(Authenticator plaintext) =
${authHex}

Server confirmation plaintext = ${serverPlain}
Server confirmation = E_KCS(Server confirmation plaintext) =
${serverHex}

DECRYPTION CHECKS
Decrypted ticket using KS = ${decTicket}
Decrypted authenticator using KCS = ${decAuth}
Decrypted server confirmation using KCS = ${decServer}`;
}