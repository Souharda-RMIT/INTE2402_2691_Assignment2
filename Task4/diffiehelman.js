const P_DEC =
  "1780119054785422665282375624501599901452321563691206742732744503144428657887370207706" +
  "126952521234630795671567847784664499706507709207278570500096683881440341297452211718185" +
  "060472311500393010799593580673953487170663198022620197149665241350609459137075949565146" +
  "72855690606794135837542707371727429551343320695239";

const G_DEC =
  "1740682075324020951858119801235234365386044907945613509784958310405999534884558231478" +
  "515974089409507253077970949157594923683005742524387610370844734671801488761181030830437" +
  "549851909834726015504946913294880833954923138500003616464826446084923040787218189599990" +
  "56496097769368017749273708962006689187956744210730";

// Converts text into UTF-8 bytes
function utf8Bytes(text) {
  return new TextEncoder().encode(text);
}


function leftRotate(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}


function sha1Hex(message) {
  const msg = utf8Bytes(message);
  const originalBitLength = BigInt(msg.length) * 8n;

  let paddedLength = msg.length + 1;

  while (paddedLength % 64 !== 56) {
    paddedLength++;
  }

  const padded = new Uint8Array(paddedLength + 8);
  padded.set(msg);
  padded[msg.length] = 0x80;

  // Append original message length as 64-bit big-endian integer
  for (let i = 0; i < 8; i++) {
    padded[padded.length - 1 - i] =
      Number((originalBitLength >> BigInt(8 * i)) & 0xffn);
  }

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const w = new Array(80);

  for (let chunk = 0; chunk < padded.length; chunk += 64) {
    for (let i = 0; i < 16; i++) {
      const j = chunk + i * 4;

      w[i] =
        ((padded[j] << 24) |
          (padded[j + 1] << 16) |
          (padded[j + 2] << 8) |
          padded[j + 3]) >>> 0;
    }

    for (let i = 16; i < 80; i++) {
      w[i] = leftRotate(
        w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16],
        1
      );
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let i = 0; i < 80; i++) {
      let f;
      let k;

      if (i < 20) {
        f = ((b & c) | ((~b) & d)) >>> 0;
        k = 0x5a827999;
      } else if (i < 40) {
        f = (b ^ c ^ d) >>> 0;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = ((b & c) | (b & d) | (c & d)) >>> 0;
        k = 0x8f1bbcdc;
      } else {
        f = (b ^ c ^ d) >>> 0;
        k = 0xca62c1d6;
      }

      const temp = (leftRotate(a, 5) + f + e + k + w[i]) >>> 0;

      e = d;
      d = c;
      c = leftRotate(b, 30);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  return [h0, h1, h2, h3, h4]
    .map(word => word.toString(16).padStart(8, "0"))
    .join("");
}


function random160BitHex() {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBigInt(hex) {
  return BigInt("0x" + hex);
}

function decToBigInt(dec) {
  return BigInt(dec);
}


function modPow(base, exponent, modulus) {
  if (modulus === 1n) {
    return 0n;
  }

  let result = 1n;
  base = base % modulus;

  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }

    exponent = exponent / 2n;
    base = (base * base) % modulus;
  }

  return result;
}

function toPaddedHex(value, length = 256) {
  return value.toString(16).padStart(length, "0");
}

function wrap(text, width = 64) {
  const lines = [];

  for (let i = 0; i < text.length; i += width) {
    lines.push(text.slice(i, i + width));
  }

  return lines.join("\n");
}

function computeQ4() {
  const firstName = document.getElementById("firstName").value.trim();
  const surname = document.getElementById("surname").value.trim();
  const studentId = document.getElementById("studentId").value.trim();

  if (!firstName || !surname || !studentId) {
    document.getElementById("output").textContent =
      "Please enter first name, surname, and student ID.";
    return;
  }

  const p = decToBigInt(P_DEC);
  const g = decToBigInt(G_DEC);


  // Part 1: Generate 160-bit random numbers

  const aHex = random160BitHex();
  const bHex = random160BitHex();

  // Extra random numbers for MITM attack demonstration
  const attackerRandom1Hex = random160BitHex();
  const attackerRandom2Hex = random160BitHex();

  // Part 2: x = SHA1(student ID), y = g^x mod p

  const xHex = sha1Hex(studentId);
  const x = hexToBigInt(xHex);
  const y = modPow(g, x, p);


  // Part 3: Diffie-Hellman key establishment
  
  

  const AHex = sha1Hex(aHex + firstName);
  const BHex = sha1Hex(bHex + surname);

  const A = hexToBigInt(AHex);
  const B = hexToBigInt(BHex);

  const gA = modPow(g, A, p);
  const gB = modPow(g, B, p);

  const sharedByVPC = modPow(gB, A, p);
  const sharedByDataCentre = modPow(gA, B, p);


  // Part 4: Man-in-the-Middle attack demonstration


  const M1Hex = sha1Hex(attackerRandom1Hex + "MalloryTo" + firstName);
  const M2Hex = sha1Hex(attackerRandom2Hex + "MalloryTo" + surname);

  const M1 = hexToBigInt(M1Hex);
  const M2 = hexToBigInt(M2Hex);

  const gM1 = modPow(g, M1, p);
  const gM2 = modPow(g, M2, p);

  const vpcMallorySecret = modPow(gM1, A, p);
  const malloryVpcSecret = modPow(gA, M1, p);

  const dataCentreMallorySecret = modPow(gM2, B, p);
  const malloryDataCentreSecret = modPow(gB, M2, p);

  const report =
`Q4 Diffie-Hellman Computation Results
--------------------------------------

Identity values
---------------
VPC name / First name: ${firstName}
Data centre name / Surname: ${surname}
Student ID: ${studentId}

Part 1: 160-bit random number generation
----------------------------------------


a =
${aHex}

b =
${bHex}

Length of a: ${aHex.length} hex characters = 160 bits
Length of b: ${bHex.length} hex characters = 160 bits


Part 2: x = SHA1(student ID), y = g^x mod p
-------------------------------------------
x = SHA1("${studentId}")

x =
${xHex}

y = g^x mod p

y =
${wrap(toPaddedHex(y))}

Part 3: Diffie-Hellman key establishment
----------------------------------------
A = SHA1(a || first name)

A =
${AHex}

B = SHA1(b || surname)

B =
${BHex}

Public value generated by VPC:
g^A mod p =

${wrap(toPaddedHex(gA))}

Public value generated by data centre:
g^B mod p =

${wrap(toPaddedHex(gB))}

Shared secret computed by VPC:
(g^B)^A mod p =

${wrap(toPaddedHex(sharedByVPC))}

Shared secret computed by data centre:
(g^A)^B mod p =

${wrap(toPaddedHex(sharedByDataCentre))}

Do both shared secrets match?
${sharedByVPC === sharedByDataCentre}

Part 4: Man-in-the-Middle attack demonstration
----------------------------------------------
Attacker random value 1 =
${attackerRandom1Hex}

Attacker random value 2 =
${attackerRandom2Hex}

M1 = SHA1(attacker random value 1 || MalloryTo${firstName})

M1 =
${M1Hex}

M2 = SHA1(attacker random value 2 || MalloryTo${surname})

M2 =
${M2Hex}

Fake public value sent by Mallory to VPC:
g^M1 mod p =

${wrap(toPaddedHex(gM1))}

Fake public value sent by Mallory to data centre:
g^M2 mod p =

${wrap(toPaddedHex(gM2))}

Secret computed by VPC with Mallory:
(g^M1)^A mod p =

${wrap(toPaddedHex(vpcMallorySecret))}

Secret computed by Mallory with VPC:
(g^A)^M1 mod p =

${wrap(toPaddedHex(malloryVpcSecret))}

Do VPC and Mallory share the same secret?
${vpcMallorySecret === malloryVpcSecret}

Secret computed by data centre with Mallory:
(g^M2)^B mod p =

${wrap(toPaddedHex(dataCentreMallorySecret))}

Secret computed by Mallory with data centre:
(g^B)^M2 mod p =

${wrap(toPaddedHex(malloryDataCentreSecret))}

Do data centre and Mallory share the same secret?
${dataCentreMallorySecret === malloryDataCentreSecret}
`;

  document.getElementById("output").textContent = report;
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("computeBtn").addEventListener("click", computeQ4);

  // Automatically generate random values and compute once when page loads
  computeQ4();
});
