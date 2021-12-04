import hmac from "js-crypto-hmac";

export const hash_MD4 = (text, key) => {
  let text_bin = "";

  /* read each character of message and append 0s 
  to complete 16 bits for each character */
  [...text].forEach((c) => {
    let bin = c.charCodeAt().toString(2);
    text_bin += Array(8 - bin.length + 1).join("0") + bin;
  });
  let originalSize = text_bin.length;

  /* append padding bits */
  text_bin += "1";
  let paddedOnce = false;
  while ((text_bin.length + 64) % 512 !== 0 || !paddedOnce) {
    text_bin += "0";
    paddedOnce = true;
  }

  /* append length */
  let originalSizeBin = originalSize.toString(2);
  let md4 = require("js-md4");
  originalSizeBin =
    Array(64 - originalSizeBin.length + 1).join("0") + originalSizeBin;
  text_bin += originalSizeBin;

  /* divide in blocks of 32 bits */
  let size = 32;
  let numBlocks = text_bin.length / size;
  text_bin = md4(text);
  let blocks = new Uint32Array(numBlocks);

  for (let i = 0, o = 0; i < numBlocks; ++i, o += size) {
    blocks[i] = parseInt(text_bin.substr(o, size), 2);
  }

  /* initialize MD buffer */
  let A = 0x67452301;
  let B = 0xefcdab89;
  let C = 0x98badcfe;
  let D = 0x10325476;

  /* process message  */
  /* define 3 auxiliary functions */
  const f = (X, Y, Z) => (X & Y) | (~X & Z);
  const g = (X, Y, Z) => (X & Y) | (X & Z) | (Y & Z);
  const h = (X, Y, Z) => X ^ Y ^ Z;

  /* define round functions */
  const round_1 = (X, A, B, C, D, i, s) => {
    let temp = A + f(B, C, D) + X[i];
    return (temp << s) | (temp >>> (32 - s));
  };
  const round_2 = (X, A, B, C, D, i, s) => {
    let temp = A + g(B, C, D) + X[i] + 0x5a827999;
    return (temp << s) | (temp >>> (32 - s));
  };
  const round_3 = (X, A, B, C, D, i, s) => {
    let temp = A + h(B, C, D) + X[i] + 0x6ed9eba1;
    return (temp << s) | (temp >>> (32 - s));
  };

  let X = new Uint32Array(16);
  for (let i = 0; i < blocks.length / 16; i++) {
    let AA = A;
    let BB = B;
    let CC = C;
    let DD = D;
    for (let j = 0; j < 16; j++) {
      X[j] = blocks[i * 16 + j];
    }

    /* round 1 */
    for (let j = 0; j <= 12; j += 4) {
      A = round_1(X, A, B, C, D, j, 3);
      D = round_1(X, D, A, B, C, j + 1, 7);
      C = round_1(X, C, D, A, B, j + 2, 11);
      B = round_1(X, B, C, D, A, j + 3, 19);
    }

    /* round 2 */
    for (let j = 0; j < 4; j++) {
      A = round_2(X, A, B, C, D, j, 3);
      D = round_2(X, D, A, B, C, j + 4, 5);
      C = round_2(X, C, D, A, B, j + 8, 9);
      B = round_2(X, B, C, D, A, j + 12, 13);
    }

    /* round 3 */
    A = round_3(X, A, B, C, D, 0, 3);
    D = round_3(X, D, A, B, C, 4, 9);
    C = round_3(X, C, D, A, B, 8, 11);
    B = round_3(X, B, C, D, A, 12, 15);
    A = round_3(X, A, B, C, D, 2, 3);
    D = round_3(X, D, A, B, C, 10, 9);
    C = round_3(X, C, D, A, B, 6, 11);
    B = round_3(X, B, C, D, A, 14, 15);
    A = round_3(X, A, B, C, D, 1, 3);
    D = round_3(X, D, A, B, C, 9, 9);
    C = round_3(X, C, D, A, B, 5, 11);
    B = round_3(X, B, C, D, A, 13, 15);
    A = round_3(X, A, B, C, D, 3, 3);
    D = round_3(X, D, A, B, C, 11, 9);
    C = round_3(X, C, D, A, B, 7, 11);
    B = round_3(X, B, C, D, A, 15, 15);

    A += AA;
    B += BB;
    C += CC;
    D += DD;
  }

  return text_bin;
  /* return A.toString(16) + B.toString(16) + C.toString(16) + D.toString(16); */
};

export const hash_MD5 = async (text, key) => {
  let md5 = require("md5");
  if (key.length > 0) {
    let hexString = "";
    return await hmac.compute(key, text, "MD5").then((hmac) => {
      hmac.forEach((num) => {
        hexString += num.toString(16);
      });
      console.log(hmac);
      console.log(hexString);
      return hexString;
    });
  } else return md5(text);
};

export const hash_sha1 = async (text, key) => {
  let sha1 = require("js-sha1");
  if (key.length > 0) {
    let hexString = "";
    return await hmac.compute(key, text, "SHA-1").then((hmac) => {
      hmac.forEach((num) => {
        hexString += num.toString(16);
      });
      console.log(hmac);
      console.log(hexString);
      return hexString;
    });
  } else return sha1(text);
};

export const hash_sha256 = async (text, key) => {
  let sha256 = require("js-sha256");
  if (key.length > 0) {
    let hexString = "";
    return await hmac.compute(key, text, "SHA-256").then((hmac) => {
      hmac.forEach((num) => {
        hexString += num.toString(16);
      });
      console.log(hmac);
      console.log(hexString);
      return hexString;
    });
  } else {
    return sha256(text);
  }
};
