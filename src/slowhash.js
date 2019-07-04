function cn_slow_hash(data) {
    // ============================
    // 3. Scratchpad Initialization
    // First, the input is hashed using Keccak [KECCAK] with parameters 
    // b = 1600 and c = 512
    var k1buffer = mykeccak256.arrayBufferState(data);
    
    // A scratchpad of 2 097 152 bytes (2 MiB) is allocated.
    var scratchpad = new Uint8Array(2097152);
    
    // The bytes 0..31 of the Keccak final state are
    // interpreted as an AES-256 key [AES]
    var aes1 = new Uint8Array(k1buffer, 0, 32);
    var aesHash = new aesjs.AES(aes1);
    
    // The bytes 64..191
    // are extracted from the Keccak final state and split into 8 blocks of
    // 16 bytes each
    var blocks = []
    for(var i = 0; i < 8; i++) {
        blocks.push(new Uint8Array(k1buffer, 64 + i * 16, 16));
    };
    
    var scratchpadPos = 0;
    for(var i = 0; i < 262144; i++) {
      // Each block is encrypted using the following procedure
      blocks[i % 8] = aesHash.encrypt_rounds(new Uint32Array(k1buffer, 64 + i * 16, 4));
      if (i % 8 == 7) {
        for(var j = 0; j < 8; j++) {
          for(var k = 0; k < 16; k++) {
            scratchpad[scratchpadPos] = blocks[j][k];
            scratchpadPos++;
          }
        }
      }
    }
    
    // ===================
    // 4. Memory-Hard Loop
    // Prior to the main loop, bytes 0..31 and 32..63 of the Keccak state
    // are XORed, and the resulting 32 bytes are used to initialize
    // variables a and b, 16 bytes each
    var first2k1 = new Uint8Array(k1buffer, 0, 64);
    var ab = new Uint8Array(32);
    for(var i = 0; i < 32; i++) {
      ab[i] = first2k1[i] ^ first2k1[i + 32];
    }
    var a = new Uint8Array(ab.buffer, 0, 16);
    var b = new Uint8Array(ab.buffer, 16, 16);
    
    // The main loop is iterated 524,288 times
    for(var i = 0; i < 524288; i++) {
      var scratchpad_address = to_scratchpad_address(a);
      var around = aesHash.encrypt_round(scratchpad.slice(scratchpad_address, scratchpad_address + 16), new Uint32Array(a.buffer));
      scratchpad.set(around, scratchpad_address);
      
      var oldB = b;
      b = scratchpad.slice(scratchpad_address, scratchpad_address + 16);
      scratchpad.set(xor_array_16(oldB, scratchpad.slice(scratchpad_address, scratchpad_address + 16)), scratchpad_address);
      
      a = f8byte_add(a, f8byte_mul(b, scratchpad.slice(scratchpad_address, scratchpad_address + 16)));
      
      var oldA = a;
      a = xor_array_16(a, scratchpad.slice(scratchpad_address, scratchpad_address + 16))
      scratchpad.set(oldA, scratchpad_address);
    }

    // ======================
    // 5. Result Calculation
    // After the memory-hard part, bytes 32..63 from the Keccak state are
    // expanded into 10 AES round keys in the same manner as in the first
    // part.
    var aes2 = new Uint8Array(k1buffer, 32, 32);
    var aesHash2 = new aesjs.AES(aes2);
    
    var t1 = new Uint8Array(k1buffer, 64, 128);
    t1.set(xor_array_128(t1, scratchpad.slice(0, 128)), 0);
    
    var blocks2 = []
    for(var i = 0; i < 8; i++) {
        blocks2.push(new Uint8Array(k1buffer, 64 + i * 16, 16));
    };

    scratchpadPos = 0;
    for(var i = 0; i < 131072; i++) {
      // Each block is encrypted using the following procedure
      blocks2[i % 8] = aesHash2.encrypt_rounds(blocks2[i % 8]);
      if (i % 8 == 7) {
        t1 = new Uint8Array(k1buffer, 64, 128);
        var t2 = scratchpad.slice((i + 1) * 16, (i + 1) * 16 + 128)
        var t3 = xor_array_128(t1, t2)
        t1.set(t3, 0);
        
        var blocks2 = []
        for(var j = 0; j < 8; j++) {
            blocks2.push(new Uint8Array(k1buffer, 64 + j * 16, 16));
        };
      }
    }
    
    // Then, the 2 low-order bits of the first byte of the state are used to
    // select a hash function: 0=BLAKE-256 [BLAKE], 1=Groestl-256 [GROESTL],
    // 2=JH-256 [JH], and 3=Skein-256 [SKEIN]. The chosen hash function is
    // then applied to the Keccak state, and the resulting hash is the
    // output of CryptoNight.
    var lastHashType = t1[0] % 4;
    var result = "";
    var keccakState = new Uint8Array(k1buffer, 0, 200);
    switch(lastHashType) {
        case 0: // BLAKE-256
            var blake = new Blake256();
            blake.update(keccakState);
            result = buf2hex(blake.digest());
            break;
        case 1: // GROESTL-256
            result = groestl.groestl(keccakState, 2);
            break;
        case 2: // JH-256
            result = faultylabs.hash.jh(keccakState, 256, 1600);
            break;
        case 3: // SKEIN-256
            result = halfskein(keccakState);
            break;
    }
    console.log(result);
    return result;
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function f8byte_mul(a, b) {
    // The 8byte_mul function, however, uses only the first 8 bytes of each
    // argument, which are interpreted as unsigned 64-bit little-endian
    // integers and multiplied together. The result is converted into 16
    // bytes, and finally the two 8-byte halves of the result are swapped.
    var lea = new Uint8Array([a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]]);
    var leb = new Uint8Array([b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]]);
    
    var res8 = new Uint8Array(8);
    var carry = 0;
    
    for(var i = 7; i >= 0; i--) {
        // multiply
        carry = 0;
        var res8_1 = new Uint8Array(8);
        for(var j = 7; j >= (7 - i); j--) {
            var m = lea[i] * leb[j] + carry;
            res8_1[j - (7-i)] = m % 0x100;
            carry = Math.floor(m / 0x100);
        }
        
        carry = 0;
        for(var j = 7; j >= 0; j--) {
            var s = res8[j] + res8_1[j] + carry;
            res8[j] = s % 0x100;
            carry = Math.floor(s / 0x100);
        }
    }
    var res = new Uint8Array(16);
    for(var i = 0; i < res8.length; i++) { 
      res[15 - i] = res8[i];
    }
    return res;    
}

function f8byte_add(a, b) {
    // Where, the 8byte_add function represents each of the arguments as a
    // pair of 64-bit little-endian values and adds them together,
    // component-wise, modulo 2^64. The result is converted back into 16
    // bytes.
    var lea1 = new Uint8Array([a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8]]);
    var lea2 = new Uint8Array([a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]]);
    var leb1 = new Uint8Array([b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8]]);
    var leb2 = new Uint8Array([b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]]);
    
    carry = 0;
    var addition1 = new Uint8Array(8);
    for(var i = 7; i >= 0; i--) {
        var s = lea1[i] + leb1[i] + carry;
        addition1[i] = s % 0x100;
        carry = Math.floor(s / 0x100);
    }
    
    carry = 0;
    var addition2 = new Uint8Array(8);
    for(var i = 7; i >= 0; i--) {
        var s = lea2[i] + leb2[i] + carry;
        addition2[i] = s % 0x100;
        carry = Math.floor(s / 0x100);
    }

    var res = new Uint8Array(16);
    for(var i = 0; i < 8; i++) { 
      res[15 - i] = addition1[i];
    }
    for(var i = 0; i < 8; i++) { 
      res[7 - i] = addition2[i];
    }
    return res;    
}

function f8byte_mul_SLOW(a, b) {
    // The 8byte_mul function, however, uses only the first 8 bytes of each
    // argument, which are interpreted as unsigned 64-bit little-endian
    // integers and multiplied together. The result is converted into 16
    // bytes, and finally the two 8-byte halves of the result are swapped.
    var lea = new Uint8Array([a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]]);
    var leb = new Uint8Array([b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]]);
    
    
    var multiple = bufToBn(lea).multiply(bufToBn(leb));
    var multipleArr = bnToBuf(multiple);
    var res = new Uint8Array(16);
    for(var i = 0; i < multipleArr.length; i++) { 
      res[15 - i] = multipleArr[i];
    }
    return res;    
}

function f8byte_add_SLOW(a, b) {
    // Where, the 8byte_add function represents each of the arguments as a
    // pair of 64-bit little-endian values and adds them together,
    // component-wise, modulo 2^64. The result is converted back into 16
    // bytes.
    var lea1 = new Uint8Array([a[15], a[14], a[13], a[12], a[11], a[10], a[9], a[8]]);
    var lea2 = new Uint8Array([a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]]);
    var leb1 = new Uint8Array([b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8]]);
    var leb2 = new Uint8Array([b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]]);
    var addition1 = bufToBn(lea1).add(bufToBn(leb1)).remainder(bigInt('10000000000000000', 16));
    var addition2 = bufToBn(lea2).add(bufToBn(leb2)).remainder(bigInt('10000000000000000', 16));
    var additionArr1 = bnToBuf(addition1);
    var additionArr2 = bnToBuf(addition2);
    var res = new Uint8Array(16);
    for(var i = 0; i < 8; i++) { 
      res[15 - i] = additionArr1[i];
    }
    for(var i = 0; i < 8; i++) { 
      res[7 - i] = additionArr2[i];
    }
    return res;    
}

function bufToBn(u8) {
  var hex = [];

  u8.forEach(function (i) {
    var h = i.toString(16);
    if (h.length % 2) { h = '0' + h; }
    hex.push(h);
  });

  return new bigInt(hex.join(''), 16);
}

function bnToBuf(bn) {
  var hex = bn.toString(16);
  if (hex.length % 2) { hex = '0' + hex; }

  var len = hex.length / 2;
  var u8 = new Uint8Array(len);

  var i = 0;
  var j = 0;
  while (i < len) {
    u8[i] = parseInt(hex.slice(j, j+2), 16);
    i += 1;
    j += 2;
  }

  return u8;
}

function xor_array_128(a, b) {
    var ret = new Uint8Array(128);
    for(var i = 0; i < 128; i++) {
        ret[i] = a[i] ^ b[i];
    }
    return ret;
}

function xor_array_16(a, b) {
    var ret = new Uint8Array(16);
    for(var i = 0; i < 16; i++) {
        ret[i] = a[i] ^ b[i];
    }
    return ret;
}

function xor_array_8(a, b) {
    var ret = new Uint8Array(8);
    for(var i = 0; i < 8; i++) {
        ret[i] = a[i] ^ b[i];
    }
    return ret;
}

function to_scratchpad_address(a) {
    // When a 16-byte value needs to be converted into an address in the scratchpad, it is
    // interpreted as a little-endian integer, and the 21 low-order bits are
    // used as a byte index. However, the 4 low-order bits of the index are
    // cleared to ensure the 16-byte alignment.
    return a[15] << 13
         | a[14] << 5 
         | (a[13] >> 7) << 4;
}