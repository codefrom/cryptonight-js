var bench_s = new Date();
var bench_e = new Date();
var bench_b = 1;
var bench_bnames = {};

function getBench() {
    bench_e = new Date();
    var t = (bench_e-bench_s);
    console.log("BENCH #" + bench_b + " : " + t);
    bench_b++;
    bench_s = new Date();
    return t;
}

function getBenchByName(name) {
    if (!(name in bench_bnames))
        bench_bnames[name] = { time : 0, count : 0 };
    bench_e = new Date();
    var t = (bench_e-bench_s);
    bench_bnames[name].time += t;
    bench_bnames[name].count++;
    bench_s = new Date();
}

function showBenchsByName() {
    console.log(bench_bnames);
}

function cn_slow_hash(data) {
    // ============================
    // 3. Scratchpad Initialization
    // First, the input is hashed using Keccak [KECCAK] with parameters 
    // b = 1600 and c = 512
    var keccak = mykeccak256.arrayBufferState(data);
    var k1buffer = keccak.arrayBufferState();
    
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
        blocks.push(new Uint8Array(k1buffer, 64 + i * 16, 16).slice());
    };
    getBench();
    
    var scratchpadPos = 0;
    for(var i = 0; i < 262144; i++) {
      // Each block is encrypted using the following procedure
      aesHash.encrypt_rounds(new Uint32Array(blocks[i % 8].buffer));
      if (i % 8 == 7) {
        for(var j = 0; j < 8; j++) {
          for(var k = 0; k < 16; k++) {
            scratchpad[scratchpadPos] = blocks[j][k];
            scratchpadPos++;
          }
        }
      }
    }
    getBench();
    
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
      getBenchByName("loopstart");
      var scratchpad_address = to_scratchpad_address(a);
      getBenchByName("0_scratchpad_address");
      aesHash.encrypt_round(new Uint32Array(scratchpad.buffer, scratchpad_address, 4), new Uint32Array(a.buffer));
      getBenchByName("1_aes");
      
      var oldB = b;
      b = scratchpad.slice(scratchpad_address, scratchpad_address + 16);
      scratchpad.set(xor_array_16(oldB, b), scratchpad_address);
      getBenchByName("2_b");
      
      scratchpad_address = to_scratchpad_address(b)
      var mul = f8byte_mul(new Uint16Array(b.buffer), new Uint16Array(scratchpad.buffer, scratchpad_address, 4));
      getBenchByName("3_a_mul");
      a = f8byte_add(a, mul);
      getBenchByName("3_a_add");
      
      var oldA = a;
      a = xor_array_16(a, scratchpad.slice(scratchpad_address, scratchpad_address + 16))
      scratchpad.set(oldA, scratchpad_address);
      getBenchByName("4_a");
      getBenchByName("loopsfinish");
    }
    showBenchsByName();

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
        blocks2.push(new Uint8Array(k1buffer, 64 + i * 16, 16).slice());
    };

    scratchpadPos = 0;
    for(var i = 0; i < 131072; i++) {
      // Each block is encrypted using the following procedure
      blocks2[i % 8] = aesHash2.encrypt_rounds(new Uint32Array(blocks2[i % 8].buffer));
      if (i % 8 == 7) {
        for(var j = 0; j < 8; j++) {
          t1.set(blocks2[j], j * 16);
        }          
        var t2 = scratchpad.slice((i + 1) * 16, (i + 1) * 16 + 128)
        var t3 = xor_array_128(t1, t2)
        t1.set(t3, 0);
        
        blocks2 = []
        for(var j = 0; j < 8; j++) {
            blocks2.push(new Uint8Array(k1buffer, 64 + j * 16, 16).slice());
        };
      }
    }
    getBench();
    
    // After XORing with the last 128 bytes of the scratchpad, the result is
    // encrypted the last time, and then the bytes 64..191 in the Keccak
    // state are replaced with the result. 
    // Then, the Keccak state is passed
    // through Keccak-f (the Keccak permutation) with b = 1600.
    keccak.s = new Int32Array(k1buffer);
    var k2buffer = keccak.permutation();
    
    // Then, the 2 low-order bits of the first byte of the state are used to
    // select a hash function: 0=BLAKE-256 [BLAKE], 1=Groestl-256 [GROESTL],
    // 2=JH-256 [JH], and 3=Skein-256 [SKEIN]. The chosen hash function is
    // then applied to the Keccak state, and the resulting hash is the
    // output of CryptoNight.
    var keccakState = new Uint8Array(k2buffer, 0, 200);
    var lastHashType = keccakState[0] & 3;
    var result = "";
    getBench();
    switch(lastHashType) {
        case 0: // BLAKE-256
            var blake = new Blake256();
            blake.update(keccakState);
            result = buf2hex(blake.digest());
            break;
        case 1: // GROESTL-256
            result = buf2hex(groestl.groestl(keccakState));
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

function swap32(val) {
    return ((val & 0xFF) << 24)
           | ((val & 0xFF00) << 8)
           | ((val >> 8) & 0xFF00)
           | ((val >> 24) & 0xFF);
}

function f8byte_mul(lea, leb) {
    // The 8byte_mul function, however, uses only the first 8 bytes of each
    // argument, which are interpreted as unsigned 64-bit little-endian
    // integers and multiplied together. The result is converted into 16
    // bytes, and finally the two 8-byte halves of the result are swapped.
    // var lea = new Uint16Array(a.buffer);
    // var leb = new Uint16Array(b.buffer);

    var res16 = new Uint16Array(8);
    var carry = 0;
    
    for(var i = 0; i < 4; i++) {
        // multiply
        carry = 0;
        for(var j = 0; j < 4; j++) {
            var m = lea[i] * leb[j] + carry;
            var s = res16[j + i] + m;
            res16[j + i] = s & 0xFFFF;
            carry = s >>> 16;
        }
        var ind = 4 + i;
        while(carry > 0 && ind < 8) {
            var s = res16[ind] + carry;
            res16[ind] = s & 0xFFFF;
            carry = s >>> 16;
            ind++;
        }
    }
    // swapping 8 bytes...
    var res32 = new Uint32Array(res16.buffer);
    var temp1 = res32[0];
    var temp2 = res32[1];
    res32[0] = res32[2];
    res32[1] = res32[3];
    res32[2] = temp1;
    res32[3] = temp2;
    return new Uint8Array(res16.buffer);
}

function f8byte_mul_SLOW2(a, b) {
    // The 8byte_mul function, however, uses only the first 8 bytes of each
    // argument, which are interpreted as unsigned 64-bit little-endian
    // integers and multiplied together. The result is converted into 16
    // bytes, and finally the two 8-byte halves of the result are swapped.
    var lea = new Uint8Array([0,0,0,0,0,0,0,0,a[7], a[6], a[5], a[4], a[3], a[2], a[1], a[0]]);
    var leb = new Uint8Array([0,0,0,0,0,0,0,0,b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]]);

    var res8 = new Uint8Array(16);
    var carry = 0;
    
    for(var i = 15; i >= 0; i--) {
        // multiply
        carry = 0;
        var res8_1 = new Uint8Array(16);
        for(var j = 15; j >= (15 - i); j--) {
            var m = lea[i] * leb[j] + carry;
            res8_1[j - (15-i)] = m % 0x100;
            carry = Math.floor(m / 0x100);
        }
        
        carry = 0;
        for(var j = 15; j >= 0; j--) {
            var s = res8[j] + res8_1[j] + carry;
            res8[j] = s % 0x100;
            carry = Math.floor(s / 0x100);
        }
    }

    var res = new Uint8Array(16);
    for(var i = 0; i < res8.length; i++) { 
      res[i] = res8[(i >> 3) * 8 + (7 - i % 8)];
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
    return (a[0] >> 4) << 4
         | (a[1] << 8)
         |((a[2] & 0x1F) << 16)
}