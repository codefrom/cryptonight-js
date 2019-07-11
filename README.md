# cryptonight-js
Pure JavaScript implementation of CryptoNight hashing algorithm from Monero (and others)

## Thanks to projects
js-sha3 - https://github.com/emn178/js-sha3 (keccak algorithm)

aes-js - https://github.com/ricmoo/aes-js (aes)

groestl-hash-js - https://github.com/QuantumExplorer/groestl-hash-js (groestl)

skein - https://github.com/coiscir/jsdigest (skein algorithm)

JH hash function in Javascript - https://thlg.nl/p/?p=909e18539366b53579cceadbe42d229d (jh)

blake-hash - https://github.com/cryptocoinjs/blake-hash (blake 256)

## History
**11.07.2019** Oh my, I forgot implement variations of algorithm :D

**10.07.2019** Now it's seems to return right results for some tests, but it ... is ... SO ... SLOW ... :D

**08.07.2019** Ok, it's still slow or even slower :'( BUT... hash of empty is valid!!!  And so it seems hash that ending in groestl, gotta check them all now...

**03.07.2019** It is SLOW, it is wrong, so need more work and debugging T_T 
