default:
	gcc -O2 -o god god.c sha256.c base58.c bech32.c ripemd160.c secp256k1.c cashaddr.c random.c sha3256.c keccak256.c

clean:
	rm -f god

