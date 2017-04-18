# _xorscura_

A tool for simplifying string obfuscation with xor.

_xorscura_ is the command line wrapper for _libxorscura_. This is useful for hiding the true nature of an executable.

## _libxorscura_

_libxorscura_ is a library for handling the normal operations around xor obfuscation of strings. Read the libxorscura.h and .c files for more information.

## Example

	empty@monkey:~$ echo "hello, world" | xorscura 
	plaintext: 68656c6c6f2c20776f726c640a
	seed: 2081836537
	key: a95b2c261058ce0260cb63138c
	cipher: c13e404a7f74ee750fb90f7786

	empty@monkey:~$ xorscura -d -c c13e404a7f74ee750fb90f7786 -k a95b2c261058ce0260cb63138c
	hello, world

	empty@monkey:~$ xorscura -d -c c13e404a7f74ee750fb90f7786 -s 2081836537
	hello, world

## Notes

* _xorscura_ will work on all data, not just strings. Perfect for unpacking binaries directly into memory for execution.
* _xorscura_ uses the thread safe random_r() to generate the encryption key. This means you only need store a ciphertext and the seed in your binary (though using the entire key will also work).
* _libxorscura_ has a built in xorscura_compare() function which performs a bitwise comparison, ensuring your plaintext never exists in memory more than one char at a time.
