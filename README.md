# xorscura

A tool and library for string obfuscation using xor.

## What?

A quick tool for generating the hex codes for a key and cyphertext that when xor'd reveal your string.

## Why?

To defeat a quick "strings" analysis of your binary. 

___NOTE:___ xor isn't terribly difficult to reverse. All of the data will be there for a proper RE analyst to see your secrets. 

## How?

* _xorscura_ cli lets you quickly create ciphertext and key to embed in your binary.
* _xorscura_ library allows you to quickly and repeatedly use encrypted strings throughout your code without reinventing the recurring functions.
* _xorscura_ uses the thread safe random_r() to generate the encryption key. This means you only need store a ciphertext and the uint seed in your binary (though using the entire key will also work).
* _xorscura_ library has a built in xorscura_compare() function which performs a bitwise comparison, ensuring your plaintext never exists in memory more than one char at a time.
* _xorscura_ will work on all data, not just strings. Perfect for unpacking binaries directly into memory for execution.
