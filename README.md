ObscurCore
==========

A general purpose, easy to use, highly customisable and extensible encryption and data packaging library.

Thanks
------

To the BouncyCastle project. This work is built heavily on top of theirs, and it likely would not have been possible without it. So - thank you!

Also a big thanks to Marc Gravell for his excellent protobuf-net and its associated precompiler. It is used extensively throughout (especially for the packaging features) and provides great flexibility and performance.

How do I use it?
----------------

First up, a disclaimer:

**This library as it is currently should not be considered production ready and is a work in progress. It is currently in Alpha.**

*It is recommended that you not use the UM1 key agreement scheme (and the manifest cryptography scheme derived from it, UM1Hybrid). It lacks a security feature in the key generation to ensure the the generated keys do not fall into a vulnerable set of parameters. It has not, however, been disabled.*

*****

Now that that's out of the way, here's how you can use it for doing some stuff. Where there is a non-obvious parameter list, the signature of the constructor/method is included as a comment.


ObscurCore Packaging System
---------------------------

**Please note that this part of the API is very, very new and is subject to change (a lot) on its way to a stable release. I'll try to minimise this, but the fact remains.**

This feature is an automated system that acts somewhat like an very paranoid archive format.
It allows you to bundle together collections of data and key agreements/actions [latter not implemented fully].
The contents of the archive are encrypted along with the contents. Each item has its own unique encryption configuration, so you may have plausible deniability by using different keys on different items.

The index of the archive (where all the information about the items in the archive is kept), termed a *manifest*, is encrypted with a choice of schemes: 

+	Symmetric cipher (non-public key; participants must share key securely somehow)
+	UM1-hybrid (public key)
+	Curve25519-UM1-hybrid (public key)

The hybrid schemes derive a key from the public key cryptosystems, derive it further with a KDF, and uses this as the key for a symmetric cipher.
The symmetric-only scheme derives the supplied shared key further with a KDF, and uses this as the key for a symmetric cipher.

The collection of items in the package is termed the "payload". There is a choice of schemes:

+	Simple
+	Frameshift
+	Fabric

Simple just concatenates them together in "random" order. Frameshift does the same but inserts random lengths of bytes before and after each item. Fabric multiplexes "random"-length stripes of each item, mixing them all up.
Fabric is currently disabled in the build as it's unpredictably buggy.

... Obviously, if it were *actually* random, you'd never get your data back. No - rather, "random" is from the output of a stream-cipher-powered CSPRNG.


Here's an example using the packager:

	var mCipher = SymmetricCipherConfigurationFactory.CreateStreamCipherConfiguration(SymmetricStreamCiphers.HC256);

    var preKey = new byte[mCipher.KeySize / 8];
    StratCom.EntropySource.NextBytes(preKey);
    using (var temp = new MemoryStream()) {
    	PackageWriter.WritePackageSymmetric(outStream, temp, manifest, mCipher, preKey);
    }


Functionality exposed through streams
-------------------------------------

### Encryption/decryption ###

	var config = SymmetricCipherConfigurationFactory.CreateBlockCipherConfiguration(SymmetricBlockCiphers.AES,
		BlockCipherModes.CTR, BlockCipherPaddings.None);
	/* SymmetricCryptoStream (Stream target, bool isEncrypting, ISymmetricCipherConfiguration config, byte[] key = null, bool leaveOpen = false) */
	using (var cs = new SymmetricCryptoStream(destStream, true, config, true) ) {
		sourceStream.CopyTo(cs);
	}

These block ciphers are supported:

+	AES,
+	Blowfish
+	Camellia
+	CAST-5
+	CAST-6
+	GOST 28147-89 [disabled]
+	IDEA
+	NOEKEON
+	RC-6
+	Rijndael [disabled]
+	Serpent
+	TripleDES (3DES/DESEDE)
+	Twofish

... in CBC mode (variety of paddings provided), CTR, CFB, OFB, and CTS. There is also GCM and EAX provided for your authenticated encryption/decryption needs.
Paddings available: ISO 10126-2, ISO/IEC 7816-4, PKCS7, TBC, and ANSI X.923.

And these stream ciphers:

+	HC-128
+	HC-256
+	ISAAC [disabled]
+	Rabbit
+	RC-4 [disabled]
+	Salsa20
+	SOSEMANUK
+	VMPC [disabled]
+	VMPC_KSA3 [disabled]


### Hashing and MAC ###

	byte[] hash = null;
	/* HashStream (Stream binding, bool writing, HashFunctions function, ref byte[] output, bool closeOnDispose = true) */
	using (var hs = new HashStream(destStream, true, HashFunctions.BLAKE2B256, hash, true) ) {
		sourceStream.CopyTo(cs);
	}

	byte[] mac = null;
	/* MacStream (Stream binding, bool writing, MACFunctions function, out byte[] output, byte[] key, 
		byte[] salt = null, byte[] config = null, bool closeOnDispose = true) */
	using (var ms = new MacStream(destStream, true, HashFunctions.BLAKE2B256, mac, key, salt, null, true) ) {
		sourceStream.CopyTo(cs);
	}

Here's all the hash functions supported (HashFunctions enumeration) :

+	BLAKE-2B-256
+	BLAKE-2B-384
+	BLAKE-2B-512
+	Keccak-224
+	Keccak-256
+	Keccak-384
+	Keccak-512
+	RIPEMD-160
+	SHA-1
+	SHA-2-256
+	SHA-2-512
+	Tiger
+	Whirlpool

And here's all the MAC functions (MACFunctions enumeration) :

+	BLAKE-2B-256
+	BLAKE-2B-384
+	BLAKE-2B-512
+	Keccak-224
+	Keccak-256
+	Keccak-384
+	Keccak-512
+	*CMAC*
+	*HMAC*

^ With CMAC you can use any symmetric block cipher (see above in Encryption section) with block size of 64 or 128 bits - which is all of them, currently. HMAC can use any hash/digest function. So that expands the selection significantly.


Primitives
----------

### Key derivation ###

	var config = new ScryptConfiguration {
		IterationPower = 16,
		Blocks = 8,
		Parallelism = 2
	};
	var configBytes = StratCom.SerialiseDTO(config).ToArray();
	var derivedKey = Source.DeriveKeyWithKDF(KeyDerivationFunctions.Scrypt, key, salt, outputSizeBits, configBytes);

These are in serious need of a convenience method. It's on the list.


### Key agreements ###

Please note that currently no 3-pass algorithms are implemented. Sorry. It's definitely a desired feature, for that sweet, sweet Perfect Forward Secrecy...
There are, however, implemented UM1-type agreements, which provide unilateral forward secrecy - which is much better than nothing.

There are no convenience methods for key agreements currently, they must be used manually by manipulating the primitives. Fortunately, they're pretty approachable - an example with Curve25519-UM1:

Creating keys:

	var privEntropy = new byte[32];
    StratCom.EntropySource.NextBytes(privEntropy);
    _privateKeySender = Curve25519.CreatePrivateKey(privEntropy);
    _publicKeySender = Curve25519.CreatePublicKey(_privateKeySender);

    StratCom.EntropySource.NextBytes(privEntropy);
    _privateKeyRecipient = Curve25519.CreatePrivateKey(privEntropy);
    _publicKeyRecipient = Curve25519.CreatePublicKey(_privateKeyRecipient);

And calculating shared secret:

    byte[] ephemeral;
    initiatorSS = Curve25519UM1Exchange.Initiate(_publicKeyRecipient, _privateKeySender, out eph);
	responderSS = Curve25519UM1Exchange.Respond(_publicKeySender, _privateKeyRecipient, eph);


Some words on Streams
---------------------

ObscurCore uses stream decorators for I/O, so anything that is derived from the abstract Stream class of the .NET BCL can be plugged into the constructor of an ObscurCore *SymmetricCryptoStream*. This means, in practice, pretty much anything.

Please note that ObscurCore's main stream classes **close on dispose by default**. This means the stream they were bound to on construction (passed in the constructor) will be closed as well, when the wrapping ObscurCore stream is closed/disposed.
Don't make the mistake of thinking stuff isn't working by binding on a MemoryStream and wondering why the data is missing afterward.

The main stream classes have a parameter, closeOnDispose, that conteols this. Set it to **false** if you don't want them to close. They're set to true by default to try and ensure that if they're bound to a FileStream, the OS hooks get disposed of properly.
If you omit it (so it reverts to the default, true), or set it to false, then the stream the SymmetricCryptoStream is bound to (reading from if decrypting, writing to if encrypting) will be closed as well when the SymmetricCryptoStream is closed.

Note: It's good practice to use the **using** block, because it calls Stream.Dispose once you're done writing/reading. It's most important when writing, as block ciphers have different behaviour when writing the last block of data, so disposing the stream lets them know when to do this. If you don't, you'll be missing the final block (which might be ALL your data if you only wrote a little!) in the output. This is a common mistake.
If *using* isn't what you favour, then just call .Dispose() or .Close() when you're all done with the stream.


Recommendations
---------------

The author's recommendations, among block ciphers:
 
+	AES/CTR
+	Serpent/CTR

and in stream ciphers:

+	HC-256
+	SOSEMANUK
+	Salsa20

These all have decent security margins, and with the partial exception of Serpent, are fast.

Advanced
--------

Want to play around with the cryptographic primitives instead? This is not recommended, but you can.
Have a look around the **Source** object. It provides easy instantiation and configuration of the most useful classes.

Some features of ObscurCore are only accessible this way currently, but that's soon to change.

What's next?
------------

The next major planned features is automatic nonce management. 
The idea is that you simply pass in a colelction that conforms to a particular interface (whether this is just a reference to a simple in-memory database that's repopulated from disk on startup, or a *real* database), ObscurCore checks this DB whenever you reference a key, and makes sure it doesn't use the same nonce again when it's using a cryptographic scheme for which this is essential to maintain its security assurances.

... Or you, the reader, could give a suggestion, or code contribution.

Where can I get more information?
---------------------------------

Check out the wiki. Hopefully I'll have filled it out more. Or send me a message.