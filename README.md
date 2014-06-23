ObscurCore
==========

A general purpose, customisable, and extensible encryption and data packaging library.

Thanks
------

To the Legion of the [Bouncy Castle](http://www.bouncycastle.org/).

![BouncyCastle C# logo](http://www.bouncycastle.org/images/csharp_logo.gif)

This work is built heavily on top of theirs, and likely would not have been possible without it. So - thank you very much for your hard work!

Also a big thanks to **Marc Gravell** for his excellent [protobuf-net](https://code.google.com/p/protobuf-net/) and its associated serialisation assembly precompiler. It is used extensively throughout (especially for the packaging features) and provides great flexibility and performance.

And finally, to [LZ4 for .NET](https://lz4net.codeplex.com/). It is used, optionally, for compression of package manifests, where it has excellent speed.


Why use this?
-------------

ObscurCore is designed to make cryptography accessible *and* customisable, supporting advanced schemes.
The packaging system included is a pertinent example of this, fusing together many primitives to create a strong cryptosystem without the developer requiring deep knowledge of the design of such systems. It hopefully also eliminates or at least greatly cuts down on duplication of effort, since many developers end up building similar systems ad-hoc.

If the features offered are insufficient for some particular circumstance, it offers a strong foundation for further extension; most components are abstracted in a way to support this.


How do I use it?
----------------

First up, a disclaimer:

**This library as it is currently should not be considered production ready and is a work in progress. It is currently in Beta.**

*****

Now that that's out of the way, here's how you can use it for doing some stuff!


ObscurCore Packaging System
---------------------------

**Please note that this part of the API is subject to change on its way to a stable release. I'll try to minimise this, but the fact remains. Now it has reached v0.9, it should change very little.**
*****

This feature is an automated system that acts somewhat like an very paranoid archive/packaging format.
It allows you to bundle together collections of data, text, and cryptographic keys. You need not care about the details if you don't want to (conservative defaults are used), but if want to, you can heavily customise.

*Note: If you don't want to use the packager, but are instead interested in the general-purpose crypto, skip this entire section.*


### What does it look like to use? ###

    using (var output = new MemoryStream()) {
    	var package = new Package(key);
    	package.AddFile(filePath);
    	package.Write(output);
    }

you can also add an entire directory (optionally including subdirectories) at once:
    package.AddDirectory(path)
    package.AddDirectory(string path, search : SearchOption.AllDirectories) // including subdirectories


Pretty easy?

You *can* stop reading here, if you have no interest in the technical parts. You really don't need to know, but it might be easier with some knowledge of the technicalities.


### How does it work? ###

At basics, a package consists of a Manifest and Payload. The manifest (a sort of description of contents, an index) is encrypted, as with the actual contents.
The payload consists of items, and each item has its own unique encryption configuration, so you can have plausible deniability by using different keys on different items, and/or including decoy/fake items if needed.
If deniability is not needed, one could use this feature by distributing a package to multiple recipients, with the different items encrypted with recipient-specific keys, so each sees only that which they are able to decrypt.

The manifest is encrypted with a choice of schemes: 

+	Symmetric cipher (participants must share secret key securely somehow)
+	UM1-hybrid (ephemeral-static-static elliptic curve Diffie-Hellman, so-called *Unified Model 1-pass*)

The latter doesn't use a secret key which has to be somehow communicated to the other party, instead you just exchange 'public keys', so named because you don't need to keep them secret.

The hybrid scheme derives a key from the public key cryptosystem, derives it further with a KDF, and uses this as the key for a symmetric cipher.
The symmetric-only scheme derives the supplied shared key further with a KDF, and uses this as the key for a symmetric cipher.

The collection of items in the package is termed the "payload". There is a choice of schemes:

+	Simple
+	Frameshift
+	Fabric [disabled in build until intermittent issues fixed - sorry]

Simple just concatenates them together in varied (or sequential) order.
Frameshift does the same but inserts variable (or fixed) lengths of bytes before and after each item.
Fabric multiplexes variable (or fixed) length stripes of each item, mixing them all up, much like the Rubberhose file system.

Where variable ordering/lengths are used, these are assigned by the use of a cryptographically-secure pseudorandom number generator.

All data is authenticated with a MAC in the **Encrypt-then-MAC (EtM)** scheme, which provides strong verification and minimum information leakage. Upon detection of any alteration, all operations are aborted.


In the code example above/before, the packager performs the following actions automatically...
*	Creates the symmetric-encryption package, the manifest being configured to use XSalsa20 encryption, Keccak-256 (SHA-3-256) key confirmation, Keccak-512 (SHA-3-512) authentication, and Scrypt key derivation
* 	The package is set up with frameshifting payload layout (default) and a Salsa20-based CSPRNG
*	Adds a file to a package with HC-128 encryption (random key & IV, default) and Poly1305-AES EtM authentication (random key and nonce, default). Key confirmation and derivation is not used due to the keys being random and stored in the manifest, in this instance. If keys are to be supplied by recipient, then the defaults are Keccak-256 key confirmation and scrypt key derivation.
*	Derives a package/manifest key (from the supplied one) with Scrypt KDF
*	Writes it out to the output stream


All schemes offer key confirmation capability with a choice between MAC or KDF method.

If a package is recieived from a sender for which you hold multiple keys on file for (whatever kind they may be), all them will be verified with the key confirmation data (if present, which it is by default - generated automatically) to determine the correct one to proceed with.


In future: packages will include the capability to communicate new keys (of any kind), or request invalidation of keys for subsequent communications. For example, you could send a symmetric key for manifests, so as to reduce overhead incurred by public key schemes.




Functionality exposed through streams
-------------------------------------

**Please note the parameter closeOnDispose. If you test these methods using a MemoryStream, and the parameter set to true (by default or explicitly), the stream will be closed, and your data will be missing.**

### Encryption/decryption ###

	var config = CipherConfigurationFactory.CreateBlockCipherConfiguration(BlockCipher.Aes,
		BlockCipherMode.Ctr, BlockCipherPadding.None);
	using (var cs = new CipherStream(destStream, encrypting:true, config, keyBytes, closeOnDispose:false) ) {
		sourceStream.CopyTo(cs);
	}

These block ciphers are supported:

+	AES
+	Blowfish
+	Camellia
+	CAST-5
+	CAST-6
+	IDEA
+	NOEKEON
+	RC-6
+	Serpent
+	Twofish
+	Threefish

... in CTR, CBC mode (variety of paddings provided), CFB, and OFB.
Paddings available for CBC mode: ISO 10126-2, ISO/IEC 7816-4, PKCS7, TBC, and ANSI X.923.

And these stream ciphers:

+	HC-128
+	HC-256
+	Rabbit
+	RC-4 *[disabled; optionally included]*
+	Salsa20
+	ChaCha
+	XSalsa20
+	SOSEMANUK


### Hashing and MAC ###

	byte[] hash = null;
	using (var hs = new HashStream(destStream, writing:true, HashFunction.Blake2B256, out hash, closeOnDispose:true) ) {
		sourceStream.CopyTo(cs);
	}

	byte[] mac = null;
	using (var ms = new MacStream(destStream, writing:true, MacFunction.BlakeB256, out mac, keyBytes, saltBytes:null, config:null, closeOnDispose:true) ) {
		sourceStream.CopyTo(ms);
	}

Here's all the hash/digest functions supported (*HashFunction* enumeration) :

+	BLAKE-2B-256 / 384 / 512
+	Keccak-224 / 256 / 384 / 512 (SHA-3-224 / 256 / 384 / 512)
+	RIPEMD-160
+	SHA-1
+	SHA-2-256 / 512
+	Tiger

And here's all the MAC functions (*MacFunction* enumeration) :

+	BLAKE-2B-256 / 384 / 512
+	Keccak-224 / 256 / 384 / 512 (SHA-3-224 / 256 / 384 / 512)
+	Skein
+	Poly1305
+	*CMAC*
+	*HMAC*

CMAC can use any symmetric block cipher (see above in Encryption section) with a block size of 64 or 128 bits. 
Poly1305 can use any symmetric block cipher (see above in Encryption section) with a block size of 128 bits.
HMAC can use any hash/digest function.


Primitives
----------

### Key derivation ###

	var config = new ScryptConfiguration {
		Iterations = 32768,
		Blocks = 8,
		Parallelism = 2
	};
	var configBytes = config.SerialiseDto();
	byte[] derivedKey = Source.DeriveKeyWithKDF(KeyDerivationFunction.Scrypt, keyBytes, saltBytes, outputSizeBits:256, configBytes);

These are in serious need of a convenience method. It's on the list.


### Key agreements ###

Please note that currently, perfect-forward-secrecy ECDH algorithms (such as 3-pass Full Unified Model; UM3) are not implemented. Sorry!

There are, however, implemented UM1-type agreements, which provide unilateral forward secrecy - which is much better than nothing.

J-PAKE password-authenticated key agreement is also available, using ECC instead of DSA, making for very secure and fast agreements.

Elliptic curves provided are from the Brainpool Consortium, SEC2 (secp and sect curves; also called NIST curves), and Daniel J. Bernstein. These are the most popular choices.


Creating keys:

	var keypair = KeypairFactory.GenerateEcKeypair(DjbCurve.Curve25519.ToString());

And calculating shared secret:

    EcKeyConfiguration ephemeral;
    byte[] initiatorSS = Um1Exchange.Initiate(senderKeypair.ExportPublicKey(), senderKeypair.GetPrivateKey(), out ephemeral);
	byte[] responderSS = Um1Exchange.Respond(receiverKeypair.ExportPublicKey(), receiverKeypair.GetPrivateKey(), ephemeral);


### Signatures ###

No concrete implementation is yet in place. ECDSA is being added - the preferred example of this is Ed25519.
DSA proper (using RSA) will most likely not be added due to concerns with security and efficiency.
Watch this space.


Some words on Streams
---------------------

CipherStream **encrypts only when being written to**, and **decrypts only when being read from**. The other core stream types (for example, the HashStream) do not enforce directionality like this.

ObscurCore uses stream decorators for I/O, so anything that is derived from the abstract Stream class of the .NET BCL can be plugged into the constructor of an ObscurCore *SymmetricCryptoStream/HashStream/MacStream*. This means in practice pretty much anything, since pretty much anything can be serialised to a byte array.

Please note that ObscurCore's main stream classes **close on dispose by default**. The reason for this is to ensure the stream that it's bound to gets closed. Most (all?) of the .NET BCL streams are the same, the difference here is that you get a choice, because you may only want to finish the cipher operation but retain the underlying bound stream(s).

This means the stream they were bound to on construction will be closed with it, when the wrapping ObscurCore stream is closed/disposed.
Don't make the mistake of thinking stuff isn't working when binding on a MemoryStream, and wondering why the data is missing afterward.

The main stream classes have a parameter, *closeOnDispose*, that controls this. Set it to **false** if you *don't* want them to close. They're set to *true* by default to try and ensure that if they're bound to a FileStream, the OS hooks get disposed of properly.

It's good practice to use the **using** block, because it calls Stream.Dispose() once you're done writing/reading. It's most important when writing, as block ciphers have different behaviour when writing the last block of data, so disposing the stream lets it know when to do this. If you don't, **you'll probably be missing the final block** (which might be *all* of your data if you only wrote a little, and are using a block cipher!) in the output. **This is a common mistake.**
If *using* isn't what you favour, then just call .Dispose() or .Close() when you're all done with the stream.


Recommendations
---------------

The author's recommendations, among block ciphers:
 
+	AES in CTR mode
+	Twofish in CTR mode
+	Serpent in CTR mode

and in stream ciphers:

+	XSalsa20
+	HC-128

In hash and MAC functions:

+	Keccak/SHA-3
+	BLAKE2B
+	Poly1305-AES

In KDFs:

+	Scrypt



Where can I get more information?
---------------------------------

Check out the wiki. Hopefully I'll have filled it out some more. Or send me a message.