ObscurCore
==========

A general purpose, easy to use, highly customisable and extensible encryption and data packaging library.

How do I use it?
----------------

First up, an apology, and a disclaimer: The main feature of ObscurCore that really sets it apart from other libraries offering encryption, its packaging features, isn't yet fully operational (though nearly all infrastructure and logic is done) - SORRY! I am working on it, and it is very close! You can check out the payload tests (passing) in ObscurCore.Tests.Packaging.Payload and the payload muxer base class in ObscurCore/Packaging/StreamMux.cs if you're interested.
The payload muxers work just fine, so if you have a side channel where you might communicate serialised PayloadItem objects through (you may use the serialisation contracts defined in ObscurCore.DTO for use with protobuf-net as provided, usable through ObscurCore.StratCom.SerialiseDTO() , or whatever you might prefer instead) you can use these right away.

**This library as it is currently should not be considered production ready and is a work in progress**

*****

Now that that's out of the way, here's how you can use it for doing some encryption:

Import namespaces *ObscurCore* and *ObscurCore.Cryptography* into your codefile you'll be using it in.
ObscurCore uses stream decorators for I/O, so anything that is derived from the abstract Stream class of the .NET BCL can be plugged into the constructor of an ObscurCore *SymmetricCryptoStream*. This means, in practice, pretty much anything.

**Here's how to do things properly** (we're using an old favourite, AES in CTR mode here, and writing into it...) :

	var config = new BlockCipherConfiguration(SymmetricBlockCiphers.AES, BlockCipherModes.CTR,
		BlockCipherPaddings.None);
	using (var cs = new SymmetricCryptoStream(destStream, true, config, true) ) {
		sourceStream.CopyTo(cs);
	}

sourceStream and destStream are your source and destination streams, if that wasn't already obvious.
The first boolean is to designate writing mode.
The last *true* is for leave-open functionality.
If you omit it (so it reverts to the default, false), or set it to false, then the stream the SymmetricCryptoStream is bound to (reading from if decrypting, writing to if encrypting) will be closed as well when the SymmetricCryptoStream is closed.
We've set it to true here in case you're testing the above code fragment with a MemoryStream, which would immediately destroy the data - which would be very confusing!

Note: It's important to use the **using** block, because it calls Stream.Dispose once you're done writing/reading. It's most important when writing, as block ciphers have different behaviour when writing the last block of data, so disposing the stream lets them know when to do this. If you don't, you'll be missing the final block (which might be ALL your data if you only wrote a little!) in the output. If *using* isn't what you favour, then just call .Dispose() when you're all done with the stream.


The author's recommendations, among block ciphers:
 
* AES/CTR
* Serpent/CTR

and in stream ciphers:

* HC-256
* SOSEMANUK
* Salsa20

These all have decent security margins, and with the partial exception of Serpent, are fast.