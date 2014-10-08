using System;
using PerfCopy;

namespace ObscurCore.Cryptography.Ciphers.Block.Modes
{
	/// <summary>
	/// Implements Output FeedBack (OFB; also called Segmented Integer Counter, SIC) mode on top of a block cipher.
	/// </summary>
	public class CtrBlockCipher : BlockCipherModeBase
	{
		private readonly byte[] 	_counter;
		private readonly byte[] 	_counterOut;

		public CtrBlockCipher(BlockCipherBase cipher) : base(BlockCipherMode.Ctr, cipher)
		{
			_counter = new byte[CipherBlockSize];
            _counterOut = new byte[CipherBlockSize];
		}

        /// <inheritdoc />
	    protected override void InitState(byte[] key)
	    {
            Reset();
            BlockCipher.Init(true, key); // Streaming mode - cipher always used in encryption mode
	    }

        /// <inheritdoc />
	    internal override int ProcessBlockInternal(byte[] input, int inOff, byte[] output, int outOff)
	    {
            BlockCipher.ProcessBlock(_counter, 0, _counterOut, 0);

            // XOR the counterOut with the plaintext producing the cipher text
            input.XorInternal(inOff, _counterOut, 0, output, outOff, CipherBlockSize);

            // Increment the counter
            int j = CipherBlockSize;
            while (--j >= 0 && ++_counter[j] == 0) { }

            return CipherBlockSize;
	    }

        /// <inheritdoc />
	    public override void Reset()
		{
            IV.DeepCopy_NoChecks(0, _counter, 0, CipherBlockSize);
            BlockCipher.Reset();
		}
	}
}
