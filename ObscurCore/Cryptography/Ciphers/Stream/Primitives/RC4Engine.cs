using System;
using System.Linq;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
#if(INCLUDE_RC4)
    public class Rc4Engine
		: IStreamCipher
    {
        private const int StateLength = 256;

        /*
        * variables to hold the state of the RC4 engine
        * during encryption and decryption
        */

        private byte[]	engineState;
        private int		x;
        private int		y;
        private byte[]	workingKey;

		/// <summary>
		/// Initialise the cipher.
		/// </summary>
		/// <param name="forEncryption">No effect for this cipher.</param>
		/// <param name="encrypting">If set to <c>true</c> encrypting.</param>
		/// <param name="key">Key for the cipher (required).</param>
		/// <param name="iv">Not applicable for this cipher.</param>
		/// <exception cref="ArgumentException">If the parameter argument is invalid (e.g. incorrect length).</exception>
		public void Init (bool encrypting, byte[] key, byte[] iv) {
			if (key == null) 
				throw new ArgumentNullException("key", "RC4 initialisation requires a key.");
			if (!Athena.Cryptography.StreamCiphers[SymmetricStreamCipher.Rc4].AllowableKeySizes.Contains(key.Length * 8))
				throw new ArgumentException("Incompatible key size supplied.", "key");

			SetKey (key);
		}


		public string AlgorithmName
        {
            get { return "RC4"; }
        }

		public int StateSize
		{
			get { return StateLength; }
		}

		public byte ReturnByte(
			byte input)
        {
            x = (x + 1) & 0xff;
            y = (engineState[x] + y) & 0xff;

            // swap
            byte tmp = engineState[x];
            engineState[x] = engineState[y];
            engineState[y] = tmp;

            // xor
            return (byte)(input ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
        }

        public void ProcessBytes(
            byte[]	input,
            int		inOff,
            int		length,
            byte[]	output,
            int		outOff
        )
        {
            if ((inOff + length) > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }

            if ((outOff + length) > output.Length)
            {
                throw new DataLengthException("output buffer too short");
            }

            for (int i = 0; i < length ; i++)
            {
                x = (x + 1) & 0xff;
                y = (engineState[x] + y) & 0xff;

                // swap
                byte tmp = engineState[x];
                engineState[x] = engineState[y];
                engineState[y] = tmp;

                // xor
                output[i+outOff] = (byte)(input[i + inOff]
                        ^ engineState[(engineState[x] + engineState[y]) & 0xff]);
            }
        }

        public void Reset()
        {
            SetKey(workingKey);
        }

        // Private implementation

        private void SetKey(
			byte[] keyBytes)
        {
            workingKey = keyBytes;

            // System.out.println("the key length is ; "+ workingKey.Length);

            x = 0;
            y = 0;

            if (engineState == null)
            {
                engineState = new byte[StateLength];
            }

            // reset the state of the engine
            for (int i=0; i < StateLength; i++)
            {
                engineState[i] = (byte)i;
            }

            int i1 = 0;
            int i2 = 0;

            for (int i=0; i < StateLength; i++)
            {
                i2 = ((keyBytes[i1] & 0xff) + engineState[i] + i2) & 0xff;
                // do the byte-swap inline
                byte tmp = engineState[i];
                engineState[i] = engineState[i2];
                engineState[i2] = tmp;
                i1 = (i1+1) % keyBytes.Length;
            }
        }
    }
#endif
}
