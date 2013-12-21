using System;

namespace ObscurCore.Cryptography.Ciphers.Stream.Primitives
{
#if INCLUDE_ISAAC
	/**
	* Implementation of Bob Jenkin's ISAAC (Indirection Shift Accumulate Add and Count).
	* see: http://www.burtleburtle.net/bob/rand/isaacafa.html
	*/
	public class IsaacEngine
		: IStreamCipher
	{
		// Constants
	    private const int SizeL = 8; // 256

	    private const int StateArraySize = SizeL << 5; // 256

	    // Cipher's internal state
		private uint[]   engineState, // mm                
						results; // randrsl
		private uint     a, b, c;

		// Engine state
		private int     index;
		private byte[]  keyStream     = new byte[StateArraySize<<2], // results expanded into bytes
						workingKey;
		private bool	initialised;

		/**
		* initialise an ISAAC cipher.
		*
		* @param forEncryption whether or not we are for encryption.
		* @param params the parameters required to set up the cipher.
		* @exception ArgumentException if the params argument is
		* inappropriate.
		*/
		public void Init(
			bool				forEncryption, 
			ICipherParameters	parameters)
		{
			if (!(parameters is KeyParameter))
				throw new ArgumentException(
					"invalid parameter passed to ISAAC Init - " + parameters.GetType().Name,
					"parameters");

			/* 
			* ISAAC encryption and decryption is completely
			* symmetrical, so the 'forEncryption' is 
			* irrelevant.
			*/
			KeyParameter p = (KeyParameter) parameters;
			setKey(p.GetKey());
		}

		public byte ReturnByte(
			byte input)
		{
			if (index == 0) 
			{
				isaac();
				keyStream = intToByteLittle(results);
			}

			byte output = (byte)(keyStream[index]^input);
			index = (index + 1) & 1023;

			return output;
		}

		public void ProcessBytes(
			byte[]	input, 
			int		inOff, 
			int		len, 
			byte[]	output, 
			int		outOff)
		{
			if (!initialised)
				throw new InvalidOperationException(AlgorithmName + " not initialised");
			if ((inOff + len) > input.Length)
				throw new DataLengthException("input buffer too short");
			if ((outOff + len) > output.Length)
				throw new DataLengthException("output buffer too short");

			for (int i = 0; i < len; i++)
			{
				if (index == 0) 
				{
					isaac();
					keyStream = intToByteLittle(results);
				}
				output[i+outOff] = (byte)(keyStream[index]^input[i+inOff]);
				index = (index + 1) & 1023;
			}
		}

        // Added by Matthew Ducker to facilitate use as a PRNG
        public void GetKeystream(byte[] output, int offset, int length) {
            if (!initialised)
				throw new InvalidOperationException(AlgorithmName + " not initialised");
            if ((offset + length) > output.Length)
				throw new DataLengthException("output buffer too short");

            for (int i = 0; i < length; i++)
			{
				if (index == 0) 
				{
					isaac();
					keyStream = intToByteLittle(results);
				}
				output[i+offset] = (keyStream[index]);
				index = (index + 1) & 1023;
			}
        }

		public string AlgorithmName
		{
			get { return "ISAAC"; }
		}

		public void Reset()
		{
			setKey(workingKey);
		}

		// Private implementation
		private void setKey(
			byte[] keyBytes)
		{
			workingKey = keyBytes;

			if (engineState == null)
			{
				engineState = new uint[StateArraySize];
			}

			if (results == null)
			{
				results = new uint[StateArraySize];
			}

			int i, j, k;

			// Reset state
			for (i = 0; i < StateArraySize; i++)
			{
				engineState[i] = results[i] = 0;
			}
			a = b = c = 0;

			// Reset index counter for output
			index = 0;

			// Convert the key bytes to ints and put them into results[] for initialization
			byte[] t = new byte[keyBytes.Length + (keyBytes.Length & 3)];
			Array.Copy(keyBytes, 0, t, 0, keyBytes.Length);
			for (i = 0; i < t.Length; i+=4)
			{
				results[i>>2] = byteToIntLittle(t, i);
			}

			// It has begun?
			uint[] abcdefgh = new uint[SizeL];

			for (i = 0; i < SizeL; i++)
			{
				abcdefgh[i] = 0x9e3779b9; // Phi (golden ratio)
			}

			for (i = 0; i < 4; i++)
			{
				mix(abcdefgh);
			}

			for (i = 0; i < 2; i++)
			{
				for (j = 0; j < StateArraySize; j+=SizeL)
				{
					for (k = 0; k < SizeL; k++)
					{
						abcdefgh[k] += (i<1) ? results[j+k] : engineState[j+k];
					}

					mix(abcdefgh);

					for (k = 0; k < SizeL; k++)
					{
						engineState[j+k] = abcdefgh[k];
					}
				}
			}

			isaac();

			initialised = true;
		}    

		private void isaac()
		{
			uint x, y;

			b += ++c;
			for (int i = 0; i < StateArraySize; i++)
			{
				x = engineState[i];
				switch (i & 3)
				{
					case 0: a ^= (a << 13); break;
					case 1: a ^= (a >>  6); break;
					case 2: a ^= (a <<  2); break;
					case 3: a ^= (a >> 16); break;
				}
				a += engineState[(i+128) & 0xFF];
				engineState[i] = y = engineState[(int)((uint)x >> 2) & 0xFF] + a + b;
				results[i] = b = engineState[(int)((uint)y >> 10) & 0xFF] + x;
			}
		}

		private static void mix(uint[] x)
		{
//			x[0]^=x[1]<< 11; x[3]+=x[0]; x[1]+=x[2];
//			x[1]^=x[2]>>> 2; x[4]+=x[1]; x[2]+=x[3];
//			x[2]^=x[3]<<  8; x[5]+=x[2]; x[3]+=x[4];
//			x[3]^=x[4]>>>16; x[6]+=x[3]; x[4]+=x[5];
//			x[4]^=x[5]<< 10; x[7]+=x[4]; x[5]+=x[6];
//			x[5]^=x[6]>>> 4; x[0]+=x[5]; x[6]+=x[7];
//			x[6]^=x[7]<<  8; x[1]+=x[6]; x[7]+=x[0];
//			x[7]^=x[0]>>> 9; x[2]+=x[7]; x[0]+=x[1];
			x[0]^=x[1]<< 11; x[3]+=x[0]; x[1]+=x[2];
			x[1]^=x[2]>>  2; x[4]+=x[1]; x[2]+=x[3];
			x[2]^=x[3]<<  8; x[5]+=x[2]; x[3]+=x[4];
			x[3]^=x[4]>> 16; x[6]+=x[3]; x[4]+=x[5];
			x[4]^=x[5]<< 10; x[7]+=x[4]; x[5]+=x[6];
			x[5]^=x[6]>>  4; x[0]+=x[5]; x[6]+=x[7];
			x[6]^=x[7]<<  8; x[1]+=x[6]; x[7]+=x[0];
			x[7]^=x[0]>>  9; x[2]+=x[7]; x[0]+=x[1];
		}

		private static uint byteToIntLittle(
			byte[]	x,
			int		offset)
		{
			uint result = (byte) x[offset + 3];
			result = (result << 8) | x[offset + 2];
			result = (result << 8) | x[offset + 1];
			result = (result << 8) | x[offset + 0];
			return result;
		}

		private static byte[] intToByteLittle(
			uint x)
		{
			byte[] output = new byte[4];
			output[3] = (byte)x;
			output[2] = (byte)(x >> 8);
			output[1] = (byte)(x >> 16);
			output[0] = (byte)(x >> 24);
			return output;
		} 

		private static byte[] intToByteLittle(
			uint[] x)
		{
			byte[] output = new byte[4*x.Length];
			for (int i = 0, j = 0; i < x.Length; i++,j+=4)
			{
				Array.Copy(intToByteLittle(x[i]), 0, output, j, 4);
			}
			return output;
		}
	}
#endif
}
