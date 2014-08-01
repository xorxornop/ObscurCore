using System;
using ObscurCore.Cryptography.Entropy;

namespace ObscurCore.Cryptography.Ciphers.Block.Padding
{
    /// <summary>
    /// Adds ISO10126-2 padding to a block.
    /// </summary>
    public class Iso10126D2Padding: IBlockCipherPadding
    {
        private CsRng _random;
		
        public void Init(CsRng random)
        {
            this._random = random ?? StratCom.EntropySupplier;
        }

        /**
        * Return the name of the algorithm the cipher implements.
        *
        * @return the name of the algorithm the cipher implements.
        */
        public string PaddingName
        {
            get { return "ISO10126-2"; }
        }

		/**
        * add the pad bytes to the passed in block, returning the
        * number of bytes added.
        */
        public int AddPadding(
            byte[]	input,
            int		inOff)
        {
            byte code = (byte)(input.Length - inOff);

            while (inOff < (input.Length - 1))
            {
                input[inOff] = (byte)_random.Next();
                inOff++;
            }

            input[inOff] = code;

            return code;
        }

        /**
        * return the number of pad bytes present in the block.
        */
        public int PadCount(byte[] input)
            //throws InvalidCipherTextException
        {
            int count = input[input.Length - 1] & 0xff;

            if (count > input.Length)
            {
                throw new InvalidCipherTextException("pad block corrupted");
            }

            return count;
        }
    }

}
