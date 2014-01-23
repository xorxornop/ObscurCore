//
//  Copyright 2014  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

namespace ObscurCore.Cryptography.Authentication
{
	/// <summary>
	/// Interface that a Message Authentication Code (MAC) function conforms to.
	/// </summary>
    public interface IMac
    {
		void Init (byte[] key);

        /**
         * Return the name of the algorithm the MAC implements.
         *
         * @return the name of the algorithm the MAC implements.
         */
        string AlgorithmName { get; }

		/**
		 * Return the block size for this MAC (in bytes).
		 *
		 * @return the block size for this MAC in bytes.
		 */
        int MacSize { get; }

        /**
         * add a single byte to the mac for processing.
         *
         * @param in the byte to be processed.
         * @exception InvalidOperationException if the MAC is not initialised.
         */
        void Update(byte input);

		/**
         * @param in the array containing the input.
         * @param inOff the index in the array the data begins at.
         * @param len the length of the input starting at inOff.
         * @exception InvalidOperationException if the MAC is not initialised.
         * @exception DataLengthException if there isn't enough data in in.
         */
        void BlockUpdate(byte[] input, int inOff, int len);

		/**
         * Compute the final stage of the MAC writing the output to the out
         * parameter.
         * <p>
         * doFinal leaves the MAC in the same state it was after the last init.
         * </p>
         * @param out the array the MAC is to be output to.
         * @param outOff the offset into the out buffer the output is to start at.
         * @exception DataLengthException if there isn't enough space in out.
         * @exception InvalidOperationException if the MAC is not initialised.
         */
        int DoFinal(byte[] output, int outOff);

		/**
         * Reset the MAC. At the end of resetting the MAC should be in the
         * in the same state it was after the last init (if there was one).
         */
        void Reset();
    }
}
