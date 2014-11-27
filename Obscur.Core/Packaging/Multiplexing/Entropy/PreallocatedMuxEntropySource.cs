#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using System;
using System.IO;
using Obscur.Core.Cryptography.Entropy;

namespace Obscur.Core.Packaging.Multiplexing.Entropy
{
    public sealed class PreallocatedMuxEntropySource : IMuxEntropySource
    {
        private readonly CsRng _entropySource = StratCom.EntropySupplier;
        private readonly MemoryStream _preallocatedStream;
        private readonly bool _writing;

        public PreallocatedMuxEntropySource(bool writing, byte[] preallocatedData)
        {
            _writing = writing;
            _preallocatedStream = new MemoryStream(preallocatedData, writable:false);
        }

        #region IMuxEntropySource Members

        /// <summary>
        /// </summary>
        /// <returns></returns>
        public int NextPositive(int max)
        {
            return NextPositive(0, max);
        }

        /// <summary>
        /// </summary>
        /// <returns></returns>
        public int NextPositive(int min, int max)
        {
            int val;
            try {
                val = (int) _preallocatedStream.ReadUInt32();
            } catch (Exception e) {
                throw new InvalidDataException("Insufficient preallocated entropy data.", e);
            }
            if (val.IsBetween(min, max) == false) {
                throw new InvalidDataException(
                    "Preallocated entropy data for payload multiplexer contains an invalid entry.");
            }
            return val;
        }

        /// <summary>
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max"></param>
        /// <returns></returns>
        public int Next(int min, int max)
        {
            int val;
            try {
                val = _preallocatedStream.ReadInt32();
            } catch (Exception e) {
                throw new InvalidDataException("Insufficient preallocated entropy data.", e);
            }
            if (val.IsBetween(min, max) == false) {
                throw new InvalidDataException(
                    "Preallocated entropy data for payload multiplexer contains an invalid entry.");
            }
            return val;
        }

        public void Next(byte[] buffer, int offset, int count)
        {
            if (_writing) {
                _entropySource.NextBytes(buffer, offset, count);
            } else {
                throw new InvalidOperationException();
            }
        }

        #endregion
    }
}
