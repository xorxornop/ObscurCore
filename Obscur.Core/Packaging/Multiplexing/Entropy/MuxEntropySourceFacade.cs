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
using Obscur.Core.DTO;

namespace Obscur.Core.Packaging.Multiplexing.Entropy
{
    public class MuxEntropySourceFacade : IMuxEntropySource
    {
        private readonly IMuxEntropySource _sourceImplementation;

        public MuxEntropySourceFacade(bool writing, IPayloadConfiguration payloadConfig)
        {
            if (payloadConfig.EntropyScheme == PayloadMuxEntropyScheme.Preallocation) {
                _sourceImplementation = new PreallocatedMuxEntropySource(writing, payloadConfig.EntropySchemeData);
            } else if (payloadConfig.EntropyScheme == PayloadMuxEntropyScheme.StreamCipherCsprng) {
                var csprngConfig = payloadConfig.EntropySchemeData.DeserialiseDto<StreamCipherCsprngConfiguration>();
                _sourceImplementation = new StreamCipherCsprngMuxEntropySource(csprngConfig);
            } else {
                throw new ConfigurationInvalidException("Unknown payload multiplexer entropy scheme specified.");
            }
        }

        #region IMuxEntropySource Members

        /// <summary>
        /// </summary>
        /// <param name="max">Returned number will be lower than this.</param>
        /// <returns>Zero to positive number under <paramref name="max" />.</returns>
        public int NextPositive(int max)
        {
            if (max < 1)
                throw new ArgumentException();
            return _sourceImplementation.NextPositive(max);
        }

        /// <summary>
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max"></param>
        /// <returns></returns>
        public int NextPositive(int min, int max)
        {
            if (min < 0)
                throw new ArgumentException("Min is less than 0.", "min");
            if (max < 1)
                throw new ArgumentException("Max is less than 1.", "max");
            if (max < min)
                throw new ArgumentException("Min is less than max.");
            return _sourceImplementation.NextPositive(min, max);
        }

        /// <summary>
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max"></param>
        /// <returns></returns>
        public int Next(int min, int max)
        {
            if (max < min)
                throw new ArgumentException("Min is less than max.");
            return _sourceImplementation.Next(min, max);
        }

        /// <summary>
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public void Next(byte[] buffer, int offset, int count)
        {
            if (offset < 0)
                throw new ArgumentException("Offset is less than 0.", "offset");
            if (count < 1)
                throw new ArgumentException("Count is less than 1.", "count");
            if (offset + count < buffer.Length)
                throw new ArgumentException("Offset + count is less than buffer length.");
            if (buffer == null) 
                throw new ArgumentNullException();

            _sourceImplementation.Next(buffer, offset, count);
        }

        #endregion
    }
}
