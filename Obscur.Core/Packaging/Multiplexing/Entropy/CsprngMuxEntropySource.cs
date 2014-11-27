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

using Obscur.Core.Cryptography.Entropy;

namespace Obscur.Core.Packaging.Multiplexing.Entropy
{
    public abstract class CsprngMuxEntropySource : IMuxEntropySource
    {
        protected CsPrng EntropySource;

        #region IMuxEntropySource Members

        public int NextPositive(int max)
        {
            return EntropySource.Next(max + 1);
        }

        public int NextPositive(int min, int max)
        {
            return EntropySource.Next(min, max + 1);
        }

        public int Next(int min, int max)
        {
            return EntropySource.Next(min, max + 1);
        }

        public void Next(byte[] buffer, int offset, int count)
        {
            EntropySource.NextBytes(buffer, offset, count);
        }

        #endregion
    }
}
