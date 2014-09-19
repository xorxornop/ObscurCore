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

using ObscurCore.Cryptography.Ciphers;
using ObscurCore.Cryptography.Ciphers.Stream;
using ObscurCore.Cryptography.Entropy.Primitives;
using ObscurCore.DTO;

namespace ObscurCore.Cryptography.Entropy
{
    /// <summary>
    ///     Instantiator for CSPRNGs.
    /// </summary>
    public static class CsPrngFactory
    {
        public static CsPrng CreateCsprng(StreamCipherCsprngConfiguration config)
        {
            var streamCipherEnum = config.CipherName.ToEnum<StreamCipher>();
            StreamCipherEngine streamCipher = CipherFactory.CreateStreamCipher(streamCipherEnum);
            var csprng = new StreamCsPrng(streamCipher, config.Key, config.Nonce);

            return csprng;
        }

        public static StreamCipherCsprngConfiguration CreateStreamCipherCsprngConfiguration
            (CsPseudorandomNumberGenerator cipherEnum)
        {
            return StreamCsPrng.CreateRandomConfiguration(cipherEnum);
        }
    }
}
