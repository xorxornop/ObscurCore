//
//  Copyright 2013  Matthew Ducker
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

namespace ObscurCore.Information
{
    /// <summary>
    /// Policy for toleration of nonce reuse in a cryptographic scheme.
    /// </summary>
    /// <remarks>
    /// Reuse of a nonce/IV in a scheme that does not allow for it can result in total security failure.
    /// </remarks>
    public enum NonceReusePolicy
    {
        NotApplicable = 0,
        /// <summary>
        /// Nonce reuse may result in total or partial loss of security properties.
        /// </summary>
        NotAllowed,
        /// <summary>
        /// Construction of operation mode allows nonce reuse without catastrophic security loss, 
        /// but better security properties will be obtained by ensuring a new nonce is used each time.
        /// </summary>
        Allowed
    }
}