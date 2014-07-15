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

namespace ObscurCore.Cryptography.Ciphers.Information
{
    /// <summary>
    ///     Policy for toleration of nonce reuse in a cryptographic scheme.
    /// </summary>
    /// <remarks>
    ///     CAUTION: Nonce reuse may result in total or partial loss of security properties for past, present, and future data,
    ///     unless it is quite specifically allowed.
    /// </remarks>
    public enum NoncePolicy
    {
        NotApplicable = 0,

        /// <summary>
        ///     Construction of operation mode allows nonce reuse without catastrophic security loss,
        ///     but better security properties will be almost certainly be obtained by ensuring that
        ///     a new nonce is used each instance.
        /// </summary>
        ReuseAllowed,

        /// <summary>
        ///     A sequential or patterned non-repeating (with respect to keys used with it previously)
        ///     counter scheme may be used for nonce selection/generation.
        /// </summary>
        /// <remarks>
        ///     CAUTION: Nonce reuse may result in total or partial loss of security properties for past, present, and future data.
        /// </remarks>
        CounterAllowed,

        /// <summary>
        ///     A random, unique (with respect to keys used with it previously) nonce must be used each instance.
        /// </summary>
        /// <remarks>
        ///     CAUTION: Nonce reuse may result in total or partial loss of security properties for past, present, and future data.
        /// </remarks>
        RequireRandom
    }
}
