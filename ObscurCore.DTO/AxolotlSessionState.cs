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

using System.Collections.Generic;
using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
	public class AxolotlSessionState
	{
		/// <summary>
		///     RK
		/// </summary>
		[ProtoMember(1)]
		public byte[] RootKey { get; set; }

		/// <summary>
		///     HKs
		/// </summary>
        [ProtoMember(2)]
        public byte[] HeaderKeySend { get; set; }

		/// <summary>
		///     HKr
		/// </summary>
        [ProtoMember(3)]
        public byte[] HeaderKeyReceive { get; set; }

		/// <summary>
		///     NHKs
        /// </summary>
        [ProtoMember(4)]
		public byte[] NextHeaderKeySend { get; set; }

		/// <summary>
		///     NHKr
        /// </summary>
        [ProtoMember(5)]
		public byte[] NextHeaderKeyReceive { get; set; }

		/// <summary>
		///     CKs
		/// </summary>
		/// <remarks>
		///     Used for updating future secrecy.
        /// </remarks>
        [ProtoMember(6)]
		public byte[] ChainKeySend { get; set; }

		/// <summary>
		///     CKr
		/// </summary>
        /// <remarks>
        ///     Used for updating future secrecy.
        /// </remarks>
        [ProtoMember(7)]
		public byte[] ChainKeyReceive { get; set; }

		/// <summary>
		///     DHIs
        /// </summary>
        [ProtoMember(8)]
		public byte[] IdentityKeySend { get; set; }

		/// <summary>
		///     DHIr
        /// </summary>
        [ProtoMember(9)]
		public byte[] IdentityKeyReceive { get; set; }

		/// <summary>
		///     DHRs
        /// </summary>
        [ProtoMember(10)]
		public byte[] RatchetKeySend { get; set; }

		/// <summary>
		///     DHRr
        /// </summary>
        [ProtoMember(11)]
		public byte[] RatchetKeyReceive { get; set; }

		/// <summary>
		///     Ns : 
        ///     Reset to 0 with each new ratchet.
		/// </summary>
		/// <remarks>
		///     Reset to 0 with each new ratchet.
        /// </remarks>
        [ProtoMember(12)]
		public int MessageNumberSend { get; set; }

		/// <summary>
		///     Nr : 
        ///     Reset to 0 with each new ratchet.
		/// </summary>
        /// <remarks>
        ///     Reset to 0 with each new ratchet.
        /// </remarks>
        [ProtoMember(13)]
		public int MessageNumberReceive { get; set; }

		/// <summary>
		///     PNs : 
        ///     Number of messages sent under previous ratchet.
		/// </summary>
		/// <remarks>
        ///     Number of messages sent under previous ratchet.
        /// </remarks>
        [ProtoMember(14)]
		public List<int> PreviousMessageNumbers { get; set; }

		/// <summary>
        ///     ratchet_flag : 
		///     Indicates whether the party will send a new ratchet key in next message. 
        /// </summary>
        [ProtoMember(15)]
		public bool RatchetFlag { get; set; }
	}

    /// <summary>
    ///     Enumeration of algorithms that form the basis of a key agreement scheme.
    /// </summary>
    public enum KeyAgreementAlgorithm
    {
        /// <summary>
        ///     Diffie-Hellman.
        /// </summary>
        DH,

        /// <summary>
        ///     Elliptic Curve Diffie-Hellman (extension of <see cref="DH"/> using elliptic curve mathematics).
        /// </summary>
        /// <remarks>
        ///     Provides considerably higher security for a given key size when compared with <see cref="DH"/>, 
        ///     but has a greater associated complexity in mutually-agreed parameters and in implementation.
        /// </remarks>
        ECDH
    }
}
