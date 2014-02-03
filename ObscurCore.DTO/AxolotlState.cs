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

using System;
using System.Collections.Generic;
using ProtoBuf;

namespace ObscurCore.DTO
{
	public class AxolotlState
	{
		/// <summary>
		/// RK
		/// </summary>
		public byte[] RootKey { get; set; }

		/// <summary>
		/// HKs
		/// </summary>
		public byte[] HeaderKeySend { get; set; }

		/// <summary>
		/// HKr
		/// </summary>
		public byte[] HeaderKeyReceive { get; set; }

		/// <summary>
		/// NHKs
		/// </summary>
		public byte[] NextHeaderKeySend { get; set; }

		/// <summary>
		/// NHKr
		/// </summary>
		public byte[] NextHeaderKeyReceive { get; set; }

		/// <summary>
		/// CKs
		/// </summary>
		public byte[] ChainKeySend { get; set; }

		/// <summary>
		/// CKr
		/// </summary>
		public byte[] ChainKeyReceive { get; set; }

		/// <summary>
		/// DHIs
		/// </summary>
		public byte[] IdentityKeySend { get; set; }

		/// <summary>
		/// DHIr
		/// </summary>
		public byte[] IdentityKeyReceive { get; set; }

		/// <summary>
		/// DHRs
		/// </summary>
		public byte[] RatchetKeySend { get; set; }

		/// <summary>
		/// DHRr
		/// </summary>
		public byte[] RatchetKeyReceive { get; set; }

		/// <summary>
		/// Ns
		/// </summary>
		public int MessageNumberSend { get; set; }

		/// <summary>
		/// Nr
		/// </summary>
		public int MessageNumberReceive { get; set; }

		/// <summary>
		/// PNs
		/// </summary>
		public List<int> PreviousMessageNumbers { get; set; }

		/// <summary>
		/// Indicates whether the party will send a new ratchet key in next message. 
		/// ratchet_flag
		/// </summary>
		public bool RatchetFlag { get; set; }
	}
}
