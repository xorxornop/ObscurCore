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
using ProtoBuf;

namespace ObscurCore.DTO
{
	[ProtoContract]
	public class JpakeRound1 : IDataTransferObject
	{
		[ProtoMember(1, IsRequired = true)]
		public string ParticipantId { get; set; }

		[ProtoMember(2, IsRequired = true)]
		public byte[] GX1 { get; set; }

		[ProtoMember(3, IsRequired = true)]
		public byte[] X1V { get; set; }

		[ProtoMember(4, IsRequired = true)]
		public byte[] X1R { get; set; }

		[ProtoMember(5, IsRequired = true)]
		public byte[] GX2 { get; set; }

		[ProtoMember(6, IsRequired = true)]
		public byte[] X2V { get; set; }

		[ProtoMember(7, IsRequired = true)]
		public byte[] X2R { get; set; }
	}
}
