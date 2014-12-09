using System;
using System.IO;
using NUnit.Framework;
using Obscur.Core.DTO;

namespace Obscur.Core.Tests.Packaging.Serialisation
{
	public abstract class SerialisationTestBase
	{
		protected DtoSerialiser serialiser;
		
		[TestFixtureSetUp]
		public void InitFixture () {
            serialiser = new DtoSerialiser();
			AuxTestFixtureInit ();
		}
		
		[SetUp]
		public void InitTest () {
			AuxPerTestInit ();
		}
		
		public virtual void AuxTestFixtureInit () { } // Implement as required by overriding
		public virtual void AuxPerTestInit () { } // Implement as required by overriding

		protected MemoryStream SerialiseToMemory<T>(T inputObj) {
			var stream = new MemoryStream ();
			serialiser.SerializeWithLengthPrefix (stream, inputObj, typeof(T), ProtoBuf.PrefixStyle.Base128, 0);
			stream.Seek (0, SeekOrigin.Begin);
			return stream;
		}
		
		protected T DeserialiseFromMemory<T>(MemoryStream input) where T : IEquatable<T> {
			var outputObj = (T) serialiser.DeserializeWithLengthPrefix (input, null, typeof(T), ProtoBuf.PrefixStyle.Base128, 0);
			return outputObj;
		}
	}
}

