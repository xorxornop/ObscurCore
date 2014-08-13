using System;
using ObscurCore.Cryptography.Entropy;
namespace ObscurCore.Cryptography.Support
{
	public class ECKeyGenerationParameters
		: KeyGenerationParameters
	{
		private readonly ECDomainParameters domainParams;

		public ECKeyGenerationParameters(
			ECDomainParameters	domainParameters,
			CsRng		random)
			: base(random, domainParameters.N.BitLength)
		{
			this.domainParams = domainParameters;
		}

		public ECDomainParameters DomainParameters
		{
			get { return domainParams; }
		}
	}
}
