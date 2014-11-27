using Obscur.Core.Cryptography.Entropy;

namespace Obscur.Core.Cryptography.Support
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
