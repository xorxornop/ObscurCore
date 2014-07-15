using System;
using ObscurCore.Cryptography.Entropy;
namespace ObscurCore.Cryptography.Support
{
	public class ECKeyGenerationParameters
		: KeyGenerationParameters
	{
		private readonly ECDomainParameters domainParams;
//		private readonly DerObjectIdentifier publicKeyParamSet;

		public ECKeyGenerationParameters(
			ECDomainParameters	domainParameters,
			CsRng		random)
			: base(random, domainParameters.N.BitLength)
		{
			this.domainParams = domainParameters;
		}

//		public ECKeyGenerationParameters(
//			DerObjectIdentifier	publicKeyParamSet,
//			CsRng		random)
//			: this(ECKeyParameters.LookupParameters(publicKeyParamSet), random)
//		{
//			this.publicKeyParamSet = publicKeyParamSet;
//		}

		public ECDomainParameters DomainParameters
		{
			get { return domainParams; }
		}

//		public DerObjectIdentifier PublicKeyParamSet
//		{
//			get { return publicKeyParamSet; }
//		}
	}
}
