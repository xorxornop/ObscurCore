using System;

// From Chaos.NaCl, authored by CodesInChaos (https://github.com/CodesInChaos/Chaos.NaCl)

namespace ObscurCore.Cryptography.Signing.Primitives.Ed25519Ref10
{
	internal static partial class FieldOperations
	{
		public static void fe_1(out FieldElement h)
		{
			h = default(FieldElement);
			h.x0 = 1;
		}
	}
}