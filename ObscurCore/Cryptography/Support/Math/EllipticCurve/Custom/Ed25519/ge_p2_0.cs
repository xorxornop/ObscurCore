namespace ObscurCore.Cryptography.Support.Math.EllipticCurve.Custom.Ed25519
{
	internal static partial class GroupOperations
	{
		public static void ge_p2_0(out  GroupElementP2 h)
		{
			FieldOperations.fe_0(out h.X);
			FieldOperations.fe_1(out h.Y);
			FieldOperations.fe_1(out h.Z);
		}
	}
}