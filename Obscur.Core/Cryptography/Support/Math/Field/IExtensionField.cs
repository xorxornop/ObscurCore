namespace Obscur.Core.Cryptography.Support.Math.Field
{
    public interface IExtensionField
        : IFiniteField
    {
        IFiniteField Subfield { get; }

        int Degree { get; }
    }
}
