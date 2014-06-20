using ObscurCore.DTO;

namespace ObscurCore.Cryptography
{
    public class EcKeypair
    {
        /// <summary>
        ///     Name of the curve provider. Used to look up relevant domain parameters to interpret the encoded keys.
        /// </summary>
        public string CurveProviderName { get; set; }

        /// <summary>
        ///     Name of the elliptic curve in the provider's selection.
        /// </summary>
        public string CurveName { get; set; }

        /// <summary>
        ///     Byte-array-encoded form of the public key.
        /// </summary>
        public byte[] EncodedPublicKey { get; set; }

        /// <summary>
        ///     Byte-array-encoded form of the private key.
        /// </summary>
        public byte[] EncodedPrivateKey { get; set; }

        /// <summary>
        ///     Exports the public component of the keypair as an EcKeyConfiguration DTO object.
        /// </summary>
        /// <returns>Public key as EcKeyConfiguration DTO.</returns>
        public EcKeyConfiguration ExportPublicKey()
        {
            return new EcKeyConfiguration {
                PublicComponent = true,
                CurveProviderName = CurveProviderName,
                CurveName = CurveName,
                EncodedKey = EncodedPublicKey.DeepCopy()
            };
        }

        /// <summary>
        ///     Exports the public component of the keypair as a serialised EcKeyConfiguration DTO object.
        /// </summary>
        /// <returns>Public key as bytes of serialised EcKeyConfiguration DTO.</returns>
        public byte[] ExportPublicKeySerialised()
        {
            return ExportPublicKey().SerialiseDto();
        }

        /// <summary>
        ///     Exports the public component of the keypair as an EcKeyConfiguration DTO object.
        /// </summary>
        /// <returns>Public key as EcKeyConfiguration DTO.</returns>
        public EcKeyConfiguration GetPrivateKey()
        {
            return new EcKeyConfiguration {
                PublicComponent = false,
                CurveProviderName = CurveProviderName,
                CurveName = CurveName,
                EncodedKey = EncodedPrivateKey.DeepCopy()
            };
        }
    }
}
