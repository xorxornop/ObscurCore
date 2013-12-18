namespace ObscurCore.Cryptography.Ciphers
{
    interface ICipherWrapper
    {
        bool Encrypting { get; }
        int OperationSize { get; }

        int ProcessBytes(byte[] input, int inputOffset, byte[] output, int outputOffset);

        byte[] ProcessFinal(byte[] finalInput);
    }
}