using ObscurCore.Cryptography.Authentication;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
    /// <summary>
    ///     Cryptographically-secure random number generator (CSRNG) based on digest with counter.
    /// </summary>
    /// <remarks>
    ///     Calling AddSeedMaterial will always increase the entropy of the hash.
    ///     Internal access to the digest is synchronized so a single instance can be shared.
    /// </remarks>
    public sealed class DigestCsRng : CsRng
    {
        private const long CycleCount = 10;

        private readonly IDigest _digest;
        private readonly byte[] _seed;
        private readonly byte[] _state;
        private long _seedCounter;
        private long _stateCounter;

        public DigestCsRng(
            IDigest digest)
        {
            this._digest = digest;

            _seed = new byte[digest.DigestSize];
            _seedCounter = 1;

            _state = new byte[digest.DigestSize];
            _stateCounter = 1;
        }

        public override void AddSeedMaterial(
            byte[] inSeed)
        {
            lock (this) {
                DigestUpdate(inSeed);
                DigestUpdate(_seed);
                DigestDoFinal(_seed);
            }
        }

        public override void NextBytes(
            byte[] bytes,
            int start,
            int len)
        {
            lock (this) {
                int stateOff = 0;

                GenerateState();

                int end = start + len;
                for (int i = start; i < end; ++i) {
                    if (stateOff == _state.Length) {
                        GenerateState();
                        stateOff = 0;
                    }
                    bytes[i] = _state[stateOff++];
                }
            }
        }

        private void CycleSeed()
        {
            DigestUpdate(_seed);
            DigestAddCounter(_seedCounter++);
            DigestDoFinal(_seed);
        }

        private void GenerateState()
        {
            DigestAddCounter(_stateCounter++);
            DigestUpdate(_state);
            DigestUpdate(_seed);
            DigestDoFinal(_state);

            if ((_stateCounter % CycleCount) == 0) {
                CycleSeed();
            }
        }

        private void DigestAddCounter(long seedVal)
        {
            var seed = (ulong) seedVal;
            for (int i = 0; i != 8; i++) {
                _digest.Update((byte) seed);
                seed >>= 8;
            }
        }

        private void DigestUpdate(byte[] inSeed)
        {
            _digest.BlockUpdate(inSeed, 0, inSeed.Length);
        }

        private void DigestDoFinal(byte[] result)
        {
            _digest.DoFinal(result, 0);
        }
    }
}
