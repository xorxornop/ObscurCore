using System;
using System.Threading;
using BitManipulator;
using ObscurCore.Support.Entropy;

namespace ObscurCore.Cryptography.Entropy
{
    /// <summary>
    /// Base class for cryptographically-secure random number generators (CSRNG).
    /// </summary>
    public abstract class CsRng : Rng
    {
        private static long _counter = DateTime.UtcNow.Ticks * 100L;

        private static long NextCounterValue()
        {
            return Interlocked.Increment(ref _counter);
        }

        /// <summary>Add more seed material to the generator.</summary>
        /// <param name="seed">A byte array to be mixed into the generator's state.</param>
        public abstract void AddSeedMaterial(byte[] seed);

        public void AddSeedMaterial(long inSeed)
        {
            AddSeedMaterial(inSeed.ToLittleEndian());
        }

        public CsRng CreateRng(bool autoSeed = true)
        {
            var csrng = CreateGenerator();

            if (autoSeed) {
                csrng.AddSeedMaterial(NextCounterValue());
                csrng.AddSeedMaterial(DateTime.Now.Ticks);
                byte[] rv = new byte[64];
                NextBytes(rv);
            }

            return csrng;
        }

        // TODO: Fix shitty implementations that don't really do anything useful except prevent build error
        protected abstract CsRng CreateGenerator();
    }
}
