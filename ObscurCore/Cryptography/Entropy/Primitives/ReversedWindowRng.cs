using System;
using ObscurCore.Support.Random;

namespace ObscurCore.Cryptography.Entropy.Primitives
{
    /// <summary>
    ///     Reverses the order of bytes within a window of output (of configurable size) 
    ///     from another CSRNG.
    /// </summary>
    /// <remarks>
    ///     Access to internals is synchronised so a single instance can be shared.
    /// </remarks>
    public sealed class ReversedWindowRng : CsRng
    {
        private readonly Rng _rng;

        private readonly byte[] _window;

        private int _windowCount;

        public ReversedWindowRng(
            Rng rng,
            int windowSize)
        {
            if (rng == null) {
                throw new ArgumentNullException("rng");
            }
            if (windowSize < 2) {
                throw new ArgumentException("Window size must be at least 2", "windowSize");
            }

            _rng = rng;
            _window = new byte[windowSize];
        }

        public Rng BaseRng
        {
            get { return _rng; }
        }

        public override void AddSeedMaterial(
            byte[] seed)
        {
            var rng = _rng as CsRng;
            if (rng != null) {
                lock (this) {
                    _windowCount = 0;
                    rng.AddSeedMaterial(seed);
                }
            } else {
                throw new InvalidOperationException("CSRNG was initialised with RNG, not CSRNG. Cannot add seed material.");
            }
        }

        public override void NextBytes(
            byte[] buffer,
            int offset,
            int count)
        {
            lock (this) {
                int done = 0;
                while (done < count) {
                    if (_windowCount < 1) {
                        _rng.NextBytes(_window, 0, _window.Length);
                        _windowCount = _window.Length;
                    }
                    buffer[offset + done++] = _window[--_windowCount];
                }
            }
        }
    }
}
