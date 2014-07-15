using System;
using System.Diagnostics;
using System.Threading;

namespace ObscurCore.Support.Random
{
    /// <summary>
    ///     Thread based seed generator - one source of randomness.
    /// </summary>
    /// <remarks>
    ///     Based on an idea from Marcus Lippert.
    /// </remarks>
    public class ThreadedSeedRng : Rng
    {
        private readonly bool _fast;

        /// <summary>
        ///     Create a new threaded generator.
        /// </summary>
        /// <remarks>
        ///     If fast is set to true, the code should be round about 8 times faster when
        ///     generating a long sequence of random bytes.
        /// </remarks>
        /// <param name="fast">If<c>true</c>, fast generation method (with less quality) will be used.</param>
        public ThreadedSeedRng(bool fast = false)
        {
            _fast = fast;
        }

        public override void NextBytes(byte[] buffer, int offset, int count)
        {
            new SeedGenerator().GenerateSeed(buffer, 0, count, _fast);
        }

        private class SeedGenerator
        {
            private volatile int _counter;
            private volatile bool _stop;

            public SeedGenerator()
            {
                _counter = 0;
            }

            private void Run(object ignored)
            {
                while (!_stop) {
                    _counter++;
                }
            }

            public void GenerateSeed(byte[] buffer, int offset, int count, bool fast)
            {
                _counter = 0;
                _stop = false;

                int last = 0;
                int end = fast ? count : count * 8;

                ThreadPool.QueueUserWorkItem(Run);

                for (int i = 0; i < end; i++) {
                    while (_counter == last) {
                        try {
                            Thread.Sleep(1);
                        } catch (Exception e) {
                            Debug.Print(DebugUtility.CreateReportString("ThreadedSeedRng", "GenerateSeed",
                                "Thread sleep threw exception", e.ToString()));
                        }
                    }

                    last = _counter;

                    if (fast) {
                        buffer[offset + i] = (byte)last;
                    } else {
                        int bytepos = i / 8;
                        buffer[offset + bytepos] = (byte)((buffer[offset + bytepos] << 1) | (last & 1));
                    }
                }

                _stop = true;
            }
        }
    }
}
