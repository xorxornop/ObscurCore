using System;

namespace Obscur.Core
{
    /// <summary>
    /// EventArgs for storing PercentDone property.
    /// </summary>
    public class PercentDoneEventArgs : EventArgs
    {
        private readonly byte _percentDone;

        /// <summary>
        /// Initializes a new instance of the PercentDoneEventArgs class.
        /// </summary>
        /// <param name="percentDone">The percent of finished work.</param>
        /// <exception cref="System.ArgumentOutOfRangeException"/>
        public PercentDoneEventArgs (byte percentDone)
        {
            if (percentDone > 100 || percentDone < 0) {
                throw new ArgumentOutOfRangeException ("percentDone",
                                                      "The percent of finished work must be between 0 and 100.");
            }
            _percentDone = percentDone;
        }

        /// <summary>
        /// Gets the percent of finished work.
        /// </summary>
        public byte PercentDone {
            get {
                return _percentDone;
            }
        }        

        /// <summary>
        /// Converts a [0, 1] rate to its percent equivalent.
        /// </summary>
        /// <param name="doneRate">The rate of the done work.</param>
        /// <returns>Percent integer equivalent.</returns>
        /// <exception cref="System.ArgumentException"/>
        internal static byte ProducePercentDone (float doneRate)
        {   
            return (byte)Math.Round (Math.Min (100 * doneRate, 100), MidpointRounding.AwayFromZero);
        }
    }
    
    /// <summary>
    /// The EventArgs class for accurate progress handling.
    /// </summary>
    public sealed class ProgressEventArgs : PercentDoneEventArgs
    {
        private readonly byte _delta;

        /// <summary>
        /// Initializes a new instance of the ProgressEventArgs class.
        /// </summary>
        /// <param name="percentDone">The percent of finished work.</param>
        /// <param name="percentDelta">The percent of work done after the previous event.</param>
        public ProgressEventArgs (byte percentDone, byte percentDelta)
            : base(percentDone)
        {
            _delta = percentDelta;
        }

        /// <summary>
        /// Gets the change in done work percentage.
        /// </summary>
        public byte PercentDelta {
            get {
                return _delta;
            }
        }
    }
    
}

