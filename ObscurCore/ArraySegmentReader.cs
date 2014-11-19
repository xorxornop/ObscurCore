using System;
using System.Diagnostics.Contracts;
using System.IO;

namespace ObscurCore
{
    /// <summary>
    /// A reader that divides a source <see cref="ArraySegment{T}"/> into multiple <see cref="ArraySegment{T}"/> instances.
    /// </summary>
    /// <typeparam name="T">The type of elements contained in the array.</typeparam>
    public sealed class ArraySegmentReader<T>
    {
        /// <summary>
        /// The source array segment.
        /// </summary>
        private readonly ArraySegment<T> source;

        /// <summary>
        /// Initializes a new instance of the <see cref="ArraySegmentReader&lt;T&gt;"/> class.
        /// </summary>
        /// <param name="source">The source array segment.</param>
        public ArraySegmentReader(ArraySegment<T> source)
        {
            Contract.Ensures(this.Position == 0);
            this.source = source;
            this.Position = 0;
        }

        /// <summary>
        /// Gets the source array segment.
        /// </summary>
        public ArraySegment<T> Source { get { return this.source; } }

        /// <summary>
        /// Gets or sets the position of this reader.
        /// </summary>
        public int Position { get; set; }

        /// <summary>
        /// Sets the position of this reader. Returns the new position.
        /// </summary>
        /// <param name="offset">The offset from the origin.</param>
        /// <param name="origin">The origin to use when setting the position.</param>
        /// <returns>The new position.</returns>
        public int Seek(int offset, SeekOrigin origin)
        {
            Contract.Ensures(origin != SeekOrigin.Begin || this.Position == offset);
            Contract.Ensures(origin != SeekOrigin.Current || this.Position == Contract.OldValue(this.Position) + offset);
            Contract.Ensures(origin != SeekOrigin.End || this.Position == this.Source.Count + offset);

            switch (origin) {
                case SeekOrigin.Begin:
                    this.Position = offset;
                    break;
                case SeekOrigin.Current:
                    this.Position += offset;
                    break;
                case SeekOrigin.End:
                    this.Position = this.Source.Count + offset;
                    break;
            }

            return this.Position;
        }

        /// <summary>
        /// Creates a new array segment which starts at the current position and covers the specified number of elements.
        /// </summary>
        /// <param name="count">The number of elements in the new array segment.</param>
        /// <returns>The new array segment.</returns>
        public ArraySegment<T> Read(int count)
        {
            Contract.Requires(count >= 0);
            Contract.Requires(this.Position >= 0 && this.Position < this.Source.Count);
            Contract.Requires(count <= this.Source.Count - this.Position);
            var ret = this.Source.Slice(this.Position, count);
            this.Position += count;
            return ret;
        }
    }
}
