using System;
using System.IO;

namespace ObscurCore
{
    /// <summary>
    ///     Interface for stream decorators - streams that modify data as they read and/or write it.
    /// </summary>
    public interface IStreamDecorator
    {
        /// <summary>
        ///     What I/O mode of the decorator is active.
        /// </summary>
        /// <value><c>true</c> if writing, <c>false</c> if reading.</value>
        bool Writing { get; }

        /// <summary>
        ///     Bytes that have passed into the decorator.
        /// </summary>
        long BytesIn { get; }

        /// <summary>
        ///     Bytes that have passed out of the decorator.
        /// </summary>
        long BytesOut { get; }

        /// <summary>
        ///     Stream that is being decorated/de-decorated.
        /// </summary>
        Stream Binding { get; }

        /// <summary>
        ///     Decorates and writes the contents of <paramref name="buffer" /> to the <see cref="Binding" /> stream.
        /// </summary>
        /// <param name="buffer">
        ///     Data to decorate and write.
        /// </param>
        /// <param name="offset">
        ///     Index in <paramref name="buffer" /> from which to write from.
        /// </param>
        /// <param name="count">
        ///     Quantity of bytes from <paramref name="buffer" /> to decorate and write.
        /// </param>
        void Write(byte[] buffer, int offset, int count);

        /// <summary>
        ///     Writes an exact quantity of bytes (after decoration) to the <see cref="Binding" /> stream,
        ///     reading as necessary from the <paramref name="source" /> stream to supply the decorator.
        /// </summary>
        /// <returns>
        ///     The quantity of bytes taken from the <paramref name="source" /> stream to fulfil the request.
        /// </returns>
        /// <param name="source">
        ///     Source of decorated data.
        /// </param>
        /// <param name="length">
        ///     Quantity of bytes to write to the <see cref="Binding" /> stream, after decoration.
        /// </param>
        long WriteExactlyFrom(Stream source, long length);

        /// <summary>
        ///     Reads and de-decorates data from the <see cref="Binding" /> stream
        ///     and writes it to <paramref name="buffer" />.
        /// </summary>
        /// <param name="buffer">
        ///     Where to write de-decorated data to.
        /// </param>
        /// <param name="offset">
        ///     Index in <paramref name="buffer" /> from which to write to.
        /// </param>
        /// <param name="count">
        ///     Quantity of bytes to attempt to return to <paramref name="buffer" />.
        /// </param>
        /// <returns>
        ///     Quantity of bytes actually returned to <paramref name="buffer" />.
        /// </returns>
        int Read(byte[] buffer, int offset, int count);

        /// <summary>
        ///     Reads an exact amount of bytes from the <see cref="Binding" /> stream, and writing
        ///     as necessary (after de-decoration) to the <paramref name="destination" /> stream.
        /// </summary>
        /// <returns>
        ///     The quantity of bytes written to the <paramref name="destination" /> stream.
        /// </returns>
        /// <param name="destination">
        ///     Stream to write output to.
        /// </param>
        /// <param name="length">
        ///     Quantity of bytes to read from the <see cref="Binding" /> stream, before de-decoration.
        /// </param>
        /// <param name="finishing">
        ///     If used in derived class, and set to <c>true</c>, causes special behaviour if this is the last read.
        /// </param>
        long ReadExactlyTo(Stream destination, long length, bool finishing);
    }
}
