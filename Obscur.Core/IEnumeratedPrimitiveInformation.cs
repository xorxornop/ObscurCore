using System;

namespace Obscur.Core
{
    /// <summary>
    ///     Enumeration data to be available in a information store object definining a primitive  
    ///     (e.g. an implementation of a discrete algorithm than can be used in a modular way).
    /// </summary>
    internal interface IEnumeratedPrimitiveInformation<T> : IPrimitiveInformation where T : struct, IConvertible
    {
        /// <summary>
        ///     Enumeration member associated with the primitive.
        /// </summary>
        T Identity { get; }
    }
}