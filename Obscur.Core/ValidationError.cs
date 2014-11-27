#region License

//  	Copyright 2013-2014 Matthew Ducker
//  	
//  	Licensed under the Apache License, Version 2.0 (the "License");
//  	you may not use this file except in compliance with the License.
//  	
//  	You may obtain a copy of the License at
//  		
//  		http://www.apache.org/licenses/LICENSE-2.0
//  	
//  	Unless required by applicable law or agreed to in writing, software
//  	distributed under the License is distributed on an "AS IS" BASIS,
//  	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  	See the License for the specific language governing permissions and 
//  	limitations under the License.

#endregion

using Obscur.Core.Cryptography.Ciphers.Information;
using Obscur.Core.DTO;

namespace Obscur.Core
{
    /// <summary>
    ///     Enumerated validation error types that may be included in a <see cref="ArgumentValidationException"/> 
    ///     to clarify the nature of the exception/error.
    /// </summary>
    public enum ValidationError
    {
        /// <summary>
        ///     Error type was not specified or is inadequately expressed by any single 
        ///     member of the <see cref="ValidationError"/> enumeration.
        /// </summary>
        /// <remarks>
        ///     If this member is used intentionally it should be accompanied by some 
        ///     additional information to describe the error.
        /// </remarks>
        Unspecified = 0,

        /// <summary>
        ///     Value null or missing, but required/expected to be non-null.
        /// </summary>
        ValueIsNull,

        /// <summary>
        ///     Value not null, but required/expected to be null.
        /// </summary>
        ValueIsNotNull,

        /// <summary>
        ///     Numerical argument is out of the allowed range.
        /// </summary>
        ValueOutOfRange,

        /// <summary>
        ///     Array segment length is less than zero.
        /// </summary>
        ArrayNegativeLength,

        /// <summary>
        ///     Array required/expected to have contents, but is zero-length (empty).
        /// </summary>
        ArrayZeroLength,

        /// <summary>
        ///     Source or destination array of insufficient length/size to store/load the required data. 
        /// </summary>
        /// <remarks>
        ///     This error type should <b>only</b> be used when it is concerned with the use
        ///     of a method that <b>only</b> accepts an array or arrays, and <b>not</b> also an offset and
        ///     count/length into such [an] array(s), i.e. the length should not be a variable quantity.
        ///     <para>
        ///         For the aforementioned use case, the similar but distinct <see cref="ArraySegmentTooSmall" />
        ///         error type should instead be used.
        ///     </para>
        /// </remarks>
        ArrayTooSmall,

        /// <summary>
        ///     Array offset less than zero (invalid offset/index).
        /// </summary>
        ArraySegmentOffsetNegative,

        /// <summary>
        ///     Array offset more than the array length (invalid offset/index).
        /// </summary>
        ArrayOffsetOverflowsLength,

        /// <summary>
        ///     Starting offset in the array is valid, but the end offset is more than or equal to 
        ///     the array length (array too short/small, or length argument value too long).
        /// </summary>
        /// <remarks>
        ///     This case is distinct from <see cref=""/>
        ///     Additional data should be provided for diagnostics and debugging purposes where possible, 
        ///     e.g. size of array, supplied offset and length values.
        /// </remarks>
        ArraySegmentOverflowsLength,

        /// <summary>
        ///     Array segment was required/expected to be larger/longer.
        /// </summary>
        /// <remarks>
        ///     Different from <see cref="ArrayTooSmall"/> in that an array size is distinct from an array segment; 
        ///     a segment range can be easily modified (or at least, if the segment does not span the complete array), 
        ///     but an array cannot.
        ///     Additional information should accompany use of this option, e.g. what length is expected.
        /// </remarks>
        ArraySegmentTooSmall,

        /// <summary>
        ///     Array segment required/expected to be smaller/shorter.
        /// </summary>
        /// <remarks>
        ///     Additional information should accompany use of this option, e.g. what length is expected.
        /// </remarks>
        ArraySegmentTooLarge,

        /// <summary>
        ///     The data type of the value is not supported.
        /// </summary>
        /// <remarks>
        ///     For most uses, <see cref="ValueOutOfSpecification"/> should be used instead, but for cases where 
        ///     such a description is less clear, or possibly confusing, this option can be used instead. 
        ///     It is suited for general purpose use where a specification is not defined and/or is inappropriate.
        /// </remarks>
        TypeOfValueNotSupported,

        /// <summary>
        ///     Value is invalid within the specification (but the value itself is not 
        ///     necessarily malformed in regard to the format it is stored as/in).
        /// </summary>
        /// <remarks>
        ///     For ObscurCore objects, the specification is effectively defined
        ///     by information store objects provided and indexed by <see cref="Athena" />.
        /// </remarks>
        /// <seealso cref="ValueOutOfContextualSpecification" />
        ValueOutOfSpecification,

        /// <summary>
        ///     Value is invalid within the context of its use,
        ///     but not out of the specification itself
        ///     (additionally, the value itself may not be malformed as a data type, either).
        /// </summary>
        /// <remarks>
        ///     This error type should <b>only</b> be used when a value is conformant with specification,
        ///     but not within the specific context of the value's intended use
        ///     (<see cref="ValueOutOfContextualSpecification" /> should be used instead in this case).
        ///     For example, a key in a <see cref="CipherConfiguration" /> would fit this description if
        ///     it is not zero-length, or longer than allowed in the specification for it in the relevant
        ///     <see cref="CipherInformation" /> information-object, but is not the size specified by the
        ///     <see cref="CipherConfiguration.KeySizeBits" /> field. In this perspective, the
        ///     <see cref="CipherConfiguration.KeySizeBits" /> field effectively defines a contextual
        ///     specification for the key.
        /// </remarks>
        ValueOutOfContextualSpecification
    }
}
