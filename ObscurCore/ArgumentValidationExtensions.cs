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

using System;
using System.Reflection.Emit;

namespace ObscurCore
{
    /// <summary>
    /// </summary>
    public static class ArgumentValidationExtensions
    {
        /// <summary>
        ///     Used to verify arguments for a method of the form "copy <paramref name="length" /> items, 
        ///     possibly with modification, from <paramref name="src" />[<paramref name="srcOff" />] to 
        ///     <paramref name="dst" />[<paramref name="dstOff" />].".
        /// </summary>
        /// <typeparam name="T">Type of the source and destination arrays.</typeparam>
        /// <param name="src">Source data array.</param>
        /// <param name="dst">Destination array for data.</param>
        /// <param name="length">Number of items to copy from <paramref name="src"/> into <paramref name="dst"/>.</param>
        /// <param name="srcOff">Offset in <paramref name="src"/> to read from.</param>
        /// <param name="dstOff">Offset in <paramref name="dst"/> to write to.</param>
        /// <param name="srcName">
        ///     Name of the argument for <paramref name="src"/>. 
        ///     Set to null (default) if existing name matches.
        /// </param>
        /// <param name="dstName">
        ///     Name of the argument for <paramref name="dst"/>. 
        ///     Set to null (default) if existing name matches.
        /// </param>
        /// <param name="lengthName">
        ///     Name of the argument for <paramref name="length"/>. 
        ///     Set to null (default) if existing name matches.
        /// </param>
        /// <param name="srcOffName">
        ///     Name of the argument for <paramref name="srcOff"/>. 
        ///     Set to null (default) if existing name matches.
        /// </param>
        /// <param name="dstOffName">
        ///     Name of the argument for <paramref name="dstOff"/>. 
        ///     Set to null (default) if existing name matches.
        /// </param>
        internal static void ThrowOnInvalidArgument<T>(
            T[] src, T[] dst, int length, int srcOff = 0, int dstOff = 0,
            string srcName = null, string dstName = null, string lengthName = null, string srcOffName = null, string dstOffName = null) where T : struct
        {
            if (src == null) {
                throw new ArgumentNullException(srcName ?? "src");
            }
            int srcLength = src.Length;
            if (src.Length < 0) {
                throw new ArgumentException(String.Format("{0}.Length < 0 : {1} < 0", srcName ?? "src", srcLength), srcName ?? "src");
            }

            if (dst == null) {
                throw new ArgumentNullException(dstName ?? "dst");
            }
            int dstLength = dst.Length;
            if (dst.Length < 0) {
                throw new ArgumentException(String.Format("{0}.Length < 0 : {1} < 0", dstName ?? "dst", dstLength), dstName ?? "dst");
            }

            if (srcOff != 0 || dstOff != 0 || length != srcLength) {
                if (length < 0) {
                    throw new ArgumentOutOfRangeException(lengthName ?? "length",
                        String.Format("{0} < 0 : {1} < 0", lengthName ?? "length", length));
                }
                // Check source values
                if (srcOff + length > srcLength) {
                    if (srcOff >= srcLength) {
                        throw new ArgumentException(
                            String.Format("{0} >= {1}.Length : {2} >= {3}",
                                srcOffName ?? "srcOff", srcName ?? "src", srcOff, srcLength));
                    } else if (length > srcLength) {
                        throw new ArgumentOutOfRangeException(lengthName ?? "length",
                            String.Format("{0} > {1}.Length : {2} > {3}",
                                lengthName ?? "length", srcName ?? "src", length, srcLength));
                    } else {
                        // Either the array is smaller than expected/desired, 
                        // or the chosen offset and/or length are for a different size array...
                        throw new ArgumentException(
                            String.Format("{0} + {1} > {2}.Length : {3} + {4} > {5}",
                                srcOffName ?? "srcOff", lengthName ?? "length", srcName ?? "src",
                                srcOff, length, srcLength));
                    }
                } else if (srcOff < 0) {
                    throw new ArgumentOutOfRangeException(srcOffName ?? "srcOff",
                        String.Format("{0} < 0 : {1} < 0",
                            srcOffName ?? "srcOff", srcOff));
                }
                // Check destination values
                if (dstOff + length > dstLength) {
                    if (dstOff >= dstLength) {
                        throw new ArgumentException(
                            String.Format("{0} >= {1} : {2} >= {3}",
                                dstOffName ?? "dstOff", dstName ?? "dst", dstOff, dstLength));
                    } else if (length > dstLength) {
                        throw new ArgumentOutOfRangeException(lengthName ?? "length",
                            String.Format("{0} > {1}.Length : {2} > {3}",
                                lengthName ?? "length", dstName ?? "dst", length, dstLength));
                    } else {
                        // Either the array is smaller than expected/desired, 
                        // or the chosen offset and/or length are for a different size array...
                        throw new ArgumentException(
                            String.Format("{0} + {1} > {2}.Length : {3} + {4} > {5}",
                                dstOffName ?? "dstOff", lengthName ?? "length", dstName ?? "dst",
                                dstOff, length, dstLength));
                    }
                } else if (dstOff < 0) {
                    throw new ArgumentOutOfRangeException(dstOffName ?? "dstOff",
                        String.Format("{0} < 0 : {1} < 0",
                            dstOffName ?? "dstOff", dstOff));
                }
            }
        }

        /// <summary>
        ///     Determines the managed size of a struct <typeparamref name="T"/> at runtime using reflection.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static int SizeOf<T>(T obj) where T : struct 
        {
            var typeOfT = typeof(T);
            if (typeOfT == typeof(byte)) {
                return 1;
            } else if (typeOfT == typeof(char)) {
                return sizeof(char);
            } else if (typeOfT == typeof(short) || typeOfT == typeof(ushort)) {
                return sizeof(short);
            } else if (typeOfT == typeof(int) || typeOfT == typeof(uint)) {
                return sizeof(int);
            } else if (typeOfT == typeof(long) || typeOfT == typeof(ulong)) {
                return sizeof(long);
            } else if (typeOfT == typeof(float)) {
                return sizeof(float);
            } else if (typeOfT == typeof (double)) {
                return sizeof(double);
            }
            // Other type
            return SizeOfCache<T>.SizeOf;
        }

        private static string FormatArgValExceptionMsg(string argType, string argState, string argName = null)
        {
            const string argNameMissing = " (no argument name provided to validator)";
            return String.Format("{0} argument is {1}{2}.", argType, argState, argName ?? argNameMissing);
        }

        /// <summary>
        ///     A version of this class will be created for every distinct type <typeparamref name="T"/> that uses it.
        /// </summary>
        /// <typeparam name="T">Type to cache determined size value for.</typeparam>
        private static class SizeOfCache<T> where T : struct 
        {
            public static readonly int SizeOf;

            static SizeOfCache()
            {
                var dm = new DynamicMethod("func", typeof(int),
                    Type.EmptyTypes, typeof(ArgumentValidationExtensions));

                ILGenerator il = dm.GetILGenerator();
                il.Emit(OpCodes.Sizeof, typeof(T));
                il.Emit(OpCodes.Ret);

                var func = (Func<int>)dm.CreateDelegate(typeof(Func<int>));
                SizeOf = func();
            }
        }
    }

    /// <summary>
    /// </summary>
    public class ArgumentValidationException : ArgumentException
    {
        public ArgumentValidationException() {}
        public ArgumentValidationException(string message) : base(message) {}
        public ArgumentValidationException(string message, Exception inner) : base(message, inner) {}

        public ArgumentValidationException(string message, ValidationError type, Exception inner = null)
            : base(message, inner)
        {
            ErrorType = type;
            switch (type) {
                case ValidationError.Unspecified:
                    break;
                case ValidationError.ValueIsNull:
                    break;
                case ValidationError.ValueIsNotNull:
                    break;
                case ValidationError.ValueOutOfRange:
                    break;
                case ValidationError.ArrayNegativeLength:
                    break;
                case ValidationError.ArrayZeroLength:
                    break;
                case ValidationError.ArrayTooSmall:
                    break;
                case ValidationError.ArraySegmentOffsetNegative:
                    break;
                case ValidationError.ArrayOffsetOverflowsLength:
                    break;
                case ValidationError.ArraySegmentOverflowsLength:
                    break;
                case ValidationError.ArraySegmentTooSmall:
                    break;
                case ValidationError.ArraySegmentTooLarge:
                    break;
                case ValidationError.TypeOfValueNotSupported:
                    break;
                case ValidationError.ValueOutOfSpecification:
                    break;
                case ValidationError.ValueOutOfContextualSpecification:
                    break;
                default:
                    throw new ArgumentOutOfRangeException("type");
            }
        }

        public ValidationError ErrorType { get; protected set; }
    }
}
