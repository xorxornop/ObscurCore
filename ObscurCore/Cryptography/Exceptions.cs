//
//  Copyright 2013  Matthew Ducker
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ObscurCore.Cryptography
{
    public class PaddingException : Exception
	{
		public PaddingException () : base("The ciphertext padding is corrupt.") { }
		public PaddingException (string message) : base("The ciphertext padding is corrupt.\n" + message) { }
	}
	
    

	public class AuthenticationException : Exception
	{
	    private const string ExceptionAttention = "WARNING: Possible security issue!";

	    public AuthenticationException (Exception innerException = null) 
            : base(ExceptionAttention, innerException) { }

		public AuthenticationException (string message, Exception innerException = null) 
            : base(ExceptionAttention + "\n" + message, innerException) { }
	}
	
	/*public class DataLengthException : Exception
    {
        public DataLengthException(string message) : base(message) { }
    }*/
	
	public class IncompleteBlockException : Exception
	{
		public IncompleteBlockException () : base("The ciphertext data is not the expected length for the block size.") { }
		public IncompleteBlockException (string message) : base("The ciphertext data is not the expected length for the block size.\n" + message) { }
	}

    public class CryptoException
		: Exception
    {
        public CryptoException()
        {
        }

		public CryptoException(
            string message)
			: base(message)
        {
        }

		public CryptoException(
            string		message,
            Exception	exception)
			: base(message, exception)
        {
        }
    }

    /**
     * this exception is thrown if a buffer that is meant to have output
     * copied into it turns out to be too short, or if we've been given
     * insufficient input. In general this exception will Get thrown rather
     * than an ArrayOutOfBounds exception.
     */
    public class DataLengthException
		: CryptoException
	{
        /**
        * base constructor.
		*/
        public DataLengthException()
        {
        }

		/**
         * create a DataLengthException with the given message.
         *
         * @param message the message to be carried with the exception.
         */
        public DataLengthException(
            string message)
			: base(message)
        {
		}

		public DataLengthException(
            string		message,
            Exception	exception)
			: base(message, exception)
        {
        }
	}

    /// <summary>
	/// This exception is thrown whenever a cipher requires a change of key, iv
	/// or similar after x amount of bytes enciphered
	/// </summary>
	public class MaxBytesExceededException
		: CryptoException
	{
		public MaxBytesExceededException()
		{
		}

		public MaxBytesExceededException(
			string message)
			: base(message)
		{
		}

		public MaxBytesExceededException(
			string		message,
			Exception	e)
			: base(message, e)
		{
		}
	}

    public class KeySizeException : Exception
    {
        public KeySizeException(int size, string restriction)
            : base(String.Format("The key size {0} is not supported in the {1}.", size, restriction))
        {
            SelectedSize = size;
            CipherRestriction = restriction;
        }

        public int SelectedSize { get; private set; }
        public string CipherRestriction { get; private set; }
    }

    public class BlockSizeException : Exception
    {
        public BlockSizeException(int size, string restriction)
            : base(String.Format("The block size {0} is not supported in the {1}.", size, restriction))
        {
            SelectedSize = size;
            CipherRestriction = restriction;
        }

        public int SelectedSize { get; private set; }
        public string CipherRestriction { get; private set; }
    }

    public class MACSizeException : Exception
    {
        public MACSizeException(int size, string restriction)
            : base(String.Format("The MAC size {0} is not supported in the {1}.", size, restriction))
        {
            SelectedSize = size;
            CipherRestriction = restriction;
        }

        public int SelectedSize { get; private set; }
        public string CipherRestriction { get; private set; }
    }
}
