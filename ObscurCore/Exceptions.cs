using System;

namespace ObscurCore
{
    [Serializable]
    public class ConfigurationException : Exception
    {
        private const string AttentionString =
            "Configuration object is malformed/invalid.\nOperation that requires it cannot proceed.";

        public ConfigurationException() {}
        public ConfigurationException(string message) : base(message) {}

		public ConfigurationException (string message, Exception innerException = null) 
            : base(AttentionString + "\n" + message, innerException) { }

        public ConfigurationException (Exception innerException = null) 
            : base(AttentionString, innerException) { }
	}

    [Serializable]
    public class EnumerationValueUnknownException : Exception
    {
        public EnumerationValueUnknownException() {}
        public EnumerationValueUnknownException(string message) : base(message) {}
        public EnumerationValueUnknownException(string message, Exception inner) : base(message, inner) {}

        /// <summary>
        /// Initialises a new instance of the EnumerationValueUnknownException class with diagnostic information.
        /// </summary>
        /// <param name="requested">Value of the enumeration type that parsing was attempted on.</param>
        /// <param name="eType">Enumeration type.</param>
        public EnumerationValueUnknownException(string requested, Type eType) 
            : base("Enumeration member "+ requested + " is unknown in " + eType.Name) {
        }
    }
}