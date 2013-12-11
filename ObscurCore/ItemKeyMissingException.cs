using System;
using ObscurCore.DTO;

namespace ObscurCore
{
    /// <summary>
    /// Represents the error that occurs when, during package I/O, 
    /// cryptographic key material associated with a payload item cannot be found. 
    /// </summary>
    public class ItemKeyMissingException : Exception
    {
        public ItemKeyMissingException (PayloadItem item) : base 
            (String.Format("A cryptographic key for item GUID {0} and relative path \"{1}\" could not be found.", 
                item.Identifier.ToString(), item.RelativePath))
        {}
    }
}