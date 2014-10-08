using System;

namespace ObscurCore
{
    public class ConfigurationOutOfSpec
    {
    }

    public class OutOfSpecificationException : ConfigurationInvalidException
    {
        //
        // For guidelines regarding the creation of new exception types, see
        //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
        // and
        //    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
        //

        public OutOfSpecificationException() {}
        public OutOfSpecificationException(string message) : base(message) {}
        public OutOfSpecificationException(string message, Exception inner) : base(message, inner) {}

    }
}
