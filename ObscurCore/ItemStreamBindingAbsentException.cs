using System;
using ObscurCore.DTO;

namespace ObscurCore
{
    /// <summary>
    /// Exception thrown when, during package I/O, a payload item is missing a stream binding.
    /// </summary>
    public class ItemStreamBindingAbsentException : Exception
    {
        private const string NoStreamBindingMessage = "Item has no stream binding.";

        public ItemStreamBindingAbsentException() {}
        public ItemStreamBindingAbsentException(IPayloadItem item) : base(NoStreamBindingMessage) {
            PayloadItem = item;
        }
        public ItemStreamBindingAbsentException(IPayloadItem item, Exception inner) : base(NoStreamBindingMessage, inner) {
            PayloadItem = item;
        }

        public IPayloadItem PayloadItem { get; private set; }
    }
}