using System;

namespace ObscurCore
{
    public class MemoableResetException
        : InvalidCastException
    {
        public MemoableResetException(string msg)
            : base(msg) {}
    }
}
