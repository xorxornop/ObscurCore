using System;

namespace Obscur.Core
{
    public class MemoableResetException
        : InvalidCastException
    {
        public MemoableResetException(string msg)
            : base(msg) {}
    }
}
