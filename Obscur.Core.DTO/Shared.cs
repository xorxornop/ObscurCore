using System;

namespace Obscur.Core.DTO
{
    internal class Shared
    {
        internal const int BufferBlockCopyThreshold = 1024;
#if INCLUDE_UNSAFE
        internal const int UnmanagedThreshold = 128;

        internal static readonly int PlatformWordSize = IntPtr.Size;
        internal static readonly int PlatformWordSizeBits = PlatformWordSize * 8;
#endif
    }
}
