using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
    public enum CipherType
    {
        None,
        Block,
        Stream
    }
}