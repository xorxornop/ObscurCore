using ProtoBuf;

namespace ObscurCore.DTO
{
    [ProtoContract]
    public enum SymmetricCipherType
    {
        None,
        Aead,
        Block,
        Stream
    }
}