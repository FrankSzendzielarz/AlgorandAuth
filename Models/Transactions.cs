using Algorand;
using AlgoStudio.Core;
using AlgoStudio.Core.Attributes;

namespace AlgorandAuth.Models
{
    [ABIStruct]
    public struct RawTransaction
    {
        public ulong amount;
        public AccountReference receiver;
    }

    [ABIStruct]
    public struct PasskeySignedTransaction
    {
        public byte[] signature;
        public bool isEcdsa;
        public RawTransaction transaction;

    }

    [ABIStruct]
    public struct RekeyInstruction
    {
        public byte[] signature;
        public bool isEcdsa;
        public byte[] newPublicKey;
    }
    

}
