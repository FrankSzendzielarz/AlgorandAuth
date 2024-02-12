using Algorand;
using AlgoStudio.Core;
using AlgoStudio.Core.Attributes;

namespace AlgorandWebauthnVariant.Models
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

}
