using Algorand;
using AlgoStudio.Core;
using AlgoStudio.Core.Attributes;
using Microsoft.AspNetCore.Identity;

namespace AlgorandAuth.Models
{
    [ABIStruct]
    public struct RawSpendTransaction
    {
        public ulong amount;
        public ulong nonce;
        
    }

    [ABIStruct]
    public struct RawRekeyTransaction
    {
        public byte[] newPublicKey;
        public ulong nonce;
        
    }

    [ABIStruct]
    public struct PasskeySignedPayment
    {
        public byte[] signature;
        public bool isEcdsa;
        public RawSpendTransaction transaction;
        public byte[] clientDataJson;
        public byte[] authenticatorData;
        
        
        
        
    }

    [ABIStruct]
    public struct RekeyInstruction
    {
        public byte[] signature;
        public bool isEcdsa;
        public RawRekeyTransaction transaction;
        public byte[] clientDataJson;
        public byte[] authenticatorData;

    }

}
