using Algorand;
using Fido2NetLib.Development;

namespace AlgorandAuth.Models
{
    public class AlgorandStoredCredential : StoredCredential
    {
        public byte[] AlgorandSigningPubkey { get; set; }
        public Address AlgorandAccountAddress { get; set; }
    }
}
