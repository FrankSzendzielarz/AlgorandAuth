using Algorand;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;

namespace AlgorandAuth.Models
{
    public class AlgorandStoredCredential : StoredCredential
    {
        public byte[] AlgorandSigningPubkey { get; set; }
        public Address AlgorandAccountAddress { get; set; }
        public PublicKeyCredentialDescriptor AlgorandCredentialId { get; internal set; }
    }
}
