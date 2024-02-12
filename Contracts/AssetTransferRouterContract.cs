using Algorand;
using Algorand.Algod.Model.Transactions;
using AlgorandWebauthnVariant.Models;
using AlgoStudio.Core;
using AlgoStudio.Core.Attributes;
using Org.BouncyCastle.Crypto.Paddings;

namespace AlgorandWebauthnVariant.Contracts
{
    public class AssetTransferRouterContract : SmartContract
    {
        [Storage(StorageType.Global)]
        public byte[] OwnerPubKey;

        protected override int ApprovalProgram(in AppCallTransactionReference transaction)
        {
            // Deletion (prevent deletion)
            if (transaction.OnCompletion == 5)
            {
                return 0;
            }

            // Creation (prevent method call on creation)
            if (transaction.ApplicationID == 0)
            {
                return 1;
            }



            InvokeSmartContractMethod();
            return 1;
        }

        protected override int ClearStateProgram(in AppCallTransactionReference transaction)
        {
            return 1;
        }

        /// <summary>
        /// This example uses an simplified representation of a transaction.
        /// The actual transaction object could involve all the fields of a standard transaction, and
        /// the parameters could include all the possible foreign references.
        /// 
        /// This example however encourages the idea of having a restricted set of functionality
        /// for scenarios like onboarding new users to video games, where the account and MBR required is 
        /// controlled by the server, until the user wishes to transition to more full control of the account
        /// such as by rekeying.
        /// </summary>
        /// <param name="payment"></param>
        [SmartContractMethod(OnCompleteType.NoOp,"send")]
        public void SendTransaction(PasskeySignedTransaction signedTransaction, AccountReference foreignAccount1)
        {

            [InnerTransactionCall]
            void sendTransaction()
            {
                AccountReference recipient= signedTransaction.transaction.receiver;
                new Payment(recipient, signedTransaction.transaction.amount);
            }

            //Demo implementation. A full transaction would involve more fields, this is just a simplified example.
            if  (signedTransaction.isEcdsa)
            {
                byte[] message = Sha256((byte[])(object)signedTransaction);
                
                byte[] signature = signedTransaction.signature;
                byte[] signatureR = signature.Part(0, 31);
                byte[] signatureS= signature.Part(32, 63);

                byte[] ownerPubKeyBytes = OwnerPubKey;
                byte[] ownerPubKeyX= ownerPubKeyBytes.Part(0, 31);
                byte[] ownerPubKeyY= ownerPubKeyBytes.Part(32, 63);
                bool verified = Ecdsa_verify_secp256r1(message, signatureR, signatureS,ownerPubKeyX,ownerPubKeyY);

                if ((verified)) 
                {
                    sendTransaction();
                }
                else
                {
                    Fail();
                }

            }else
            {
                // Do ed25519 verification
            }
        }

        
    }
}
