using Algorand;
using Algorand.Algod.Model.Transactions;
using AlgorandAuth.Models;
using AlgoStudio.Core;
using AlgoStudio.Core.Attributes;
using Org.BouncyCastle.Crypto.Paddings;

namespace AlgorandAuth.Contracts
{
    public class TransactionRouterContract : SmartContract
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

        [SmartContractMethod(OnCompleteType.NoOp, "setpubkey")]
        public void SetPubKey(byte[] pubKey)
        {
            OwnerPubKey = pubKey;
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
        public void SendTransaction(PasskeySignedPayment signedTransaction, AccountReference foreignAccount1)
        {
            //TODO - Nonce must be checked!


            [InnerTransactionCall]
            void sendTransaction()
            {
                AccountReference recipient= foreignAccount1;
                new Payment(recipient, signedTransaction.transaction.amount);
            }

            //Demo implementation. A full transaction would involve more fields, this is just a simplified example.
            if  (signedTransaction.isEcdsa)
            {
                //get the part of the signed message that is the transaction and verify that it matches the transaction
                // (an alternative implementation could just use the part of the signed message directly)

                string challengeB64 = GetJsonString(signedTransaction.clientDataJson, "challenge");
                byte[] challenge = Base64DecodeUrlEncoded(challengeB64.ToByteArray());
                byte[] transaction = (byte[])(object)signedTransaction.transaction;
                if (transaction != challenge)
                {
                    Fail();
                }
                else
                {


                    byte[] signature = signedTransaction.signature;
                    byte[] signatureR = signature.Part(0, 31);
                    byte[] signatureS = signature.Part(32, 63);

                    byte[] ownerPubKeyBytes = OwnerPubKey;
                    byte[] ownerPubKeyX = ownerPubKeyBytes.Part(0, 31);
                    byte[] ownerPubKeyY = ownerPubKeyBytes.Part(32, 63);

                    //construct message:
                    byte[] hash = Sha256(signedTransaction.clientDataJson);
                    byte[] authenticatorData = signedTransaction.authenticatorData;
                    byte[] message = authenticatorData.Concat(hash);

                    bool verified = Ecdsa_verify_secp256r1(message, signatureR, signatureS, ownerPubKeyX, ownerPubKeyY);

                    if ((verified))
                    {
                        sendTransaction();
                    }
                    else
                    {
                        Fail();
                    }
                }

            }else
            {
                // Do ed25519 verification
            }
        }

        //[SmartContractMethod(OnCompleteType.NoOp, "changeowner")]
        //public void ChangeOwner(RekeyInstruction rekeySignedTransaction, AccountReference foreignAccount1)
        //{

        //    //TODO - Nonce must be checked!

        //    // This example method requires user input to change the owner of the account.
        //    // For some of the example scenarios, where the user is onboarded via the server, and user interaction is needed anyway to change the owner, 
        //    // then this may be an acceptable approach.
        //    // If not then the server may want to take an alternative route, such as maintaining a master account and using that instead.
            

        //    [InnerTransactionCall]
        //    void changeOwner()
        //    {
        //        byte[] newOwner = rekeySignedTransaction.transaction.newPublicKey;
        //        byte[] self = CurrentApplicationAddress;
        //        AccountReference currentAddress= (AccountReference)(object)self;
        //        //This is actually a rekey transaction.
        //        new Payment(currentAddress, 0,null,null,null,null,null,null,null,null,newOwner);
        //    }
            
            
        //    if (rekeySignedTransaction.isEcdsa)
        //    {
        //        string challengeB64 = GetJsonString(rekeySignedTransaction.clientDataJson, "challenge");
        //        byte[] challenge = Base64DecodeUrlEncoded(challengeB64.ToByteArray());
        //        byte[] transaction = (byte[])(object)rekeySignedTransaction.transaction;
        //        if (transaction != challenge)
        //        {
        //            Fail();
        //        }

        //        byte[] signature = rekeySignedTransaction.signature;
        //        byte[] signatureR = signature.Part(0, 31);
        //        byte[] signatureS = signature.Part(32, 63);

        //        byte[] ownerPubKeyBytes = OwnerPubKey;
        //        byte[] ownerPubKeyX = ownerPubKeyBytes.Part(0, 31);
        //        byte[] ownerPubKeyY = ownerPubKeyBytes.Part(32, 63);

        //        //construct message:
        //        byte[] hash = Sha256(rekeySignedTransaction.clientDataJson);
        //        byte[] authenticatorData = rekeySignedTransaction.authenticatorData;
        //        byte[] message = authenticatorData.Concat(hash);

        //        bool verified = Ecdsa_verify_secp256r1(message, signatureR, signatureS, ownerPubKeyX, ownerPubKeyY);
        //        if ((verified))
        //        {
        //            changeOwner();
        //        }
        //        else
        //        {
        //            Fail();
        //        }

        //    }
        //    else
        //    {
        //        // Do ed25519 verification
        //    }

        //}
    }

    
}
