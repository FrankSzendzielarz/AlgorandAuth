using System;
using Algorand.Algod;
using Algorand.Algod.Model;
using Algorand.Algod.Model.Transactions;
using AlgoStudio;
using Algorand;
using AlgoStudio.Core;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Proxies
{

	
	public class TransactionRouterContractProxy : ProxyBase
	{
		
		public TransactionRouterContractProxy(DefaultApi defaultApi, ulong appId) : base(defaultApi, appId) 
		{
		}

		public async Task SetPubKey (Account sender, ulong? fee, byte[] pubKey,string note, List<BoxRef> boxes)
		{
			var abiHandle = Encoding.UTF8.GetBytes("setpubkey");
			var result = await base.CallApp(null, fee, AlgoStudio.Core.OnCompleteType.NoOp, 1000, note, sender,  new List<object> {abiHandle,pubKey}, null, null,null,boxes);

		}

		public async Task<List<Transaction>> SetPubKey_Transactions (Account sender, ulong? fee, byte[] pubKey,string note, List<BoxRef> boxes)
		{
			var abiHandle = Encoding.UTF8.GetBytes("setpubkey");
			return await base.MakeTransactionList(null, fee, AlgoStudio.Core.OnCompleteType.NoOp, 1000, note, sender,  new List<object> {abiHandle,pubKey}, null, null,null,boxes);

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
		public async Task SendTransaction (Account sender, ulong? fee, ulong opup,Address foreignAccount1,AlgorandAuth.Models.PasskeySignedPayment signedTransaction,string note, List<BoxRef> boxes)
		{
			var abiHandle = Encoding.UTF8.GetBytes("send");
			var result = await base.CallApp(null, fee, AlgoStudio.Core.OnCompleteType.NoOp, 1000, note, sender,  new List<object> {abiHandle,signedTransaction}, new List<ulong> {opup}, null,new List<Address> {foreignAccount1},boxes);

		}

		public async Task<List<Transaction>> SendTransaction_Transactions (Account sender, ulong? fee, ulong opup,Address foreignAccount1,AlgorandAuth.Models.PasskeySignedPayment signedTransaction,string note, List<BoxRef> boxes)
		{
			var abiHandle = Encoding.UTF8.GetBytes("send");
			return await base.MakeTransactionList(null, fee, AlgoStudio.Core.OnCompleteType.NoOp, 1000, note, sender,  new List<object> {abiHandle,signedTransaction}, new List<ulong> {opup}, null,new List<Address> {foreignAccount1},boxes);

		}

		public async Task<byte[]> OwnerPubKey()
		{
			var key="OwnerPubKey";
			var result= await base.GetGlobalByteSlice(key);
			return result;

		}

	}

}
