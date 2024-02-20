using Algorand;
using AlgoStudio.Core;
using AlgoStudio.Core.Attributes; 
using System; 

namespace Algorand.Imports
{
	public abstract class OpupContractReference : SmartContractReference
	{

		///<summary>
		///
		///</summary>
		///<param name="result"></param>
		[SmartContractMethod(OnCompleteType.NoOp, "opup")]
		public abstract ValueTuple<AppCall> Opup();
	}
}
