using AlgoStudio.Core;
using AlgoStudio.Core.Attributes;

namespace AlgorandAuth.Contracts
{
    public class OpupContract : SmartContract
    {
        protected override int ApprovalProgram(in AppCallTransactionReference transaction)
        {
            InvokeSmartContractMethod();
            return 1;
        }

        protected override int ClearStateProgram(in AppCallTransactionReference transaction)
        {
            return 1;
        }

        [SmartContractMethod(OnCompleteType.NoOp, "opup")]
        public void Opup()
        {
        }
    }
}
