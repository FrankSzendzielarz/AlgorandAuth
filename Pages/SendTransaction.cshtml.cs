using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AlgorandWebauthnVariant.Pages
{
    public class SendTransactionModel : PageModel
    {
        private readonly ILogger<SendTransactionModel> _logger;

        public SendTransactionModel(ILogger<SendTransactionModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
        }
    }

}
