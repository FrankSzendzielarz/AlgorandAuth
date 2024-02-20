using Algorand;
using Algorand.Algod;
using Algorand.Algod.Model;
using Algorand.KMD;
using AlgoStudio.Clients;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AlgorandAuth.Pages.Shared
{
    public class AlgorandBaseModel : PageModel
    {
        public static ulong OpupAppId = 0;

        protected DefaultApi algodClient { get; }
        protected Api kmdClient { get; }

        private const string walletName = "unencrypted-default-wallet";
        protected Account acc1;
        protected Account acc2;
        protected Account acc3;

        public AlgorandBaseModel( IConfiguration configuration)
        {


            var algoHttpClient = HttpClientConfigurator.ConfigureHttpClient(configuration["AlgorandConnection:AlgodApiUrl"], configuration["AlgorandConnection:AlgodApiToken"]);
            algodClient = new DefaultApi(algoHttpClient);


            var kmdHttpClient = new HttpClient();
            kmdHttpClient.DefaultRequestHeaders.Add("X-KMD-API-Token", configuration["AlgorandConnection:AlgodApiToken"]);
            kmdClient = new Api(kmdHttpClient);
            kmdClient.BaseUrl = configuration["AlgorandConnection:AlgodKmdApiUrl"];

            Task.Run(SetUpAccounts).Wait();

            // This should really be done once and added to a configuration setting. This code is for demo purposes.
            if (OpupAppId == 0)
            {
                var opup = new OpupContract.OpupContract();
                var appId=opup.Deploy(acc1, algodClient).Result;
                if (appId == null) throw new Exception("Failed to deploy Opup contract.");
                OpupAppId = appId.Value;
            }
        }

        private async Task SetUpAccounts()
        {
            
            var accounts = await getDefaultWallet();

            //get accounts based on the above private keys using the .NET SDK
            acc1 = accounts[0];
            acc2 = accounts[1];
            acc3 = accounts[2];
        }

        private async Task<List<Account>> getDefaultWallet()
        {
            string handle = await getWalletHandleToken();
            var accs = await kmdClient.ListKeysInWalletAsync(new ListKeysRequest() { Wallet_handle_token = handle });
            if (accs.Addresses.Count < 3) throw new Exception("Sandbox should offer minimum of 3 demo accounts.");

            List<Account> accounts = new List<Account>();
            foreach (var a in accs.Addresses)
            {

                var resp = await kmdClient.ExportKeyAsync(new ExportKeyRequest() { Address = a, Wallet_handle_token = handle, Wallet_password = "" });
                Account account = new Account(resp.Private_key);
                accounts.Add(account);
            }
            return accounts;
        }

        private async Task<string> getWalletHandleToken()
        {
            var wallets = await kmdClient.ListWalletsAsync(null);
            var wallet = wallets.Wallets.Where(w => w.Name == walletName).FirstOrDefault();
            var handle = await kmdClient.InitWalletHandleTokenAsync(new InitWalletHandleTokenRequest() { Wallet_id = wallet.Id, Wallet_password = "" });
            return handle.Wallet_handle_token;
        }
    }
}
