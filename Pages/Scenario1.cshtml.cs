using Algorand;
using AlgorandAuth.Models;
using AlgorandAuth.Pages.Shared;
using AlgoStudio.Clients;
using AlgoStudio.Compiler;
using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using Proxies;
using System.Text;
using System.Text.Json;



// Credits: some of this code is lifted from the Demo project in the FiDo2NetLib repository. Thanks!

namespace AlgorandAuth.Pages
{
    public class Scenario1Model : AlgorandBaseModel
    {
        private readonly ILogger<Scenario1Model> _logger;
        private IFido2 _fido2;
        private Fido2Configuration _fido2config;

        public static readonly Data.DevelopmentInMemoryStore DemoStorage = new();

        [BindProperty]
        public string? UserName { get; set; }

        [BindProperty]
        public string AttestationResponseAuth { get; set; }

        [BindProperty]
        public string AttestationResponseAlgorand { get; set; }

        [BindProperty]
        public string AssertedCredential { get; set; }

        public Scenario1Model(ILogger<Scenario1Model> logger, IFido2 fido2, IConfiguration config, Fido2Configuration fido2config) : base(config)
        {
            _logger = logger;
            _fido2 = fido2;
            _fido2config = fido2config;
        }

        public void OnGet()
        {
        }

        public JsonResult OnPostMakeCredentialOptions()
        {
            try
            {
                string username = UserName;

                // 1. Get user from DB by username (in our example, auto create missing users)
                var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
                {
                    DisplayName = UserName,
                    Name = username,
                    Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
                });

                // 2. Get user existing keys by username
                var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

                // 3. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {

                    RequireResidentKey = true,
                    UserVerification = UserVerificationRequirement.Preferred
                };


                //authenticatorSelection.AuthenticatorAttachment = AuthenticatorAttachment.CrossPlatform;

                var exts = new AuthenticationExtensionsClientInputs()
                {
                    Extensions = true,
                    UserVerificationMethod = true,

                };

                var options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection, AttestationConveyancePreference.None, exts);

                //restrict to ECDSA here (though ED25519 is also supported)
                //   options.PubKeyCredParams = options.PubKeyCredParams.Where(p => p.Alg == COSE.Algorithm.ES256).ToList();




                // 4. Temporarily store options, session/in-memory cache/redis/db
                HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());






                // 5. return options to client
                return new JsonResult(options);
            }
            catch (Exception e)
            {
                return new JsonResult(new CredentialCreateOptions { Status = "error", ErrorMessage = "Failed to make credential options." });
            }



        }


        private AssertionOptions GetAssertionOptions(
           IEnumerable<PublicKeyCredentialDescriptor> allowedCredentials,
           UserVerificationRequirement? userVerification,
           byte[] challengeBytes,
           AuthenticationExtensionsClientInputs? extensions = null
           )

        {
            
            var options = AssertionOptions.Create(_fido2config, challengeBytes, allowedCredentials, userVerification, extensions);
            return options;
        }


        public async Task<JsonResult> OnPostExecuteTransaction(CancellationToken cancellationToken)
        {
            try
            {
                AuthenticatorAssertionRawResponse clientResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(AssertedCredential);
                AuthenticatorAssertionResponse parsedResponse = AuthenticatorAssertionResponse.Parse(clientResponse);

                //get the app from the credential id


                var appCred = DemoStorage.GetCredentialByAlgorandId(clientResponse.Id);
                if (appCred == null)
                {
                    throw new Exception("Algorand id not found for credential.");
                }
                
                //dummy txn , same as what was signed.
                var txnToSign = new RawSpendTransaction()
                {
                    amount = 1234,
                    nonce = 10
                };

                var payment = new PasskeySignedPayment()
                {
                    transaction = txnToSign,
                    authenticatorData = clientResponse.Response.AuthenticatorData,
                    clientDataJson = clientResponse.Response.ClientDataJson,
                    isEcdsa = true,
                    signature = clientResponse.Response.Signature
                };

                TransactionRouterContractProxy proxy = new TransactionRouterContractProxy(algodClient, appCred.AlgorandAccountId);
                await proxy.SendTransaction(acc1, 2000, acc2.Address, payment, "", null);



                return new JsonResult(new { status = "ok", errorMessage = "" });
            }
            catch (Exception e)
            {

                return new JsonResult(new { status = "error", errorMessage = e.ToString() });
            }
        }
        public async Task<JsonResult> OnPostSignTransaction(CancellationToken cancellationToken)
        {
            try
            {
                string username = UserName;

                var existingCredentials = new List<PublicKeyCredentialDescriptor>();

                if (!string.IsNullOrEmpty(UserName))
                {

                    //var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                    //// 2. Get registered credentials from database
                    //existingCredentials = DemoStorage.GetCredentialsByUser(user).Where(c=>c is AlgorandStoredCredential).Select(c => (c as AlgorandStoredCredential).AlgorandCredentialId).ToList();
                }

                var exts = new AuthenticationExtensionsClientInputs()
                {
                    Extensions = true,
                    UserVerificationMethod = true,

                };

                // 3. Create options
                var txnToSign = new RawSpendTransaction()
                {
                    amount = 1234,
                    nonce = 10
                };
                var txnBytes = TealTypeUtils.ToByteArray(txnToSign);

                var uv = UserVerificationRequirement.Discouraged;
                var options = GetAssertionOptions(
                    existingCredentials,
                    uv,
                    txnBytes,
                    exts
                );


                // 4. Temporarily store options, session/in-memory cache/redis/db
                HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

                // 5. Return options to client
                return new JsonResult(options);





            }
            catch (Exception e)
            {

                return new JsonResult(new AssertionOptions { Status = "error", ErrorMessage = e.ToString() }); ;
            }
        }



        public async Task<JsonResult> OnPostRegisterCredential(CancellationToken cancellationToken)
        {
            try
            {
                // 1. get the options we sent the client
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                // 2. Create callback so that lib can verify credential id is unique to this user
                IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
                {
                    var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                    if (users.Count > 0)
                        return false;

                    return true;
                };

                // 2. Verify and make the credentials
                var attestationResponseAuth = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(AttestationResponseAuth);
                var success = await _fido2.MakeNewCredentialAsync(attestationResponseAuth, options, callback, cancellationToken: cancellationToken);


                // 2b. Get the algorand credential pubkey 
                var attestationResponseAlgorand = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(AttestationResponseAlgorand);
                var algorandCredential = await _fido2.MakeNewCredentialAsync(attestationResponseAlgorand, options, callback, cancellationToken: cancellationToken);
                var algorandSigningPubkey = algorandCredential.Result.PublicKey.Take(64).ToArray();


                // 3. Deploy the custom contract for the new user to the Algorand network
                var userAccountContract = new TransactionRouterContract.TransactionRouterContract();
                var appId = await userAccountContract.Deploy(acc1, algodClient);
                if (appId == null)
                {
                    return new JsonResult(new CredentialCreateOptions { Status = "error", ErrorMessage = "Failed to make credential options." });
                }
                Address algorandAccountAddress = Address.ForApplication(appId.Value);

                // 4. Ensure this contract will authorise instructions from this user (though the contracts will be deploy time templates in future, not parameterised with storage)
                var proxy = new Proxies.TransactionRouterContractProxy(algodClient, appId.Value);
                await proxy.SetPubKey(acc1, 1000, algorandSigningPubkey, "", null);

                var verify = await proxy.OwnerPubKey();


                // 5. Store the credentials in db along with the algorand recipient account
                DemoStorage.AddCredentialToUser(options.User, new AlgorandStoredCredential
                {
                    UserId = success.Result.User.Id,
                    Descriptor = new PublicKeyCredentialDescriptor(success.Result.CredentialId),
                    PublicKey = success.Result.PublicKey,
                    UserHandle = success.Result.User.Id,
                    SignatureCounter = success.Result.Counter,
                    RegDate = DateTime.UtcNow,
                    AaGuid = success.Result.Aaguid,
                    CredType = success.Result.CredType,
                    AlgorandSigningPubkey = algorandSigningPubkey,
                    AlgorandAccountAddress = algorandAccountAddress,
                    AlgorandAccountId = appId.Value,
                    AlgorandCredentialId = new PublicKeyCredentialDescriptor(algorandCredential.Result.CredentialId)

                });

                // 4. return "ok" to the client
                return new JsonResult(true);
            }
            catch (Exception e)
            {
                return new JsonResult(false);
            }
        }
    }

}
