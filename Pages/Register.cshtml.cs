using Fido2NetLib.Objects;
using Fido2NetLib.Development;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

using Algorand.Algod.Model;
using System.Text;
using System.Text.Json;


// Credits: some of this code is lifted from the Demo project in the FiDo2NetLib repository. Thanks!

namespace AlgorandWebauthnVariant.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly ILogger<RegisterModel> _logger;
        private IFido2 _fido2;
        public static readonly DevelopmentInMemoryStore DemoStorage = new();

        [BindProperty]
        public string? DisplayName { get; set; }

        [BindProperty]
        public string AttestationResponse { get; set; }

        public RegisterModel(ILogger<RegisterModel> logger, IFido2 fido2)
        {
            _logger = logger;
            _fido2 = fido2;
        }

        public void OnGet()
        {
        }

        public JsonResult OnPostMakeCredentialOptions()
        {
            try
            {
                // Create an Algorand account.
                Account account = new Account();

                // Let the username be the address of the account.
                string username=account.Address.ToString();

                // 1. Get user from DB by username (in our example, auto create missing users)
                var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
                {
                    DisplayName = DisplayName,
                    Name = username,
                    Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
                });

                // 2. Get user existing keys by username
                var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

                // 3. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {
                    RequireResidentKey = true ,
                    UserVerification = UserVerificationRequirement.Discouraged
                };

                
                authenticatorSelection.AuthenticatorAttachment = AuthenticatorAttachment.Platform;

                var exts = new AuthenticationExtensionsClientInputs()
                {
                    Extensions = true,
                    UserVerificationMethod = false,
                };

                var options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection, AttestationConveyancePreference.None, exts);

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
                var attestationResponse = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(AttestationResponse);
                var success = await _fido2.MakeNewCredentialAsync(attestationResponse, options, callback, cancellationToken: cancellationToken);

                // 3. Store the credentials in db
                DemoStorage.AddCredentialToUser(options.User, new StoredCredential
                {
                    UserId = success.Result.User.Id,
                    Descriptor = new PublicKeyCredentialDescriptor(success.Result.CredentialId),
                    PublicKey = success.Result.PublicKey,
                    UserHandle = success.Result.User.Id,
                    SignatureCounter = success.Result.Counter,
                    RegDate = DateTime.UtcNow,
                    AaGuid = success.Result.Aaguid,
                    CredType = success.Result.CredType,
                    
                }) ;

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
