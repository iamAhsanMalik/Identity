namespace IdentityManager.ViewModels.Account;

public class TwoFactorAuthenticationVM
{
    // Required for login to application by entering authenticator code
    public string AuthCode { get; set; } = string.Empty;
    // Required for register authenticator app
    public string AuthToken { get; set; } = string.Empty;
}
