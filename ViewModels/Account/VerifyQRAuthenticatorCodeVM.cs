namespace IdentityManager.ViewModels.Account;

public class VerifyQRAuthenticatorCodeVM
{
    [Required]
    public string QRAuthCode { get; set; } = string.Empty;
    public string ReturnUrl { get; set; } = string.Empty;
    public bool RememberMe { get; set; } = false;
}
