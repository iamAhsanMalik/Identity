namespace IdentityManager.ViewModels.Account;

public class ExternalLoginConfirmationVM
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    [PersonalData]
    public string Name { get; set; } = string.Empty;
}
