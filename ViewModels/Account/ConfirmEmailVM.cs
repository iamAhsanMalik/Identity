namespace IdentityManager.ViewModels.Account;

public class ConfirmEmailVM
{
    [Required]
    public string UserId { get; set; } = string.Empty;
    public string EmailConfirmationToken { get; set; } = string.Empty;
}
