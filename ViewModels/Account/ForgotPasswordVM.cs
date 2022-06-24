namespace IdentityManager.ViewModels.Account;
public class ForgotPasswordVM
{
  [Required]
  [Display(Name = "Full Name")]
  public string FullName { get; set; } = string.Empty;
  [Required]
  [EmailAddress]
  [RegularExpression(@"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", ErrorMessage = "Please provide a valid email address")]
  public string Email { get; set; } = string.Empty;
}
