namespace IdentityManager.ViewModels.Account;

public class RegisterVM
{
  [Required]
  [Display(Name = "First Name")]
  public string FirstName { get; set; } = string.Empty;
  [Required]
  [Display(Name = "Last Name")]
  public string LastName { get; set; } = string.Empty;
  [Required]
  [EmailAddress]
  [RegularExpression(@"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", ErrorMessage = "Please provide a valid email address")]
  public string Email { get; set; } = string.Empty;
  [Required]
  [DataType(DataType.Password)]
  public string Password { get; set; } = String.Empty;
  [Required]
  [DataType(DataType.Password)]
  [Display(Name = "Confirm Password")]
  [Compare("Password", ErrorMessage = "Password doesn't match")]
  public string ConfirmPassword { get; set; } = String.Empty;
  public bool TermsAgreement { get; set; } = false;
  public string FullName { get => $"{FirstName} {LastName}"; }
}
