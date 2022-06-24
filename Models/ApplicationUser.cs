using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityManager.Models
{
  public class ApplicationUser : IdentityUser
  {
    [PersonalData]
    [Column(TypeName = "nvarchar(100)")]
    public string? FullName { get; set; }
    public bool TermsAgreement { get; set; }
  }
}