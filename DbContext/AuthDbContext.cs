
namespace IdentityManager.DbContext;
public class AuthDbContext : IdentityDbContext<ApplicationUser>
{
  public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
  {
  }
}