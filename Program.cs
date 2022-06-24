using IdentityManager.Services.MailJet;
using Microsoft.AspNetCore.Identity.UI.Services;

var builder = WebApplication.CreateBuilder(args);

#region Services Container

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "cookie";
    options.DefaultChallengeScheme = "apple";
})
    .AddCookie("cookie")
    .AddOpenIdConnect("apple", options =>
    {
        options.ResponseType = "code id_token"; // hybrid flow due to lack of PKCE support
        options.ResponseMode = "form_post"; // form post due to prevent PII in the URL
        options.UsePkce = false; // apple does not currently support PKCE (April 2021)
        options.DisableTelemetry = true;

        options.Scope.Clear(); // apple does not support the profile scope
        options.Scope.Add("openid");
        options.Scope.Add("email");
        options.Scope.Add("name");
    });
// Getting connection string
builder.Services.AddDbContext<AuthDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AuthDbConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password settings.
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 3;
    options.Password.RequiredUniqueChars = 1;

    // Signin Settings
    options.SignIn.RequireConfirmedEmail = true;
    // Lockout settings.
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = false;

    // User settings.
    options.User.AllowedUserNameCharacters = AppConstants.AllowedUserNameCharacters;
    options.User.RequireUniqueEmail = true;
}).AddEntityFrameworkStores<AuthDbContext>().AddDefaultTokenProviders();
builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();
builder.Services.Configure<MailJetOptions>(builder.Configuration.GetSection("MailJet"));

builder.Services.AddAuthentication()
   .AddFacebook(facebookOptions =>
   {
       IConfigurationSection facebookAuthNSection = builder.Configuration.GetSection("ExternalAuthenticators:Faceboook");
       facebookOptions.ClientId = facebookAuthNSection["AppId"];
       facebookOptions.ClientSecret = facebookAuthNSection["AppSecret"];
       facebookOptions.AccessDeniedPath = "/AccessDeniedPathInfo";
   })
   .AddGoogle(googleOptions =>
   {
       IConfigurationSection googleAuthNSection = builder.Configuration.GetSection("ExternalAuthenticators:Google");
       googleOptions.ClientId = googleAuthNSection["AppId"];
       googleOptions.ClientSecret = googleAuthNSection["AppSecret"];
   })
   .AddMicrosoftAccount(microsoftOptions =>
   {
       IConfigurationSection microsoftAuthNSection = builder.Configuration.GetSection("ExternalAuthenticators:Microsoft");
       microsoftOptions.ClientId = microsoftAuthNSection["AppSecret"];
       microsoftOptions.ClientSecret = microsoftAuthNSection["AppSecret"];
   });
//.AddTwitter(twitterOptions =>
//{
//    IConfigurationSection twitterAuthNSection = builder.Configuration.GetSection("ExternalAuthenticators:Twitter");
//    twitterOptions.ConsumerKey = twitterAuthNSection["AppSecret"];
//    twitterOptions.ConsumerSecret = twitterAuthNSection["AppSecret"];
//    twitterOptions.RetrieveUserDetails = true;
//});
#endregion

var app = builder.Build();


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
