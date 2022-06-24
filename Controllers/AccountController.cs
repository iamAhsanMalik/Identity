using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityManager.Controllers;
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailSender _emailSender;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEmailSender emailSender)
    {
        _emailSender = emailSender;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    public IActionResult Index()
    {
        return View();
    }

    [HttpGet]
    public IActionResult Register(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterAsync(RegisterVM registerVM, string? returnUrl = null)
    {
        returnUrl = !string.IsNullOrEmpty(returnUrl) ? returnUrl : Url.Content("~/");
        if (!ModelState.IsValid)
        {
            return View(registerVM);
        }
        var newUser = new ApplicationUser { FullName = registerVM.FullName, UserName = registerVM.Email, Email = registerVM.Email, TermsAgreement = registerVM.TermsAgreement };
        var isUserCreated = await _userManager.CreateAsync(newUser, registerVM.Password);
        if (isUserCreated.Succeeded)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = newUser.Id, emailConfirmationToken = code }, protocol: Request.Scheme);
            await _emailSender.SendEmailAsync(newUser.Email, "Confirm your email",
            $"Please confirm your account by <a href='{callbackUrl ?? "~/ "}'>clicking here</a>.");
            return LocalRedirect("~/Account/RegisterConfirm");
        }
        else
        {
            foreach (var error in isUserCreated.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View();
        }
    }
    [HttpGet]
    public IActionResult RegisterConfirm()
    {
        return View();
    }
    [HttpGet]
    public async Task<IActionResult> ConfirmEmailAsync(ConfirmEmailVM confirmEmailVM)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByIdAsync(confirmEmailVM.UserId);
            //var isTokenValid = await _userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.EmailConfirmationTokenProvider, "EmailConfirmation", confirmEmailVM.EmailConfirmationToken);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, confirmEmailVM.EmailConfirmationToken);
                var codeDecoded = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(confirmEmailVM.EmailConfirmationToken));
                result = await _userManager.ConfirmEmailAsync(user, codeDecoded);
                if (result.Succeeded)
                {
                    return RedirectToAction("ConfirmEmail");
                }
                AddErrors(result);
            }
        }
        return View(confirmEmailVM);
    }
    [HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginAsync(LoginVM loginVM, string? returnUrl = null)
    {
        returnUrl = returnUrl ?? Url.Content("~/");
        if (!ModelState.IsValid)
        {
            return View(loginVM);
        }
        var isSignIn = await _signInManager.PasswordSignInAsync(loginVM.Email, loginVM.Password, loginVM.RememberMe, false);
        if (isSignIn.Succeeded)
        {
            return LocalRedirect(returnUrl);
        }
        if (isSignIn.RequiresTwoFactor)
        {
            return RedirectToAction(nameof(VerifyQRAuthenticatorCode), new { loginVM.RememberMe, returnUrl });
        }
        if (isSignIn.IsLockedOut)
        {
            return LocalRedirect(nameof(Lockout));
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Please use valid credentials");
        }
        return View(loginVM);
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult ExternalLogin(ExternalLoginVM externalLoginVM, string? returnUrl = null)
    {
        returnUrl = returnUrl ?? Url.Content("~/");
        if (ModelState.IsValid)
        {
            //redirect request to the external login provider
            var redirecturl = Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl });

            var properties = _signInManager.ConfigureExternalAuthenticationProperties(externalLoginVM.LoginProvider, redirecturl);
            return Challenge(properties, externalLoginVM.LoginProvider);
        }
        return View(externalLoginVM);

    }
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ExternalLoginCallBack(string? returnurl = null, string? remoteError = null)
    {
        returnurl = returnurl ?? Url.Content("~/");
        if (remoteError != null)
        {
            ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
            return View(nameof(Login));
        }
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return RedirectToAction(nameof(Login));
        }

        //Sign in the user with this external login provider, if the user already has a login.
        var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
        if (result.Succeeded)
        {
            //update any authentication tokens
            await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
            return LocalRedirect(returnurl);
        }
        if (result.RequiresTwoFactor)
        {
            return RedirectToAction(nameof(VerifyQRAuthenticatorCode), new { returnurl = returnurl });
        }
        else
        {
            //If the user does not have account, then we will ask the user to create an account.
            ViewData["ReturnUrl"] = returnurl;
            ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var name = info.Principal.FindFirstValue(ClaimTypes.Name);
            return View("ExternalLoginConfirmation", new ExternalLoginConfirmationVM { Email = email, Name = name });
        }
    }
    [AllowAnonymous]
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationVM model, string? returnurl = null)
    {
        returnurl = returnurl ?? Url.Content("~/");

        if (ModelState.IsValid)
        {
            //get the info about the user from external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return View("Error");
            }
            var user = new ApplicationUser { UserName = model.Email, Email = model.Email, FullName = model.Name };
            var result = await _userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                //await _userManager.AddToRoleAsync(user, "User");
                result = await _userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                    return LocalRedirect(returnurl);
                }
            }
            AddErrors(result);
        }
        ViewData["ReturnUrl"] = returnurl;
        return View(model);
    }
    [HttpGet]
    public IActionResult ForgotPassword()
    {
        return View();
    }
    [HttpGet]
    public async Task<IActionResult> EnableQRCodeAuthenticator()
    {
        // If user already have enable qrCode auth, then this will reset it
        var currentUser = await _userManager.GetUserAsync(User);
        await _userManager.ResetAuthenticatorKeyAsync(currentUser);
        var authKey = await _userManager.GetAuthenticatorKeyAsync(currentUser);
        var model = new TwoFactorAuthenticationVM() { AuthToken = authKey };
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> EnableQRCodeAuthenticator(TwoFactorAuthenticationVM twoFactorAuthenticationVM)
    {
        if (ModelState.IsValid)
        {
            var currentUser = await _userManager.GetUserAsync(User);
            var succeded = await _userManager.VerifyTwoFactorTokenAsync(currentUser, _userManager.Options.Tokens.AuthenticatorTokenProvider, twoFactorAuthenticationVM.AuthCode);
            if (succeded)
            {
                await _userManager.SetTwoFactorEnabledAsync(currentUser, true);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Your code is invalid or expire");
                return View(twoFactorAuthenticationVM);
            }
        }
        return RedirectToAction("QRCodeAuthenticationConfirm");

    }
    [HttpGet]
    public IActionResult QRCodeAuthenticationConfirm()
    {
        return View();
    }

    [HttpGet]
    public async Task<IActionResult> VerifyQRAuthenticatorCodeAsync(bool rememberMe, string returnUrl = "")
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return View("Error");
        }
        ViewData["ReturnUrl"] = returnUrl;
        return View(new VerifyQRAuthenticatorCodeVM { ReturnUrl = returnUrl, RememberMe = rememberMe });
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyQRAuthenticatorCode(VerifyQRAuthenticatorCodeVM verifyQRAuthenticatorCodeVM)
    {
        verifyQRAuthenticatorCodeVM.ReturnUrl = verifyQRAuthenticatorCodeVM.ReturnUrl ?? Url.Content("~/");
        if (!ModelState.IsValid)
        {
            return View(verifyQRAuthenticatorCodeVM);
        }

        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(verifyQRAuthenticatorCodeVM.QRAuthCode, verifyQRAuthenticatorCodeVM.RememberMe, rememberClient: false);

        if (result.Succeeded)
        {
            return LocalRedirect(verifyQRAuthenticatorCodeVM.ReturnUrl);
        }
        if (result.IsLockedOut)
        {
            return View("Lockout");
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Invalid Code.");
            return View(verifyQRAuthenticatorCodeVM);
        }

    }


    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordVM forgotPasswordVM)
    {
        if (ModelState.IsValid)
        {
            var existingUser = await _userManager.FindByEmailAsync(forgotPasswordVM.Email);
            if (existingUser != null && existingUser.FullName == forgotPasswordVM.FullName)
            {
                var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(existingUser);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = existingUser.Id, resetToken = passwordResetToken }, protocol: Request.Scheme);
                var htmlMessage = $"Please reset your password by <a href='{callbackUrl ?? "~/ "}'>Reset Password</a>.";

                await _emailSender.SendEmailAsync(forgotPasswordVM.Email, "Reset Password - Identity Manager :)", htmlMessage);

                return RedirectToAction("ForgotPasswordConfirm");
            }
        }
        return View(forgotPasswordVM);
    }
    [HttpGet]
    public IActionResult ForgotPasswordConfirm()
    {
        return View();
    }
    [HttpGet]
    public IActionResult ResetPassword(string resetToken)
    {
        return !string.IsNullOrEmpty(resetToken) ? View() : View("Error");
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetPassword(ResetPasswordVM resetPasswordVM)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordVM.Email);

            var isValid = await _userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", resetPasswordVM.ResetToken);
            if (user != null && isValid == true)
            {
                // Validate Token Purpose - Sensitive (UserManager.cs => Github)
                var result = await _userManager.ResetPasswordAsync(user, resetPasswordVM.ResetToken, resetPasswordVM.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirm");
                }
                else
                {
                    AddErrors(result);
                }
            }
        }
        return View(resetPasswordVM);
    }
    [HttpGet]
    public IActionResult ResetPasswordConfirm()
    {
        return View();
    }
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LogoutAsync(string? returnUrl = null)
    {
        if (!ModelState.IsValid)
        {
            return View();
        }
        await _signInManager.SignOutAsync();
        if (returnUrl != null)
        {
            return LocalRedirect(returnUrl);
        }
        else
        {
            return View();
        }
    }
    [HttpGet]
    public IActionResult Lockout()
    {
        return View();
    }
    private void AddErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }
}
