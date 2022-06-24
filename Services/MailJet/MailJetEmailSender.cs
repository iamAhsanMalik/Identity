using Mailjet.Client;
using Mailjet.Client.Resources;
using Mailjet.Client.TransactionalEmails;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace IdentityManager.Services.MailJet;

public class MailJetEmailSender : IEmailSender
{
  private readonly MailJetOptions _mailJetOptions;
  public MailJetEmailSender(IOptions<MailJetOptions> mailJetOptions)
  {
    _mailJetOptions = mailJetOptions.Value;
  }

  public async Task SendEmailAsync(string toEmail, string subject, string message)
  {
    if (string.IsNullOrEmpty(_mailJetOptions.ApiKey) || string.IsNullOrEmpty(_mailJetOptions.SecretKey))
    {
      throw new Exception("Missing MailJet configurations ");
    }
    await Execute(_mailJetOptions, subject, message, toEmail);
  }

  public async Task Execute(MailJetOptions options, string subject, string message, string toEmail)
  {

    MailjetClient _client = new MailjetClient(options.ApiKey, options.SecretKey);

    // construct your email with builder
    var email = new TransactionalEmailBuilder()
           .WithFrom(new SendContact("undeclaredvariable@protonmail.com"))
           .WithSubject(subject)
           .WithHtmlPart(message)
           .WithTo(new SendContact(toEmail))
           .Build();
    // invoke API to send email
    var response = await _client.SendTransactionalEmailAsync(email);
  }
}
