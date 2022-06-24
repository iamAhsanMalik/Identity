using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Services.MailJet;

public class MailJetOptions
{
  public string ApiKey { get; set; } = string.Empty;
  public string SecretKey { get; set; } = string.Empty;
}
