namespace MrJB.IdentityServer.AzureKeyVault.Configuration;

public class SigningKeysConfiguration
{
    public const string Position = "SigningKeys";

    public string KeyVaultUri { get; set; }

    public string CertificateNameSigning { get; set; } = "signing-certificate";

    public string CertificateNameDataProtectionKey { get; set; } = "DataProtectionKey";

    public int RolloverHours { get; set; } = 1;

    public double CacheExpiration { get; set; } = 3600000;
}
