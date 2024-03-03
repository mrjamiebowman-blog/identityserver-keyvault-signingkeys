using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Duende.IdentityServer.Stores;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MrJB.IdentityServer.AzureKeyVault.Configuration;
using MrJB.IdentityServer.SigningKeys.Stores;

namespace Microsoft.Extensions.DependencyInjection;

public static class Builder
{
    public static IServiceCollection ConfigureKeyVaultSigningCredential(this IServiceCollection services, IConfiguration configuration)
    {
        // configuration
        var signingKeysConfiguration = new SigningKeysConfiguration();
        configuration.GetSection(SigningKeysConfiguration.Position).Bind(signingKeysConfiguration);
        services.AddSingleton<SigningKeysConfiguration>(signingKeysConfiguration);

        // validate

        // client id & secret
        var tenantId = configuration.GetValue<string>("AZ_TENANT_ID");
        var clientId = configuration.GetValue<string>("AAD_CLIENT_ID");
        var secret = configuration.GetValue<string>("AAD_CLIENT_SECRET");

        // azure key vault uri
        var uri = $"https://{signingKeysConfiguration.KeyVaultUri}.vault.azure.net/";

        try
        {
            // certificate client
            var client = new CertificateClient(vaultUri: new Uri(uri), credential: new ClientSecretCredential(tenantId, clientId, secret));
            services.AddSingleton(client);
        }
        catch (Exception ex)
        {
            throw ex;
        }

        services.AddSingleton<ISigningCredentialStore, AzureKeyVaultStore>();
        services.AddSingleton<IValidationKeysStore, AzureKeyVaultStore>();

        return services;
    }
}
