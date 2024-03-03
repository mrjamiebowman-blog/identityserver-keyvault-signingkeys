# remove existing container
docker rm -f mrjb-identityserver

# variables
$VERSION = 'dev'

# app config
$connectionString = ''
$labelFilter = 'IDENTITY-SERVER'
$tenantId = ''
$clientId = ''
$clientSecret = ''
$azKeyVaultCertUri = ''

# ssl password
$certPassword = ''

# docker run (use cert locally only)
docker run -d -p 5000:5000 -p 5001:5001 `
						  -e ASPNETCORE_ENVIRONMENT=Development `
						  -e AZ_APPCONFIG_CONNECTION_STRING=$connectionString `
						  -e AZ_TENANT_ID=$tenantId `
						  -e AZ_APPCONFIG_LABEL_FILTER=$labelFilter `
						  -e AAD_CLIENT_ID=$clientId `
						  -e AAD_CLIENT_SECRET=$clientSecret `
						  -e AZ_KEYVAULT_CERT_URI=$azKeyVaultCertUri `
						  --name mrjb-identityserver `
						  -v $PWD/certs/:/certs/ `
						  mrjb/identityserver:$VERSION

# list
docker ps -a | findstr mrjb

docker logs -f mrjb-identityserver