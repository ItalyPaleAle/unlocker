# Unlocker

## How to use

Before you can deploy and use Unlocker, you need to perform a few setup steps to create resources on Azure: a Key Vault and an Azure AD application that allows the admin to authenticate and allow or deny operations.

All the steps below must be run on your laptop before you deploy the app. At the end, you'll have the values required for the `config.yaml` file and for making requests to the service.

You will need an Azure subscription to deploy these services. You can start a [free trial](https://azure.com/free) here. All the services we need for Unlocker are free (Azure AD) or very inexpensive (for this scenario, you should not spend more than a few cents on Azure Key Vault every month).

### Requirements

You'll need two tools installed in your development machine (these don't need to be installed on your server):

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- [jq](https://stedolan.github.io/jq/download/)

Alternatively, you can use [Azure Cloud Shell](https://shell.azure.com) in the browser to run the commands below, which already has all the dependencies available.

### Define the URL

First, define the URL your application is listening on and set it in a shell variable. For example:

```sh
# Using an ip:port notation
APP_URL="http://10.20.30.40:8080"
# Can be a hostname
APP_URL="http://my-unlocker.local:8080"
```

This is the URL an admin will use to reach Unlocker. It doesn't need to be a public address, but it needs to be routable by an admin.

### Create a Resource Group on Azure

First, set the location where you want your resources to be created in:

```sh
LOCATION="WestUS2"
```

> You can get the full list of options with: `az account list-locations --output tsv`

Create a Resource Group. Give it a friendly name in the `RG_NAME` variable: it will only be used for displaying in the Azure Portal.

```sh
RG_NAME="Unlocker"
RG_ID=$(az group create \
  --name $RG_NAME \
  --location $LOCATION \
  | jq -r .id)
```

### Create the Azure Key Vault

Create a Key Vault. Set a name in the `KEYVAULT_NAME` variable, which must be globally unique:

```sh
KEYVAULT_NAME="myunlockerkv"
az keyvault create \
  --name $KEYVAULT_NAME \
  --enable-rbac-authorization true \
  --resource-group $RG_NAME \
  --location $LOCATION
```

Then assign permissions to the current user to perform operations on keys (using RBAC):

```sh
USER_ACCOUNT=$(az account show | jq -r .user.name)
az role assignment create \
  --assignee "${USER_ACCOUNT}" \
  --role "Key Vault Crypto Officer" \
  --scope "${RG_ID}/providers/Microsoft.KeyVault/vaults/${KEYVAULT_NAME}"
```

Lastly, create a new RSA-4096 key directly inside the vault. You may create multiple keys if needed, each with a different name set in the `KEYVAULT_KEY` variable:

```sh
KEYVAULT_KEY="wrappingkey1"
az keyvault key create \
  --vault-name $KEYVAULT_NAME \
  --kty RSA \
  --size 4096 \
  --name $KEYVAULT_KEY \
  --ops unwrapKey wrapKey \
  --protection software
```

Take note of the value of `KEYVAULT_KEY`, which will be used when making requests to the unlocker service.

> Important: the command above generates a new RSA key within the Key Vault and returns the public part of the key. Because keys cannot be extracted from Azure Key Vault, you will never see the private key, and there's no way to obtain that (you can, however, create backups that only work inside Azure Key Vault). If you need access to the private key, consider importing a key inside the Key Vault rather than having it generate a new one for you.

### Azure AD application

Create an app in Azure AD to access Azure Key Vault with an user's delegated permissions.

```sh
# Friendly name for the application
APP_NAME="Unlocker"

# Create the app
APP_ID=$(az ad app create \
  --display-name $APP_NAME \
  --available-to-other-tenants false \
  --oauth2-allow-implicit-flow false \
  | jq -r .appId)
APP_OBJECT_ID=$(az ad app show --id $APP_ID | jq -r .objectId)
az rest \
  --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/${APP_OBJECT_ID}" \
  --body "{\"web\":{\"redirectUris\":[\"${APP_URL}/confirm\"]}}"

# Grant permissions for Azure Key Vault
az ad app permission add \
  --id $APP_ID \
  --api cfa8b339-82a2-471a-a3c9-0fc0be7a4093 \
  --api-permissions f53da476-18e3-4152-8e01-aec403e6edc0=Scope
#az ad app permission grant \
#  --id $APP_ID \
#  --api cfa8b339-82a2-471a-a3c9-0fc0be7a4093

# Add the client secret
az ad app credential reset \
  --id $APP_ID \
  --credential-description cli \
  --years 10 \
  --password $(openssl rand -base64 30)
```

Take note of the output of the last command, which includes the values for the `config.yaml` file:

- `appId` is the value for `azure.clientId`
- `password` is the value for `azure.clientSecret`
- `tenant` is the value for `azure.tenantId`
