## Requirements

Make sure you have jq installed.

## Define the list of URLs

Define the URL your application is listening on. For example:

```sh
APP_URL="http://localhost:8080"
```

## Create a Resource Group on Azure

First, set the location where you want your resources to be created in:

```sh
LOCATION="WestUS2"
```

Create a resource group:

```sh
RG_NAME="Unlocker"
RG_ID=$(az group create \
  --name $RG_NAME \
  --location $LOCATION \
  | jq -r .id)
```

## Create the Azure Key Vault

Create a Key Vault; the name of the Key Vault must be globally unique:

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

Lastly, create a new key directly inside the vault. You may create multiple keys if needed, each with a different name:

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

## Azure AD application

Create an app in Azure AD that  to access Azure Key Vault with an user's delegated permissions.

```sh
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

Take note of the output of the last command, which includes the values for the configuration file:

- `appId` is the value for `azure.clientId`
- `password` is the value for `azure.clientSecret`
- `tenant` is the value for `azure.tenantId`
