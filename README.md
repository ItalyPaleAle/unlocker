# Unlocker

Unlocker lets you wrap and unwrap (encrypt and decrypt) cryptographic keys for use by applications, securely after getting consent from an admin.

With Unlocker, your keys are wrapped and unwrapped using a RSA-4096 key stored in [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/general/overview). Applications can request Unlocker to wrap or unwrap a key (of any kind, both symmetric and asymmetric), and the operation is completed in the key vault only after a user with sufficient permission authorizes it.

As an example, Unlocker can be used to provide an encryption key for starting a long-running application, such as [unlocking encrypted drives at boot time](https://withblue.ink/2020/01/19/auto-mounting-encrypted-drives-with-a-remote-key-on-linux.html). This way, your encryption keys can be stored on your server safely in a wrapped (encrypted) format. By requiring explicit consent from an admin, you can be confident that no one can unwrap your encryption keys without your knowledge and permission.

## How it works

At a high level, Unlocker exposes two endpoints that can be used to wrap and unwrap encryption keys (where "wrapping" and "unwrapping" are synonym for "encrypting" and "decrypting" respectively). These operations are performed on Azure Key Vault, a safe, cloud-based key vault that uses strong RSA-4096 keys.

Unlocker doesn't have standing permission to perform operations on the vault, so every time a request comes in, Unlocker sends a notification to an admin (via a webhook), who can sign into Unlocker via Azure AD and allow (or deny) the operation. Unlocker uses delegated permissions to access the Key Vault, so access is restricted to specific users via Role-Based Access Control on the Azure Key Vault resource.

## Using Unlocker

In these section we'll be looking at how to wrap and unwrap a key, which in our example is `helloworld`; Unlocker supports any kind of keys and keyfiles, for both symmetric and asymmetric ciphers.

We will use a key called `wrappingkey1` stored inside an Azure Key Vault called `myunlockerkv`. We also assume that Unlocker is available at the address `https://10.20.30.40:8080`.

> Read the [**Set up**](#set-up) section below for how to set up your Unlocker app, the relevant resources on Azure, and how to generate a key inside Key Vault.

### Configure and start Unlocker

Unlocker runs as a (lightweight) app on a server you control and that offers a HTTPS endpoint. You can install it on the same server where your application that requires the cryptographic key runs, or on a separate machine.

> **Firewall rules:** Unlocker must be deployed on a server that admins can connect to via HTTPS, on a port of your choice. While Unlocker doesn't need to be exposed on the public Internet, your admins must be able to connect to it, even if through a private IP or VPN. Additionally, Unlocker must be able to make outgoing HTTPS requests.

TODO: CONFIGURE, TLS CERT, AND START WITH DOCKER

### Wrapping a key

To wrap (encrypt) a key, first make a POST request to the **`/wrap`** endpoint. The POST request's body must be a JSON document containing the following keys:

- **`value`** (string, base64-encoded): This is the key that you want to wrap. It must be encoded as base64 (Unlocker supports both base64 standard and URL-safe encoding, and padding is optional).
- **`vault`** (string): The name of the Azure Key Vault where the wrapping key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest key.
  - **`timeout`** (integer): An optional timeout for the operation, in seconds; default is 300 seconds (or 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.

For example, with curl and the sample data above (note that `aGVsbG93b3JsZA==` is the base64-encoded representation of `helloworld`, the key we want to encrypt; we are also setting an optional timeout of 10 minutes, or 600 seconds):

```sh
curl https://10.20.30.40:8080/wrap \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myunlockerkv","keyId":"wrappingkey1","value":"aGVsbG93b3JsZA==","timeout":600}'
```

> Note: in all the examples we're using the `--insecure` flag to tell curl to accept self-signed TLS certificates. If you are using a TLS certificate signed by a Certification Authority, you can (and should) omit that flag.

The response will be a JSON object similar to this, where `state` is the ID of the request.

```json
{
  "state":"4336d140-2ba1-4d7a-af84-a83d564e384b",
  "pending":true
}
```

At this point the administrator should receive a notification through the webhook configured in the app. The notification contains a link they can click on to confirm or deny the operation; if they don't take action before the timeout, the request is automatically canceled. The administrator will need to authenticate with their Azure AD account that has permission to use the key in the Key Vault, and then will have to confirm the operation.

Your application can obtain the key by making a GET request to the `/result/:state` endpoint, such as:

```sh
STATE_ID="4336d140-2ba1-4d7a-af84-a83d564e384b"
curl --insecure https://10.20.30.40:8080/result/${STATE_ID}
```

> You can automatically set the value of the `STATE_ID` variable from the `/wrap` request using jq:
>
> ```sh
> STATE_ID=$(\
>   curl https://10.20.30.40:8080/wrap \
>     --insecure \
>     -H "Content-Type: application/json" \
>     --data '{"vault":"myunlockerkv","keyId":"wrappingkey1","value":"aGVsbG93b3JsZA==","timeout":600}' \
>   | jq -r .state
> )
> ```

The request to the `/result/:state` endpoint will hang until the operation is complete. Note that your client (or any network or proxy you're connecting through) may make the request time out before you can get the result. In this case, it's safe to re-invoke the request until you get status code of 200 (the response contains your wrapped key) or 400-499 (a 4xx status code happens when the request was denied or expired). Note that once you retrieve the response, the request and its result are removed from Unlocker and you won't be able to retrieve them again (unless you start a new request and get that approved again).

A **successful**, final response will contain a JSON body similar to:

```json
{
  "state":"a6dfdcea-3330-4f55-91f7-2ec9ea02370a",
  "done":true,
  "value":"pftzpouF10Dvg1dFcHuxk1sHr3dVauTydCyJS4NRl2rQrWK6ZpGgZCIArX+svYaYo3vYYqvxGzJIeqDTCr11fM4HbqgHO/W9HR8lQZKsIbeyfq1gLQ3sBGrpTwa5HABU889387AjXDshhEHI6L9D7JHBzKE1+eXWhQL9RtxbnfsHTQ49nCS5AXLetzDuwJRxWSZzTqNu8XILsEv91y41jtc8LOxOpDudc3tRJ6KNNNxCsehnuzBmZPqh/OhAH8AHZz1gESQGhRQKiZVgobLT7uzGlv0zPqTU2jbp1swF7apADnjdcUl93nYeBaOH3KqXs1PK12C14fV6qfwTMTsQTRM6OFB2FYTGeGoq5Gfo8FtnK7/oIIDtqo2RaK+83SexM1Fe3GNw7dU3zckGCpVjzLtHJZiYcP5VnybmFPmFV1RrsEnR4aMAigFkFEE/oZcsS8ZDwtwRPGGUEoCpZw8vqCzk1/2rtHmwkcSRCuoGR0s2yR9t889hc3C5r490zP+qGZ7fh/jBizXvJMCYjYA4z/A5LXOTENGEq3Mq0SWlh6+zxaP95+sKho7P3pHsIf9mK6VLWm2jhbWADx9R59DIoP6nKRtYivEk7UoI7tV9N7krgD1sMzK/Kk4YXu7mETAQR8o77Vo5dX+UJgF+jsNPrkG16x8TInKCeDYawMlxVIk="
}
```

The `value` field contains the wrapped key, encoded using base64 "standard encoding" with padding included (per [RFC 4648 section 4](https://datatracker.ietf.org/doc/html/rfc4648#section-4)).

Because this value is wrapped, so encrypted, it's safe to store it on your server, next to the application that needs it. When you need the original key (`helloworld`) you can then use the `/unwrap` method to have the key unwrapped as we'll see in the next section.

### Unwrapping a key

The process for unwrapping a key is similar to the one for wrapping a key presented in the previous section. Unwrapping a key means retrieving the original, plain-text key, letting Azure Key Vault perform the unwrapping (decryption) using the RSA key stored in the vault.

To unwrap a key, first make a POST request to the **`/unwrap`** endpoint. The POST request's body must be a JSON document containing the following keys (same as in the `/wrap` request, but the value is the wrapped key):

- **`value`** (string, base64-encoded): This is the wrapped key, encoded as base64 (Unlocker supports both base64 standard and URL-safe encoding, and padding is optional).
- **`vault`** (string): The name of the Azure Key Vault where the wrapping key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest key.
  - **`timeout`** (integer): An optional timeout for the operation, in seconds; default is 300 seconds (or 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.

For example, to unwrap the key wrapped above with curl, we can make this request (note that the `value` field contains the key that was wrapped earlier, partially omitted here for legibility):

```sh
curl https://10.20.30.40:8080/unwrap \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myunlockerkv","keyId":"wrappingkey1","value":"pftzpou...MlxVIk="}'
```

The response will be a JSON object similar to this, where `state` is the ID of the request.

```json
{
  "state":"4336d140-2ba1-4d7a-af84-a83d564e384b",
  "pending":true
}
```

The rest of the process is identical to the one you followed to wrap a key.

> Just as above, you can pipe the curl request to jq to get the state in a `STATE_ID` variable automatically:
>
> ```sh
> STATE_ID=$(\
>   curl https://10.20.30.40:8080/unwrap \
>     --insecure \
>     -H "Content-Type: application/json" \
>     --data '{"vault":"myunlockerkv","keyId":"wrappingkey1","value":"pftzpou...MlxVIk="}' \
>   | jq -r .state
> )
> ```

The administrator will receive another notification through the webhook configured in the app. They will be asked to sign in with their Azure AD account and confirm or deny the operation before it times out.

Just as when wrapping a key, your application can invoke the `/result/:state` method to check the status of the request. This will block until the operation is complete, and the result will contain the unwrapped key (base64-encoded):

```sh
curl --insecure https://10.20.30.40:8080/result/${STATE_ID}
```

A **successful**, final response will contain a JSON body similar to:

```json
{
  "state":"a6dfdcea-3330-4f55-91f7-2ec9ea02370a",
  "done":true,
  "value":"aGVsbG93b3JsZA=="
}
```

You can notice that the `value` field contains the plain-text key encoded as base64 (standard encoding, with padding). `aGVsbG93b3JsZA==` is the base64-encoded representation of `helloworld`, our example key.

Just as before, note that requests to `/result/:state` may time out because of your client or the network. If your request times out, you should make another request to `/result/:state` until you get a 200 status code (success) or 400-499 status code (an error, such as request denied or expired). Note that once you retrieve the response, the request and its result are removed from Unlocker and you won't be able to retrieve them again (unless you start a new request and get that approved again).

Using curl and jq, you can retrieve the raw (decoded) key to pipe it directly to an application that needs to consume it with:

```sh
curl --insecure https://10.20.30.40:8080/result/${STATE_ID} \
  | jq -r .value \
  | base64 --decode
```

The command above will print the unwrapped key (in our case `helloworld`), in plain text. You can redirect that to a file (adding `> file-name`) or to another app (with a pipe `|`).

## Set up

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
APP_URL="https://10.20.30.40:8080"
# Can be a hostname
APP_URL="https://my-unlocker.local:8080"
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
