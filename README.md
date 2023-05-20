# Revaulter v1.0-beta.1

Revaulter lets you perform cryptographic operations with keys stored on [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview), securely after getting consent from an admin. You can use Revaulter for:

- Encrypting and decrypting messages
- Wrapping and unwrapping encryption keys
- Calculating and verifying digital signatures

Revaulter works with Azure Key Vault, where your cryptographic keys (RSA, elliptic curve, and symmetric) are stored safely. You can build applications that interact with Revaulter to perform cryptographic operations that are completed in the key vault, only after a user with sufficient permission authorizes it.

Some example usages:

- Revaulter can be used to provide an encryption key for starting a long-running application, such as [unlocking encrypted drives at boot time](https://withblue.ink/2020/01/19/auto-mounting-encrypted-drives-with-a-remote-key-on-linux.html). This way, your encryption keys can be stored on your server safely in a wrapped (encrypted) format. By requiring explicit consent from an admin, you can be confident that no one can unwrap your encryption keys without your knowledge and permission.
- You can use Revaulter as part of a CI/CD pipeline to digitally sign your binaries.
- Or, you can use Revaulter as a generic tool to encrypt or decrypt messages.

# How it works

Revaulter exposes two endpoints that can be used to perform cryptographic operations, including: encrypting and decrypting arbitrary data, wrapping and unwrapping keys, calculating and verifying digital signatures. These operations are performed on Azure Key Vault, a safe, cloud-based key vault that uses strong keys, including RSA (up to 4096 bits), ECDSA (with NIST curves including P-256, P-384, and P-521), and AES (on Managed HSM Azure Key Vault only).

Revaulter doesn't have standing permission to perform operations on the vault, so every time a request comes in, Revaulter sends a notification to an admin (via a webhook), who can sign into Revaulter via Azure AD and allow (or deny) the operation.

Revaulter uses delegated permissions to access the Key Vault, so access is restricted to specific users via Role-Based Access Control on the Azure Key Vault resource.

![Example of a notification sent by Revaulter (to a Discord chat)](/notification-example.png)

# Using Revaulter

In this section we'll be looking at how to wrap and unwrap a key, which in our example is `helloworld`; Revaulter supports any kind of keys and keyfiles, for both symmetric and asymmetric ciphers.

We will use a key called `wrappingkey1` stored inside an Azure Key Vault called `myrevaulterkv`. We also assume that Revaulter is available at the address `https://10.20.30.40:8080`.

> Read the [**Set up**](#set-up) section below for how to set up your Revaulter app, the relevant resources on Azure, and how to generate a key inside Key Vault.

## Configure and start Revaulter

Revaulter runs as a lightweight app on a server you control that exposes a HTTPS endpoint. You can install it on the same server where your application that requires the cryptographic key runs or on a separate machine.

> **Firewall rules:** Revaulter must be deployed on a server that admins can connect to via HTTPS, on a port of your choice. While Revaulter doesn't need to be exposed on the public Internet, your admins must be able to connect to it, even if through a private IP or VPN. Additionally, Revaulter must be able to make outgoing HTTPS requests.

### Configuration

Revaulter requires a configuration file `config.yaml` in one of the following paths:

- `/etc/revaulter/config.yaml`
- `$HOME/.revaulter/config.yaml`
- Or in the same folder where the Revaulter binary is located

> You can specify a custom configuration file using the `REVAULTER_CONFIG` environmental variable.

You can find an example of the configuration file, and a description of every option, in the [`config.sample.yaml`](/config.sample.yaml) file.

Keys can also be passed as environmental variables with the `REVAULTER_` prefix.

All configuration options:

- Azure credentials:
  - **`azureClientId`** (**required**):  
    Client ID of the Azure AD application (see the [Azure AD application](#azure-ad-application) step in the [Set up](#set-up) section below).  
    Environmental variable name: `REVAULTER_AZURECLIENTID`
  - **`azureTenantId`** (**required**):  
    Tenant ID of the Azure AD application.  
    Environmental variable name: `REVAULTER_AZURETENANTID`
- Webhooks:
  - **`webhookUrl`** (**required**):  
    Endpoint of the webhook, where notifications are sent to.  
    Environmental variable name: `REVAULTER_WEBHOOKURL`
  - **`webhookFormat`** (optional, default: `plain`):  
    The format for the webhook. Currently, these values are supported:
    - `plain` (default): sends a webhook with content type `text/plain`, where the request's body is the entire message.
    - `slack`: for usage with Slack or Slack-compatible endpoints
    - `discord`: for usage with Discord (sends Slack-compatible messages)  
    Environmental variable name: `REVAULTER_WEBHOOKFORMAT`
  - **`webhookKey`** (optional):  
    Value for the Authorization header send with the webhook request. Set this if your webhook requires it.  
    Environmental variable name: `REVAULTER_WEBHOOKKEY`
- Revaulter application:
  - **`baseUrl`** (optional but **recommended**, default: `https://localhost:8080`):  
    The URL your application can be reached at. This is used in the links that are sent in webhook notifications.  
    Environmental variable name: `REVAULTER_BASEURL`
  - **`port`** (optional, default: `8080`):  
    Port to bind to.  
    Environmental variable name: `REVAULTER_PORT`
  - **`bind`** (optional, default: `0.0.0.0`):  
    Address/interface to bind to.  
    Environmental variable name: `REVAULTER_BIND`
  - **`tlsPath`**: (optional, defaults to the same folder as the `config.yaml` file):  
    Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem`. Revaulter watches for changes in this folder and automatically reloads the TLS certificates when they're updated.  
    If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.  
    Note that while this value is optional, a TLS certificate is **required** (even if self-signed).  
    Environmental variable name: `REVAULTER_TLSPATH`
  - **`tlsCertPEM`** (optional):  
    Full, PEM-encoded TLS certificate. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.  
    Environmental variable name: `REVAULTER_TLSCERTPEM`
  - **`tlsKeyPEM`** (optional):  
    Full, PEM-encoded TLS key. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.  
    Environmental variable name: `REVAULTER_TLSKEYPEM`
  - **`allowedIps`** (optional):  
    If set, allows connections to the APIs only from the IPs or ranges set here. You can set individual IP addresses (IPv4 or IPv6) or ranges in the CIDR notation, and you can add multiple values separated by commas. For example, to allow connections from localhost and IPs in the `10.x.x.x` range only, set this to: `127.0.0.1,10.0.0.0/8`.  
    Note that this value is used to restrict connections to the `/wrap`, `/unwrap`, and `/status` endpoints only. It does not restrict the endpoints used by administrators to confirm (or deny) requests.  
    Environmental variable name: `REVAULTER_ALLOWEDIPS`
  - **`origins`** (optional, default is equal to the value of `baseUrl`):  
    Comma-separated lists of origins that are allowed for CORS. This should be a list of all URLs admins can access Revaulter at. Alternatively, set this to `*` to allow any origin (not recommended).  
    Environmental variable name: `REVAULTER_ORIGINS`
  - **`sessionTimeout`** (optional, default: `5m`)  
    Timeout for sessions before having to authenticate again, as a Go duration. This cannot be more than 1 hour.  
    Environmental variable name: `REVAULTER_SESSIONTIMEOUT`
  - **`requestTimeout`** (optional, default: `5m`):  
    Default timeout for wrap and unwrap requests, as a Go duration. This is the default value, and can be overridden in each request.  
    Environmental variable name: `REVAULTER_REQUESTTIMEOUT`
  - **`enableMetrics`** (optional, default: `false`):
    Enable the metrics server which exposes a Prometheus-compatible endpoint `/metrics`.
    Environmental variable name: `REVAULTER_ENABLEMETRICS`
  - **`metricsPort`** (optional, default: `2112`):  
    Port for the metrics server to bind to.  
    Environmental variable name: `REVAULTER_METRICSPORT`
  - **`metricsBind`** (optional, default: `0.0.0.0`):  
    Address/interface for the metrics server to bind to.  
    Environmental variable name: `REVAULTER_METRICSBIND`
  - **`tokenSigningKey`** (optional, will be randomly generated at startup if empty):  
    String used as key to sign state tokens. If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).  
    Environmental variable name: `REVAULTER_TOKENSIGNINGKEY`
  - **`cookieEncryptionKey`** (optional, will be randomly generated at startup if empty):  
    String used as key to encrypt cookies. If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).  
    Environmental variable name: `REVAULTER_COOKIEENCRYPTIONKEY`
  - **`trustedRequestIdHeader`** (optional):  
    String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.  
    Common values can include:

    - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id ) that's vendor agnostic
    - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)

    If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
    Environmental variable name: `REVAULTER_TRUSTEDREQUESTIDHEADER`
  - **`logLevel`** (optional, default: `info`):  
    Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
    Environmental variable name: `REVAULTER_LOGLEVEL`

> To generate a self-signed TLS certificate, you can use OpenSSL, for example:
>
> ```sh
> openssl req -x509 -newkey rsa:4096 -keyout tls-key.pem -out tls-cert.pem -days 730 -nodes
> ```

### Start with Docker

You can run Revaulter in a Docker container. Docker container images are available for Linux and support amd64, arm64, and armv7/armhf.

First, create a folder where you will store the configuration file `config.yaml` and the TLS certificate and key (`tls-cert.pem` and `tls-key.pem`), for example `$HOME/.revaulter`.

You can then start Revaulter with:

```sh
docker run \
  -d \
  -p 8080:8080 \
  -v $HOME/.revaulter:/etc/revaulter \
  ghcr.io/italypaleale/revaulter:1.0
```

> Revaulter follows semver for versioning. The command above uses the latest version in the 1.0 branch. We do not publish a container image tagged "latest".

### Start as standalone app

If you don't want to (or can't) use Docker, you can download the latest version of Revaulter from the [Releases](https://github.com/italypaleale/revaulter/releases) page. Fetch the correct archive for your system and architecture, then extract the files and copy the `revaulter` binary to `/usr/local/bin` or another folder.

Place the configuration for Revaulter in the `/etc/revaulter` folder, including the `config.yaml` file and the TLS certificate and key (`tls-cert.pem` and `tls-key.pem`).

You will need to start Revaulter as a service using the process manager for your system. For modern Linux distributions based on **systemd**, you can use this unit. Copy this file to `/etc/systemd/system/revaulter.service`:

```conf
[Unit]
Description=Revaulter service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
# Specify the user and group to run Revaulter as
User=daemon
Group=daemon
Restart=always
RestartSec=30
# Path where revaulter is installed
ExecStart=/usr/local/bin/revaulter

[Install]
WantedBy=multi-user.target
```

Start the service and enable it at boot with:

```sh
systemctl enable --now revaulter
```

Using systemd, you can make your own services depend on Revaulter by adding `revaulter.service` as a value for `Wants=` and `After=` in the unit files.

## APIs

There are two main API endpoints you and your application will interact with:

- First, you wrap your keys using the `/wrap` endpoint (see [Wrapping a key](#wrapping-a-key)). This needs to be done just once for each key. You will receive a wrapped (ie. encrypted) key that you can safely store alongside your application.
- Every time your application needs to retrieve the key (usually when the application starts), it should make a call to the `/unwrap` endpoint (see [Unwrapping a key](#unwrapping-a-key)).

Both the `/wrap` and `/unwrap` endpoints return a unique operation ID ("state") that your application can then use with the `/result` endpoint to retrieve the wrapped or unwrapped key after an admin approved the request. Read below for details on how it works.

### Wrapping a key

To wrap (encrypt) a key, first make a POST request to the **`/wrap`** endpoint. The POST request's body must be a JSON document containing the following keys:

- **`value`** (string, base64-encoded): This is the key that you want to wrap. It must be encoded as base64 (Revaulter supports both base64 standard and URL-safe encoding, and padding is optional).
- **`vault`** (string): The name of the Azure Key Vault where the wrapping key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest key.
  - **`timeout`** (integer): An optional timeout for the operation, in seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 300 seconds, or 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`note`** (string): A freeform message that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.

For example, with curl and the sample data above (note that `aGVsbG93b3JsZA==` is the base64-encoded representation of `helloworld`, the key we want to encrypt; we are also setting an optional timeout of 10 minutes, or 600 seconds):

```sh
curl https://10.20.30.40:8080/wrap \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"aGVsbG93b3JsZA==","timeout":600,"note":"The secret"}'
```

> Note: in all the examples we're using the `--insecure` flag to tell curl to accept self-signed TLS certificates. If you are using a TLS certificate signed by a Certification Authority, you can (and should) omit that flag.

The response will be a JSON object similar to this, where `state` is the ID of the request.

```json
{
  "state": "4336d140-2ba1-4d7a-af84-a83d564e384b",
  "pending": true
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
>     --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"aGVsbG93b3JsZA==","timeout":600}' \
>   | jq -r .state
> )
> ```

The request to the `/result/:state` endpoint will hang until the operation is complete. Note that your client (or any network or proxy you're connecting through) may make the request time out before you can get the result. In this case, it's safe to re-invoke the request until you get status code of 200 (the response contains your wrapped key) or 400-499 (a 4xx status code happens when the request was denied or expired). Note that once you retrieve the response, the request and its result are removed from Revaulter and you won't be able to retrieve them again (unless you start a new request and get that approved again).

A **successful**, final response will contain a JSON body similar to:

```json
{
  "state": "a6dfdcea-3330-4f55-91f7-2ec9ea02370a",
  "done": true,
  "value": "pftzpouF10Dvg1dFcHuxk1sHr3dVauTydCyJS4NRl2rQrWK6ZpGgZCIArX+svYaYo3vYYqvxGzJIeqDTCr11fM4HbqgHO/W9HR8lQZKsIbeyfq1gLQ3sBGrpTwa5HABU889387AjXDshhEHI6L9D7JHBzKE1+eXWhQL9RtxbnfsHTQ49nCS5AXLetzDuwJRxWSZzTqNu8XILsEv91y41jtc8LOxOpDudc3tRJ6KNNNxCsehnuzBmZPqh/OhAH8AHZz1gESQGhRQKiZVgobLT7uzGlv0zPqTU2jbp1swF7apADnjdcUl93nYeBaOH3KqXs1PK12C14fV6qfwTMTsQTRM6OFB2FYTGeGoq5Gfo8FtnK7/oIIDtqo2RaK+83SexM1Fe3GNw7dU3zckGCpVjzLtHJZiYcP5VnybmFPmFV1RrsEnR4aMAigFkFEE/oZcsS8ZDwtwRPGGUEoCpZw8vqCzk1/2rtHmwkcSRCuoGR0s2yR9t889hc3C5r490zP+qGZ7fh/jBizXvJMCYjYA4z/A5LXOTENGEq3Mq0SWlh6+zxaP95+sKho7P3pHsIf9mK6VLWm2jhbWADx9R59DIoP6nKRtYivEk7UoI7tV9N7krgD1sMzK/Kk4YXu7mETAQR8o77Vo5dX+UJgF+jsNPrkG16x8TInKCeDYawMlxVIk="
}
```

The `value` field contains the wrapped key, encoded using base64 "standard encoding" with padding included (per [RFC 4648 section 4](https://datatracker.ietf.org/doc/html/rfc4648#section-4)).

The `/result/:state` endpoint accepts an optional `?raw=1` parameter that makes the response contain the (wrapped) key only, as binary data. For example:

```sh
STATE_ID="4336d140-2ba1-4d7a-af84-a83d564e384b"
curl --insecure "https://10.20.30.40:8080/result/${STATE_ID}?raw=1"
# A successful response will contain binary data
```

Because this value is wrapped, so encrypted, it's safe to store it on your server, next to the application that needs it. When you need the original key (`helloworld`) you can then use the `/unwrap` method to have the key unwrapped as we'll see in the next section.

### Unwrapping a key

The process for unwrapping a key is similar to the one for wrapping a key presented in the previous section. Unwrapping a key means retrieving the original, plain-text key, letting Azure Key Vault perform the unwrapping (decryption) using the RSA key stored in the vault.

To unwrap a key, first make a POST request to the **`/unwrap`** endpoint. The POST request's body must be a JSON document containing the following keys (same as in the `/wrap` request, but the value is the wrapped key):

- **`value`** (string, base64-encoded): This is the wrapped key, encoded as base64 (Revaulter supports both base64 standard and URL-safe encoding, and padding is optional).
- **`vault`** (string): The name of the Azure Key Vault where the wrapping key is stored.
- **`keyId`** (string): The name of the key stored in the Key Vault.
- Optional keys:
  - **`keyVersion`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest key.
  - **`timeout`** (integer): An optional timeout for the operation, in seconds. If empty, the value is taken from the configuration option `requestTimeout` (whose default value is 300 seconds, or 5 minutes). If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.

For example, to unwrap the key wrapped above with curl, we can make this request (note that the `value` field contains the key that was wrapped earlier, partially omitted here for legibility):

```sh
curl https://10.20.30.40:8080/unwrap \
  --insecure \
  -H "Content-Type: application/json" \
  --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"pftzpou...MlxVIk="}'
```

The response will be a JSON object similar to this, where `state` is the ID of the request.

```json
{
  "state": "4336d140-2ba1-4d7a-af84-a83d564e384b",
  "pending": true
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
>     --data '{"vault":"myrevaulterkv","keyId":"wrappingkey1","value":"pftzpou...MlxVIk="}' \
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
  "state": "a6dfdcea-3330-4f55-91f7-2ec9ea02370a",
  "done": true,
  "value": "aGVsbG93b3JsZA=="
}
```

You can notice that the `value` field contains the plain-text key encoded as base64 (standard encoding, with padding). `aGVsbG93b3JsZA==` is the base64-encoded representation of `helloworld`, our example key.

Just as before, note that requests to `/result/:state` may time out because of your client or the network. If your request times out, you should make another request to `/result/:state` until you get a 200 status code (success) or 400-499 status code (an error, such as request denied or expired). Note that once you retrieve the response, the request and its result are removed from Revaulter and you won't be able to retrieve them again (unless you start a new request and get that approved again).

Using curl and jq, you can retrieve the raw (decoded) key to pipe it directly to an application that needs to consume it with:

```sh
curl --insecure https://10.20.30.40:8080/result/${STATE_ID} \
  | jq -r .value \
  | base64 --decode
```

The command above will print the unwrapped key (in our case `helloworld`), in plain text. You can redirect that to a file (adding `> file-name`) or to another app (with a pipe `|`).

Alternatively, the `/result/:state` endpoint accepts an optional `?raw=1` parameter that makes the response contain the unwrapped key only, as binary data. For example:

```sh
curl --insecure "https://10.20.30.40:8080/result/${STATE_ID}?raw=1"
# A successful response will contain binary data; in our example that would be "helloworld"
```

### Supported algorithms and keys

Revaulter can wrap and unwrap data using keys stored in Azure Key Vault only, either software-protected or HSM-protected.

Revaulter only supports RSA keys. Although all key sizes supported by Azure Key Vault can be used with Revaulter, we strongly recommend using 4096-bit keys for the best security.

Revaulter uses RSA-OAEP with SHA-256 (identified as `RSA-OAEP-256` in Azure Key Vault) as algorithm and mode of operation, to offer the best security. This value is not configurable.

## Set up

Before you can deploy and use Revaulter, you need to perform a few setup steps to create resources on Azure: a Key Vault and an Azure AD application that allows the admin to authenticate and allow or deny operations.

All the steps below must be run on your laptop before you deploy the app. At the end, you'll have the values required for the `config.yaml` file and for making requests to the service.

You will need an Azure subscription to deploy these services; if you don't have one, you can start a [free trial](https://azure.com/free). All the services we need for Revaulter are either free (Azure AD) or very inexpensive (for most scenarios, you should not spend more than a few cents on Azure Key Vault every month).

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
APP_URL="https://my-revaulter.local:8080"
```

This is the URL an admin will use to reach Revaulter. It doesn't need to be a public address, but it needs to be routable by an admin.

### Create a Resource Group on Azure

First, set the location where you want your resources to be created in:

```sh
LOCATION="WestUS2"
```

> You can get the full list of options with: `az account list-locations --output tsv`

Create a Resource Group. Give it a friendly name in the `RG_NAME` variable: it will only be used for displaying in the Azure Portal.

```sh
RG_NAME="Revaulter"
RG_ID=$(az group create \
  --name $RG_NAME \
  --location $LOCATION \
  | jq -r .id)
```

### Create the Azure Key Vault

Create a Key Vault. Set a name in the `KEYVAULT_NAME` variable, which must be globally unique:

```sh
KEYVAULT_NAME="myrevaulterkv"
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

Take note of the value of `KEYVAULT_KEY`, which will be used when making requests to the revaulter service.

> Important: the command above generates a new RSA key within the Key Vault and returns the public part of the key. Because keys cannot be extracted from Azure Key Vault, you will never see the private key, and there's no way to obtain that (you can, however, create backups that only work inside Azure Key Vault). If you need access to the private key, consider importing a key inside the Key Vault rather than having it generate a new one for you (e.g. [using the Azure CLI](https://docs.microsoft.com/en-us/cli/azure/keyvault/key?view=azure-cli-latest#az-keyvault-key-import)).

### Azure AD application

Create an app in Azure AD to access Azure Key Vault with an user's delegated permissions.

```sh
# Friendly name for the application
APP_NAME="Revaulter"

# Create the app and set the redirect URIs
APP_ID=$(az ad app create \
  --display-name $APP_NAME \
  --available-to-other-tenants false \
  --oauth2-allow-implicit-flow false \
  | jq -r .appId)
APP_OBJECT_ID=$(az ad app show --id $APP_ID | jq -r .id)
az rest \
  --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/${APP_OBJECT_ID}" \
  --body "{\"publicClient\":{\"redirectUris\":[\"${APP_URL}/auth/confirm\"]}}"

# Grant permissions for Azure Key Vault
az ad app permission add \
  --id $APP_ID \
  --api cfa8b339-82a2-471a-a3c9-0fc0be7a4093 \
  --api-permissions f53da476-18e3-4152-8e01-aec403e6edc0=Scope
```

Take note of the output of the last command, which includes the values for the `config.yaml` file:

- `appId` is the value for `azureClientId`
- `tenant` is the value for `azureTenantId`

> Note that the Azure AD application does not need permissions on the Key Vault. Instead, Revaulter uses delegated permissions, matching whatever access level the authenticated user has.
