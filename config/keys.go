package config

const (
	KeyAllowedIps             = "allowedIps"
	KeyAzureClientId          = "azureClientId"
	KeyAzureClientSecret      = "azureClientSecret"
	KeyAzureTenantId          = "azureTenantId"
	KeyBaseUrl                = "baseUrl"
	KeyBind                   = "bind"
	KeyCookieEncryptionKey    = "cookieEncryptionKey"
	KeyEnableMetrics          = "enableMetrics"
	KeyMetricsBind            = "metricsBind"
	KeyMetricsPort            = "metricsPort"
	KeyOrigins                = "origins"
	KeyPort                   = "port"
	KeyRequestTimeout         = "requestTimeout"
	KeySessionTimeout         = "sessionTimeout"
	KeyTLSCert                = "tlsCert"
	KeyTLSKey                 = "tlsKey"
	KeyTokenSigningKey        = "tokenSigningKey"
	KeyTrustedRequestIdHeader = "trustedRequestIdHeader"
	KeyWebhookFormat          = "webhookFormat"
	KeyWebhookKey             = "webhookKey"
	KeyWebhookUrl             = "webhookUrl"

	// Keys starting with "dev." are undocumented and meant for development only
	KeyDevClientProxyServer = "dev.clientProxyServer"

	// Key starting with "internal." are set by the app at startup
	KeyInternalTokenSigningKey     = "internal.tokenSigningKey"
	KeyInternalCookieEncryptionKey = "internal.cookieEncryptionKey"
	KeyInternalCookieSigningKey    = "internal.cookieSigningKey"
)
