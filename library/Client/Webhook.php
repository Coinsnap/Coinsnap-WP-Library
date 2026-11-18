<?php
declare(strict_types=1);
namespace Coinsnap\Client;

if (!defined('ABSPATH')) {
    exit;
}

class Webhook extends AbstractClient {
    
    public function getWebhook(string $storeId, string $webhookId): \Coinsnap\Result\Webhook {
        $url = $this->getApiUrl() . ''.COINSNAP_SERVER_PATH.'/' . urlencode($storeId) . '/webhooks/' . urlencode($webhookId);
        $headers = $this->getRequestHeaders();
        $method = 'GET';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() === 200) {
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);            
            return new \Coinsnap\Result\Webhook($data);
        }
        else {
            throw $this->getExceptionByStatusCode(esc_html($method), esc_url($url), (int)esc_html($response->getStatus()), esc_html($response->getBody()));
        }
    }

    public function createWebhook(string $storeId, string $url, ?array $specificEvents, ?string $secret, bool $enabled = true, bool $automaticRedelivery = true): \Coinsnap\Result\WebhookCreated {
        $data = [
            'enabled' => $enabled,
            'automaticRedelivery' => $automaticRedelivery,
            'url' => $url
        ];

        if ($specificEvents === null) {
            $data['authorizedEvents'] = ['everything' => true];
        } 
        elseif (count($specificEvents) === 0) {
            throw new \InvalidArgumentException('Argument $specificEvents should be NULL or contains at least 1 item.');
        } 
        else {
            $data['authorizedEvents'] = ['everything' => false,'specificEvents' => $specificEvents];
        }

        if ($secret === '') {
            throw new \InvalidArgumentException('Argument $secret should be NULL (let Server auto-generate a secret) or you should provide a long and safe secret string.');
        } 
        elseif ($secret !== null){
            $data['secret'] = $secret;
        }

        $url = $this->getApiUrl() . ''.COINSNAP_SERVER_PATH.'/' . urlencode($storeId) . '/webhooks';
        $headers = $this->getRequestHeaders();
        $method = 'POST';
        $response = $this->getHttpClient()->request($method, $url, $headers, wp_json_encode($data, JSON_THROW_ON_ERROR));

        if ($response->getStatus() === 200) {
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            return new \Coinsnap\Result\WebhookCreated($data);
        }
        else {
            throw $this->getExceptionByStatusCode(esc_html($method), esc_url($url), (int)esc_html($response->getStatus()), esc_html($response->getBody()));
        }
    }

    /**
     * Updates an existing webhook.
     *
     * @return \Coinsnap\Result\Webhook
     * @throws \JsonException
     */
    public function updateWebhook(
        string $storeId,
        string $url,
        string $webhookId,
        ?array $specificEvents,
        bool $enabled = true,
        bool $automaticRedelivery = true,
        ?string $secret = null): \Coinsnap\Result\Webhook {
        
        $data = [
          'enabled' => $enabled,
          'automaticRedelivery' => $automaticRedelivery,
          'url' => $url,
          'secret' => $secret
        ];

        // Specific events or all.
        if ($specificEvents === null) {
            $data['authorizedEvents'] = ['everything' => true];
        }
        elseif (count($specificEvents) === 0) {
            throw new \InvalidArgumentException('Argument $specificEvents should be NULL or contains at least 1 item.');
        }
        else {
            $data['authorizedEvents'] = [
              'everything' => false,
              'specificEvents' => $specificEvents
            ];
        }

        $url = $this->getApiUrl() . ''.COINSNAP_SERVER_PATH.'/' . urlencode($storeId) . '/webhooks/' . urlencode($webhookId);
        $headers = $this->getRequestHeaders();
        $method = 'PUT';
        $response = $this->getHttpClient()->request($method, $url, $headers, wp_json_encode($data, JSON_THROW_ON_ERROR));

        if ($response->getStatus() === 200) {
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            return new \Coinsnap\Result\Webhook($data);
        } else {
            throw $this->getExceptionByStatusCode(esc_html($method), esc_url($url), (int)esc_html($response->getStatus()), esc_html($response->getBody()));
        }
    }

    /** Maximum age of a timestamped X-Coinsnap-Signature, in seconds. */
    public const SIGNATURE_TOLERANCE = 300;

    /**
     * Check a Coinsnap webhook: header "X-Coinsnap-Signature: t=<unix time>,v1=<hex>",
     * where v1 = HMAC-SHA256(secret, "<t>.<raw body>"). Timing-safe; an empty secret rejects everything;
     * a timestamp more than SIGNATURE_TOLERANCE seconds away from now is refused.
     *
     * @param string   $rawBody         The raw request body, exactly as received.
     * @param string   $signatureHeader The X-Coinsnap-Signature header value.
     * @param string   $secret          This plugin's own webhook secret for this store.
     * @param int|null $now             Current unix time (for tests); defaults to time().
     */
    public static function isValidCoinsnapSignature(string $rawBody, string $signatureHeader, string $secret, ?int $now = null, int $tolerance = self::SIGNATURE_TOLERANCE): bool {
        return self::coinsnapSignatureError($rawBody, $signatureHeader, $secret, $now, $tolerance) === null;
    }

    /**
     * Like isValidCoinsnapSignature(), but returns why it failed, for the log:
     * null when valid, otherwise the fixed reason 'bad signature' or 'stale timestamp'.
     * Never log the header, the body or the secret.
     */
    public static function coinsnapSignatureError(string $rawBody, string $signatureHeader, string $secret, ?int $now = null, int $tolerance = self::SIGNATURE_TOLERANCE): ?string {
        $t = 0;
        $v1 = '';
        foreach (explode(',', $signatureHeader) as $part) {
            $kv = explode('=', trim($part), 2);
            if (count($kv) !== 2) {
                continue;
            }
            if ($kv[0] === 't' && ctype_digit($kv[1])) {
                $t = (int) $kv[1];
            } elseif ($kv[0] === 'v1') {
                $v1 = strtolower($kv[1]);
            }
        }
        if ($secret === '' || $t <= 0 || $v1 === '') {
            return 'bad signature';
        }
        $expected = hash_hmac('sha256', $t . '.' . $rawBody, $secret);
        if (!hash_equals($expected, $v1)) {
            return 'bad signature';
        }
        if (abs(($now ?? time()) - $t) > $tolerance) {
            return 'stale timestamp';
        }
        return null;
    }

    /**
     * Check a BTCPay webhook: header "BTCPay-Sig: sha256=<hex>", HMAC-SHA256(secret, raw body).
     * Compared including the "sha256=" prefix, timing-safe; an empty secret rejects everything.
     * BTCPay signatures carry no time, so also act on each invoice only once.
     */
    public static function isValidBTCPaySignature(string $rawBody, string $signatureHeader, string $secret): bool {
        if ($secret === '' || $signatureHeader === '') {
            return false;
        }
        $expected = 'sha256=' . hash_hmac('sha256', $rawBody, $secret);
        return hash_equals($expected, $signatureHeader);
    }

    /**
     * The only field a webhook handler should take from the body. Returns '' when there is none.
     * Fetch the invoice with Invoice::fetchInvoice() and decide from the API's answer.
     */
    public static function getInvoiceIdFromBody(string $rawBody): string {
        $data = json_decode($rawBody, true);
        $id = (is_array($data) && isset($data['invoiceId']) && is_string($data['invoiceId'])) ? $data['invoiceId'] : '';
        return preg_match('/^[A-Za-z0-9_-]{1,64}$/', $id) ? $id : '';
    }

    /**
     * Check if the request your received from a webhook is authentic ("sha256=<hex>" over the body).
     *
     * @deprecated Since 1.2.1. The old X-Coinsnap-Sig header has no timestamp, so a captured webhook can be
     *             replayed. Use isValidCoinsnapSignature() with X-Coinsnap-Signature for Coinsnap, and
     *             isValidBTCPaySignature() for BTCPay. Now timing-safe and refuses an empty secret.
     */
    public static function isIncomingWebhookRequestValid(string $requestBody, string $coinsnapSignatureHeader, string $secret): bool{
        if ($requestBody === '' || $coinsnapSignatureHeader === '' || $secret === '') {
            return false;
        }
        $expectedHeader = 'sha256='.hash_hmac('sha256', $requestBody, $secret);
        return hash_equals($expectedHeader, $coinsnapSignatureHeader);
    }

    public function deleteWebhook(string $storeId, string $webhookId): void {
        $url = $this->getApiUrl() . ''.COINSNAP_SERVER_PATH.'/' . urlencode($storeId) . '/webhooks/' . urlencode($webhookId);
        $headers = $this->getRequestHeaders();
        $method = 'DELETE';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() !== 204 && $response->getStatus() !== 200) {
            throw $this->getExceptionByStatusCode(esc_html($method), esc_url($url), (int)esc_html($response->getStatus()), esc_html($response->getBody()));
        }
    }

    /**
     * Get all webhooks for a specific store
     * @param string $storeId
     * @return \Coinsnap\Result\Webhook[]
     */
    public function getWebhooks(string $storeId): array
    {
        $url = $this->getApiUrl() . ''.COINSNAP_SERVER_PATH.'/' . urlencode($storeId) . '/webhooks';
        $headers = $this->getRequestHeaders();
        $method = 'GET';
        $response = $this->getHttpClient()->request($method, $url, $headers);

        if ($response->getStatus() === 200) {
            $r = [];
            $data = json_decode($response->getBody(), true, 512, JSON_THROW_ON_ERROR);
            foreach ($data as $item) {
                $item = new \Coinsnap\Result\Webhook($item);
                $r[] = $item;
            }
            return $r;
        } else {
            throw $this->getExceptionByStatusCode(esc_html($method), esc_url($url), (int)esc_html($response->getStatus()), esc_html($response->getBody()));
        }
    }
}
