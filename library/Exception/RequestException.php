<?php
declare(strict_types=1);
namespace Coinsnap\Exception;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * A non-success reply from the Coinsnap or BTCPay API.
 *
 * The message names the method, the API path with every ID masked (/stores/{id}/invoices/{id}) and the
 * HTTP status. It never contains the store ID or the raw reply, which can echo request data, so it is safe
 * for logs. The raw reply is available from getResponseBody() for debugging; never show or log it.
 */
class RequestException extends CSException {
    /** @var int */
    private $status;
    /** @var string */
    private $responseBody;

    public function __construct(string $method, string $url, int $status, string $body){
        $this->status = $status;
        $this->responseBody = $body;
        $message = 'Error during ' . $method . ' to ' . self::maskUrl($url) . '. Got response (' . $status . ')';
        parent::__construct($message, $status);
    }

    public function getStatus(): int {
        return $this->status;
    }

    /** The raw API reply. Do not log it or show it to users. */
    public function getResponseBody(): string {
        return $this->responseBody;
    }

    /** Replace the IDs in an API URL: /stores/abc/invoices/xyz -> /stores/{id}/invoices/{id}. Drops the query string. */
    public static function maskUrl(string $url): string {
        $url = (string) preg_replace('/[?#].*$/', '', $url);
        return (string) preg_replace('#/(stores|invoices|webhooks|users|payment-requests|pull-payments|payouts|apps)/[^/]+#i', '/$1/{id}', $url);
    }
}
