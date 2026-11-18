<?php
declare(strict_types=1);
namespace Coinsnap\Http;

if (!defined('ABSPATH')) {
    exit;
}

use Coinsnap\Exception\ConnectException;

/**
 * HTTP Client using cURL to communicate.
 */
class WPRemoteClient implements ClientInterface {
    
    protected $wpRemoteOptions = [];

    /**
     * Kept for backward compatibility; the options are not applied.
     * TLS certificate verification is always on: never disable it (sslverify => false), even to fix a
     * hosting error, or anyone between the site and the API could send back a fake "paid" invoice.
     *
     * @deprecated Since 1.2.1. Has no effect.
     * @return void
     */
    public function setWpRemoteOptions(array $options){
        unset($options['sslverify']);
        $this->wpRemoteOptions = $options;
    }

    /**
     * @deprecated Since 1.2.1. Does nothing; kept so subclasses keep working.
     * @return void
     */
    protected function initWpRemote(){
    }

    public function request(string $method,string $url,array $headers = [],string $body = ''): ResponseInterface {
        
        $wpRemoteArgs = array(
            'body' => $body,
            'method' => $method,
            'timeout' => 5,
            'headers' => $headers,
            'sslverify' => true,
        );
        
        $response = wp_remote_request( $url, $wpRemoteArgs );
        
        if(is_wp_error( $response ) ) {
            $errorMessage = $response->get_error_message();
            $errorCode = $response->get_error_code();
            throw new ConnectException(esc_html($errorMessage), (int)esc_html($errorCode));
        }
        
        elseif(is_array($response)) {
            
            $status = $response['response']['code'];
            $responseHeaders = [];
            $responseBody = '';
            $responseHeaders = wp_remote_retrieve_headers($response)->getAll();
            $responseBody = $response['body'];
            return new Response((int) $status, (string) $responseBody, $responseHeaders);
        }

        throw new ConnectException('Unexpected HTTP response', 0);
    }
}