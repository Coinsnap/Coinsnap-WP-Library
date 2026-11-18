<?php
declare(strict_types=1);
namespace Coinsnap\Util;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Short-lived admin notices carried in a cookie.
 * The cookie is written by the browser, so it is stored and read as JSON, never with PHP object deserialization.
 */
class Notice {

    public function addNotice(string $type, string $content, $dismissible = 1){
        $notice_types_array = ['error','warning','success','info'];
        if(!in_array($type,$notice_types_array,true)){ $type = 'info'; }
        if(!empty($content)){
            $value = wp_json_encode(['type' => $type,'message' => $content, 'dismissible' => (bool) $dismissible]);
            if (!is_string($value) || headers_sent()) {
                return;
            }
            setcookie('coinsnap_notices['.hash('sha256',$content).']', $value, [
                'expires'  => time()+5,
                'path'     => '/',
                'secure'   => function_exists('is_ssl') && is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        }
    }

    public function showNotices(){
        if(!isset($_COOKIE['coinsnap_notices']) || !is_array($_COOKIE['coinsnap_notices'])){
            return;
        }
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- decoded as JSON and escaped on output
        foreach(wp_unslash($_COOKIE['coinsnap_notices']) as $coinsnap_notice){
            if (!is_string($coinsnap_notice)) {
                continue;
            }
            $notice = json_decode($coinsnap_notice, true);
            if (!is_array($notice) || !isset($notice['message']) || !is_string($notice['message'])) {
                continue; // not ours, or an old serialized value: ignore it
            }
            $type = (isset($notice['type']) && in_array($notice['type'], ['error','warning','success','info'], true)) ? $notice['type'] : 'info';
            $dismissible_add = !empty($notice['dismissible']) ? ' is-dismissible' : '';
            echo '<div class="notice notice-'.esc_attr($type.$dismissible_add).'"><p>'.esc_html(sanitize_text_field($notice['message'])).'</p></div>';
        }
    }
}
