<?php
/**
 * Plain PHP unit tests for the security-relevant classes, with minimal WordPress stubs.
 * Run: php tests/security-test.php
 */
if (PHP_SAPI !== 'cli') {
    exit;
}

define('ABSPATH', __DIR__ . '/');

$GLOBALS['transients'] = [];
$GLOBALS['wp_remote_calls'] = [];
$GLOBALS['wp_remote_reply'] = null;
function get_transient($k) { return $GLOBALS['transients'][$k] ?? false; }
function set_transient($k, $v, $e) { $GLOBALS['transients'][$k] = $v; return true; }
function delete_transient($k) { unset($GLOBALS['transients'][$k]); return true; }
function wp_json_encode($d, $o = 0) { return json_encode($d, $o); }
function esc_html($s) { return htmlspecialchars((string) $s, ENT_QUOTES); }
function esc_attr($s) { return htmlspecialchars((string) $s, ENT_QUOTES); }
function esc_url($s) { return (string) $s; }
function sanitize_text_field($s) { return trim(strip_tags((string) $s)); }
function wp_unslash($v) { return is_array($v) ? array_map('wp_unslash', $v) : stripslashes((string) $v); }
function is_wp_error($r) { return $r instanceof WP_Error; }
function is_ssl() { return true; }
class WP_Error { private $m; function __construct($c, $m) { $this->m = $m; } function get_error_message() { return $this->m; } function get_error_code() { return 'http_request_failed'; } }
class FakeHeaders { function getAll() { return []; } }
function wp_remote_retrieve_headers($r) { return new FakeHeaders(); }
function wp_remote_request($url, $args) { $GLOBALS['wp_remote_calls'][] = [$url, $args]; return $GLOBALS['wp_remote_reply']; }

require __DIR__ . '/../library/loader.php';

use Coinsnap\Client\BTCPayApiAuthorization;
use Coinsnap\Client\Invoice;
use Coinsnap\Client\Webhook;
use Coinsnap\Exception\ConnectException;
use Coinsnap\Exception\RequestException;
use Coinsnap\Http\ClientInterface;
use Coinsnap\Http\Response;
use Coinsnap\Http\ResponseInterface;
use Coinsnap\Http\WPRemoteClient;

class FakeClient implements ClientInterface {
    public $calls = [];
    private $replies;
    function __construct(array $replies) { $this->replies = $replies; }
    function request(string $method, string $url, array $headers = [], string $body = ''): ResponseInterface {
        $this->calls[] = compact('method', 'url', 'headers', 'body');
        $r = array_shift($this->replies);
        if ($r instanceof Throwable) { throw $r; }
        return new Response($r[0], $r[1], []);
    }
}

$fail = 0;
$pass = 0;
function ok($cond, $msg) { global $fail, $pass; echo ($cond ? 'PASS ' : 'FAIL ') . $msg . "\n"; $cond ? $pass++ : $fail++; }
function throws(callable $f, string $class): bool { try { $f(); } catch (Throwable $e) { return $e instanceof $class; } return false; }

// ---------------------------------------------------------------- Coinsnap signature
$body = '{"type":"Settled","invoiceId":"inv_1"}';
$now = 1_800_000_000;
$sign = function (int $t, string $secret, ?string $b = null) use ($body) { $b = $b ?? $body; return "t=$t,v1=" . hash_hmac('sha256', "$t.$b", $secret); };

ok(Webhook::isValidCoinsnapSignature($body, $sign($now, 'sec'), 'sec', $now), 'Coinsnap: valid timestamped signature accepted');
ok(Webhook::isValidCoinsnapSignature($body, $sign($now - 299, 'sec'), 'sec', $now), 'Coinsnap: 299 s old accepted');
ok(!Webhook::isValidCoinsnapSignature($body, $sign($now - 301, 'sec'), 'sec', $now), 'Coinsnap: 301 s old rejected');
ok(!Webhook::isValidCoinsnapSignature($body, $sign($now - 600, 'sec'), 'sec', $now), 'Coinsnap: 10 min old rejected');
ok(!Webhook::isValidCoinsnapSignature($body, $sign($now + 600, 'sec'), 'sec', $now), 'Coinsnap: 10 min in the future rejected');
ok(Webhook::coinsnapSignatureError($body, $sign($now - 600, 'sec'), 'sec', $now) === 'stale timestamp', 'Coinsnap: stale reason reported');
ok(!Webhook::isValidCoinsnapSignature($body, $sign($now, 'wrong'), 'sec', $now), 'Coinsnap: wrong secret rejected');
ok(Webhook::coinsnapSignatureError($body, $sign($now, 'wrong'), 'sec', $now) === 'bad signature', 'Coinsnap: bad signature reason reported');
ok(!Webhook::isValidCoinsnapSignature($body . ' ', $sign($now, 'sec'), 'sec', $now), 'Coinsnap: modified body rejected');
ok(!Webhook::isValidCoinsnapSignature($body, '', 'sec', $now), 'Coinsnap: missing header rejected');
ok(!Webhook::isValidCoinsnapSignature($body, $sign($now, ''), '', $now), 'Coinsnap: empty secret rejects a webhook signed with an empty key');
ok(!Webhook::isValidCoinsnapSignature($body, 'v1=' . hash_hmac('sha256', "0.$body", 'sec'), 'sec', $now), 'Coinsnap: no timestamp rejected');
ok(!Webhook::isValidCoinsnapSignature($body, 'sha256=' . hash_hmac('sha256', $body, 'sec'), 'sec', $now), 'Coinsnap: old X-Coinsnap-Sig format rejected');
ok(!Webhook::isValidCoinsnapSignature($body, "t=$now,v1=", 'sec', $now), 'Coinsnap: empty v1 rejected');
ok(!Webhook::isValidCoinsnapSignature($body, "t=-5,v1=" . hash_hmac('sha256', "-5.$body", 'sec'), 'sec', $now), 'Coinsnap: negative t rejected');
ok(Webhook::isValidCoinsnapSignature($body, 't=' . $now . ', v1=' . strtoupper(hash_hmac('sha256', "$now.$body", 'sec')), 'sec', $now), 'Coinsnap: spaces and upper-case hex tolerated');
ok(Webhook::isValidCoinsnapSignature($body, $sign(time(), 'sec'), 'sec'), 'Coinsnap: default clock works');

// ---------------------------------------------------------------- BTCPay signature
$bsig = 'sha256=' . hash_hmac('sha256', $body, 'bs');
ok(Webhook::isValidBTCPaySignature($body, $bsig, 'bs'), 'BTCPay: valid signature accepted');
ok(!Webhook::isValidBTCPaySignature($body, substr($bsig, 7), 'bs'), 'BTCPay: missing sha256= prefix rejected');
ok(!Webhook::isValidBTCPaySignature($body, $bsig, 'other'), 'BTCPay: other secret rejected');
ok(!Webhook::isValidBTCPaySignature($body, 'sha256=' . hash_hmac('sha256', $body, ''), ''), 'BTCPay: empty secret rejected');
ok(!Webhook::isValidBTCPaySignature($body, '', 'bs'), 'BTCPay: missing header rejected');

// ---------------------------------------------------------------- deprecated legacy check
ok(Webhook::isIncomingWebhookRequestValid($body, $bsig, 'bs'), 'legacy: still accepts a correct sha256= signature');
ok(!Webhook::isIncomingWebhookRequestValid($body, 'sha256=' . hash_hmac('sha256', $body, ''), ''), 'legacy: empty secret now rejected');
ok(!Webhook::isIncomingWebhookRequestValid($body, 'sha256=00', 'bs'), 'legacy: wrong signature rejected');
$src = file_get_contents(__DIR__ . '/../library/Client/Webhook.php');
ok(strpos($src, '$expectedHeader === ') === false && substr_count($src, 'hash_equals(') >= 3, 'all signature compares use hash_equals');

// ---------------------------------------------------------------- invoice ID from body
ok(Webhook::getInvoiceIdFromBody($body) === 'inv_1', 'invoiceId taken from body');
ok(Webhook::getInvoiceIdFromBody('{"invoiceId":["x"]}') === '', 'non-string invoiceId ignored');
ok(Webhook::getInvoiceIdFromBody('{"invoiceId":"../x"}') === '', 'invoiceId with path characters ignored');
ok(Webhook::getInvoiceIdFromBody('not json') === '', 'invalid JSON gives no invoiceId');

// ---------------------------------------------------------------- fetchInvoice: three outcomes
$inv = ['id' => 'inv_1', 'status' => 'Settled', 'currency' => 'EUR', 'amount' => '1000', 'fiatAmount' => '10.00'];
$c = new FakeClient([[200, json_encode($inv)]]);
$r = (new Invoice('https://app.coinsnap.io', 'key', $c))->fetchInvoice('store_A', 'inv_1');
ok($r instanceof \Coinsnap\Result\Invoice && $r->getId() === 'inv_1', 'fetchInvoice: 200 returns the invoice');
ok($c->calls[0]['method'] === 'GET' && $c->calls[0]['url'] === 'https://app.coinsnap.io/api/v1/stores/store_A/invoices/inv_1', 'fetchInvoice: GET /api/v1/stores/{id}/invoices/{id}');
ok(($c->calls[0]['headers']['x-api-key'] ?? '') === 'key', 'fetchInvoice: x-api-key header sent');
$c = new FakeClient([[200, json_encode($inv)]]);
(new Invoice('https://app.coinsnap.io', 'key', $c))->fetchInvoice('store_A', 'a/b?c');
ok(strpos($c->calls[0]['url'], '/invoices/a%2Fb%3Fc') !== false, 'fetchInvoice: invoice ID is URL-encoded');
foreach ([400, 404] as $code) {
    $r = (new Invoice('https://x', 'key', new FakeClient([[$code, '{"error":"store_A"}']])))->fetchInvoice('store_A', 'inv_1');
    ok($r === null, "fetchInvoice: $code means not found (null)");
}
$r = (new Invoice('https://x', 'key', new FakeClient([[200, 'garbage']])))->fetchInvoice('store_A', 'inv_1');
ok($r === null, 'fetchInvoice: 200 with invalid JSON is null');
foreach ([500, 502, 503, 401, 403, 429] as $code) {
    ok(throws(function () use ($code) { (new Invoice('https://x', 'key', new FakeClient([[$code, 'oops']])))->fetchInvoice('store_A', 'inv_1'); }, RequestException::class), "fetchInvoice: $code throws");
}
ok(throws(function () { (new Invoice('https://x', 'key', new FakeClient([new ConnectException('timeout', 28)])))->fetchInvoice('store_A', 'inv_1'); }, ConnectException::class), 'fetchInvoice: network error throws');
try {
    (new Invoice('https://x', 'key', new FakeClient([[503, 'body with store_A and key']])))->fetchInvoice('store_A', 'inv_1');
} catch (RequestException $e) {
    ok(strpos($e->getMessage(), 'store_A') === false && strpos($e->getMessage(), 'inv_1') === false && strpos($e->getMessage(), 'key') === false, 'exception message has no store ID, invoice ID or body (6.13)');
    ok(strpos($e->getMessage(), '/stores/{id}/invoices/{id}') !== false && $e->getStatus() === 503, 'exception message masks the path and keeps the status');
    ok($e->getResponseBody() === 'body with store_A and key', 'raw body still available via getResponseBody()');
}
try {
    (new Invoice('https://x', 'key', new FakeClient([[400, 'x']])))->getInvoice('store_A', 'inv_1');
    ok(false, 'legacy getInvoice still throws on 400');
} catch (\Coinsnap\Exception\BadRequestException $e) {
    ok(strpos($e->getMessage(), 'store_A') === false, 'legacy getInvoice: BadRequestException without store ID');
}

// ---------------------------------------------------------------- paysAmount / isPaid
$I = function (array $d) { return new \Coinsnap\Result\Invoice($d); };
ok($I(['status' => 'Settled', 'currency' => 'EUR', 'fiatAmount' => '10.00'])->paysAmount('10.00', 'EUR'), 'Coinsnap: settled, right fiat amount pays');
ok($I(['status' => 'Settled', 'currency' => 'EUR', 'fiatAmount' => 10.01])->paysAmount('10', 'eur'), 'Coinsnap: 1 cent rounding tolerated');
ok(!$I(['status' => 'Settled', 'currency' => 'EUR', 'fiatAmount' => '9.98'])->paysAmount('10.00', 'EUR'), 'Coinsnap: underpaid does not pay');
ok(!$I(['status' => 'Settled', 'currency' => 'EUR', 'fiatAmount' => ''])->paysAmount('10.00', 'EUR'), 'Coinsnap: empty fiatAmount does not pay');
ok(!$I(['status' => 'Settled', 'currency' => 'USD', 'fiatAmount' => '10.00'])->paysAmount('10.00', 'EUR'), 'wrong currency does not pay');
ok(!$I(['status' => 'Processing', 'currency' => 'EUR', 'fiatAmount' => '10.00'])->paysAmount('10.00', 'EUR'), 'Processing does not pay');
ok(!$I(['status' => 'Expired', 'additionalStatus' => 'PaidPartial', 'currency' => 'EUR', 'fiatAmount' => '10.00'])->paysAmount('10.00', 'EUR'), 'Expired/underpaid does not pay');
ok(!$I(['status' => 'Settled', 'currency' => 'EUR', 'fiatAmount' => '0'])->paysAmount('0', 'EUR'), 'price 0 never pays');
ok(!$I(['status' => 'Settled', 'currency' => 'EUR', 'fiatAmount' => '10'])->paysAmount('abc', 'EUR'), 'unparseable price never pays');
ok($I(['status' => 'Settled', 'currency' => 'SATS', 'amount' => '1000'])->paysAmount(1000, 'SATS'), 'SATS: exact amount pays');
ok(!$I(['status' => 'Settled', 'currency' => 'SATS', 'amount' => '999'])->paysAmount(1000, 'SATS'), 'SATS: 1 sat less does not pay');
ok($I(['status' => 'Settled', 'currency' => 'EUR', 'amount' => '10.00'])->paysAmount('10.00', 'EUR', true), 'BTCPay: settled, right amount pays');
ok($I(['status' => 'Settled', 'additionalStatus' => 'PaidOver', 'currency' => 'EUR', 'amount' => '10.00'])->paysAmount('10.00', 'EUR', true), 'BTCPay: PaidOver pays');
ok(!$I(['status' => 'Settled', 'additionalStatus' => 'Marked', 'currency' => 'EUR', 'amount' => '10.00'])->paysAmount('10.00', 'EUR', true), 'BTCPay: Marked refused by default');
ok($I(['status' => 'Settled', 'additionalStatus' => 'Marked', 'currency' => 'EUR', 'amount' => '10.00'])->paysAmount('10.00', 'EUR', true, true), 'BTCPay: Marked accepted when merchant allows');
ok(!$I(['status' => 'Processing', 'additionalStatus' => 'PaidPartial'])->isPaid(), 'isPaid: PaidPartial is no longer paid');
ok($I(['status' => 'Settled'])->isPaid() && !$I([])->isPaid() && !$I([])->isMarked(), 'isPaid: Settled is paid; missing fields give false, no warnings');

// ---------------------------------------------------------------- BTCPay key acceptance
$good = ['btcpay.store.cancreateinvoice:S2', 'btcpay.store.canviewinvoices:S2', 'btcpay.store.webhooks.canmodifywebhooks:S2', 'btcpay.store.canviewstoresettings:S2'];
ok(BTCPayApiAuthorization::keyIsAcceptable($good, 'S2'), 'store-limited key with needed permissions accepted');
ok(!BTCPayApiAuthorization::keyIsAcceptable(['unrestricted'], 'S2'), 'unrestricted key refused');
ok(!BTCPayApiAuthorization::keyIsAcceptable(array_merge($good, ['btcpay.store.cancreateinvoice']), 'S2'), 'permission for all stores refused');
ok(!BTCPayApiAuthorization::keyIsAcceptable(array_merge($good, ['btcpay.server.canmodifyserversettings:S2']), 'S2'), 'server permission refused');
ok(!BTCPayApiAuthorization::keyIsAcceptable(array_merge($good, ['btcpay.user.canviewprofile']), 'S2'), 'user permission refused');
ok(!BTCPayApiAuthorization::keyIsAcceptable(array_merge($good, ['btcpay.store.canviewinvoices:OTHER']), 'S2'), 'second store refused');
ok(!BTCPayApiAuthorization::keyIsAcceptable(['btcpay.store.canviewinvoices:S2'], 'S2'), 'missing needed permission refused');
ok(!BTCPayApiAuthorization::keyIsAcceptable([], 'S2') && !BTCPayApiAuthorization::keyIsAcceptable($good, ''), 'empty list / empty store refused');

// Permissions from the POST are never trusted
$posted = new BTCPayApiAuthorization(['apiKey' => 'attacker', 'permissions' => $good]);
ok(!$posted->isVerified() && !$posted->isAcceptable(), 'object built from POST data is never acceptable');
ok($posted->isStoreLimited() && $posted->getStoreID() === 'S2', 'legacy object still reports store limits (BC)');
$empty = new BTCPayApiAuthorization([]);
ok($empty->getStoreID() === '' && !$empty->hasSingleStore() && !$empty->isStoreLimited(), 'empty permissions: no crash, not single-store');
ok(!(new BTCPayApiAuthorization(['permissions' => ['unrestricted']]))->hasSingleStore(), 'legacy hasSingleStore refuses unrestricted');
ok(!(new BTCPayApiAuthorization(['permissions' => 'x']))->hasSingleStore(), 'non-array permissions handled');

// fromApiKey reads GET /api/v1/api-keys/current
$c = new FakeClient([[200, json_encode(['apiKey' => 'k', 'permissions' => $good])]]);
$a = BTCPayApiAuthorization::fromApiKey('https://btcpay.example/', 'k', $c);
ok($a !== null && $a->isVerified() && $a->isAcceptable() && $a->getStoreID() === 'S2' && $a->getApiKey() === 'k', 'fromApiKey: store-limited key accepted');
ok($c->calls[0]['url'] === 'https://btcpay.example/api/v1/api-keys/current' && $c->calls[0]['headers']['Authorization'] === 'token k' && $c->calls[0]['method'] === 'GET', 'fromApiKey: GET api-keys/current with Authorization: token');
ok(!isset($c->calls[0]['headers']['x-api-key']), 'fromApiKey: key not sent in other headers');
ok($a->isAcceptable('S2') && !$a->isAcceptable('OTHER'), 'fromApiKey: isAcceptable($storeId) pins the configured store');
$a = BTCPayApiAuthorization::fromApiKey('https://b', 'k', new FakeClient([[200, json_encode(['permissions' => ['unrestricted']])]]));
ok($a !== null && !$a->isAcceptable(), 'fromApiKey: unrestricted key refused');
$a = BTCPayApiAuthorization::fromApiKey('https://b', 'k', new FakeClient([[200, json_encode(['permissions' => ['btcpay.store.canviewinvoices:S1', 'btcpay.store.cancreateinvoice:S1', 'btcpay.store.webhooks.canmodifywebhooks:S1', 'btcpay.store.canviewinvoices:S2']])]]));
ok($a !== null && !$a->isAcceptable(), 'fromApiKey: two-store key refused');
ok(BTCPayApiAuthorization::fromApiKey('https://b', 'k', new FakeClient([[401, '']])) === null, 'fromApiKey: invalid key (401) gives null');
ok(BTCPayApiAuthorization::fromApiKey('https://b', 'k', new FakeClient([new ConnectException('down', 0)])) === null, 'fromApiKey: network error gives null');
ok(BTCPayApiAuthorization::fromApiKey('https://b', 'k', new FakeClient([[200, 'nope']])) === null, 'fromApiKey: invalid JSON gives null');
ok(BTCPayApiAuthorization::fromApiKey('', 'k', new FakeClient([])) === null && BTCPayApiAuthorization::fromApiKey('https://b', '', new FakeClient([])) === null, 'fromApiKey: empty URL or key makes no request');

// One-time state
$st = BTCPayApiAuthorization::startState('t_state');
ok(strlen($st) === 64 && $GLOBALS['transients']['t_state'] !== $st, 'state is random and stored hashed');
ok(BTCPayApiAuthorization::consumeState('t_state', $st), 'fresh state accepted');
ok(!BTCPayApiAuthorization::consumeState('t_state', $st), 'state works once');
$st = BTCPayApiAuthorization::startState('t_state');
ok(!BTCPayApiAuthorization::consumeState('t_state', 'x'), 'wrong state refused');
ok(!BTCPayApiAuthorization::consumeState('t_state', $st), 'state deleted after a failed check');
ok(!BTCPayApiAuthorization::consumeState('t_state', ''), 'no state refused');

// ---------------------------------------------------------------- WPRemoteClient: TLS always verified
$GLOBALS['wp_remote_reply'] = ['response' => ['code' => 200], 'body' => '{}'];
$w = new WPRemoteClient();
$w->setWpRemoteOptions(['sslverify' => false]);
$w->request('GET', 'https://x/api');
ok(($GLOBALS['wp_remote_calls'][0][1]['sslverify'] ?? null) === true, 'WPRemoteClient: sslverify forced true even after setWpRemoteOptions(false)');
$GLOBALS['wp_remote_reply'] = new WP_Error('x', 'cURL error 6');
ok(throws(function () use ($w) { $w->request('GET', 'https://x'); }, ConnectException::class), 'WPRemoteClient: WP_Error becomes ConnectException');

// ---------------------------------------------------------------- Notice: no unserialize (6.1)
class Evil { public static $woke = false; function __wakeup() { self::$woke = true; } function __destruct() { self::$woke = true; } }
$_COOKIE['coinsnap_notices'] = ['a' => serialize(new Evil()), 'b' => json_encode(['type' => 'error', 'message' => '<b>Hi</b>', 'dismissible' => true]), 'c' => ['nested']];
Evil::$woke = false;
ob_start();
(new \Coinsnap\Util\Notice())->showNotices();
$html = ob_get_clean();
ok(!Evil::$woke, 'Notice: serialized object in cookie runs nothing');
ok(substr_count($html, '<div') === 1 && strpos($html, 'notice-error is-dismissible') !== false && strpos($html, '<b>') === false, 'Notice: JSON notice shown escaped, others ignored');
$_COOKIE['coinsnap_notices'] = ['x' => addslashes(json_encode(['type' => 'x" onmouseover="a', 'message' => 'm']))]; // WordPress slashes cookies
ob_start(); (new \Coinsnap\Util\Notice())->showNotices(); $html = ob_get_clean();
ok(strpos($html, 'onmouseover') === false && strpos($html, 'notice-info') !== false, 'Notice: unknown type falls back to info');

// ---------------------------------------------------------------- static checks
$all = '';
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__ . '/../library')) as $f) {
    if ($f->isFile() && substr((string) $f, -4) === '.php') { $all .= file_get_contents((string) $f); }
}
ok(!preg_match('/\bunserialize\s*\(/', $all), 'no unserialize() in library');
ok(!preg_match('/Access-Control-Allow-Origin/', $all), 'no CORS wildcard header in library');
ok(!preg_match("/sslverify'\s*=>\s*false|SSL_VERIFY(PEER|HOST)/", $all), 'TLS verification never disabled');
ok(!preg_match('/\b(print_r|var_dump|var_export|error_log)\s*\(/', $all), 'no debug output or logging of data');

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
