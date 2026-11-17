<?php
declare(strict_types=1);
namespace Coinsnap\Client;

if (!defined('ABSPATH')) {
    exit;
}

use Coinsnap\Exception\CSException;
use Coinsnap\Http\ClientInterface;
use Coinsnap\Http\WPRemoteClient;

/**
 * Checks a BTCPay API key that a merchant connected or pasted.
 *
 * Secure use in a connect callback (see the Coinsnap Plugin Security Guide, "Connect callbacks"):
 *
 *     // When the admin clicks "Connect" (capability and nonce checked there):
 *     $state = BTCPayApiAuthorization::startState('myplugin_btcpay_state');
 *     // ... add $state to the redirect URL given to BTCPay ...
 *
 *     // In the callback:
 *     if (!BTCPayApiAuthorization::consumeState('myplugin_btcpay_state', (string) ($_GET['state'] ?? ''))) { exit; }
 *     $auth = BTCPayApiAuthorization::fromApiKey($savedBtcpayUrl, (string) ($_POST['apiKey'] ?? ''));
 *     if ($auth === null || !$auth->isAcceptable()) { exit; }
 *     save($auth->getApiKey(), $auth->getStoreID());
 *
 * Permissions and the store ID are read from BTCPay (GET /api/v1/api-keys/current), never from the POST:
 * anyone can post the callback URL with made-up permissions.
 */
class BTCPayApiAuthorization {
	/**
	 * Historical list used by hasRequiredPermissions(). Kept for backward compatibility.
	 * New code should use MINIMUM_PERMISSIONS with isAcceptable().
	 */
	public const REQUIRED_PERMISSIONS = [
		'btcpay.store.canviewinvoices',
		'btcpay.store.cancreateinvoice',
		'btcpay.store.canviewstoresettings',
		'btcpay.store.canmodifyinvoices'
	];
	public const OPTIONAL_PERMISSIONS = [
		'btcpay.store.cancreatenonapprovedpullpayments',
		'btcpay.store.webhooks.canmodifywebhooks',
	];

	/** What a payment plugin needs at least: create and read invoices, manage its own webhook. */
	public const MINIMUM_PERMISSIONS = [
		'btcpay.store.cancreateinvoice',
		'btcpay.store.canviewinvoices',
		'btcpay.store.webhooks.canmodifywebhooks',
	];

	/** One-time connect state lifetime, in seconds. */
	public const STATE_TTL = 600;

	private $apiKey;
	private $permissions;
	private $verified = false;

	/**
	 * @param array $data ['apiKey' => string, 'permissions' => string[]]
	 *
	 * @deprecated Since 1.2.1 when $data comes from the request ($_POST): the posted permissions are
	 *             chosen by whoever sends the request. Use BTCPayApiAuthorization::fromApiKey(), which asks
	 *             BTCPay what the key can do.
	 */
	public function __construct($data) {
		$data = is_array($data) ? $data : [];
		$this->apiKey = isset($data['apiKey']) && is_string($data['apiKey']) ? $data['apiKey'] : null;
		$permissions = (isset($data['permissions']) && is_array($data['permissions'])) ? $data['permissions'] : [];
		$this->permissions = array_values(array_filter($permissions, 'is_string'));
	}

	/**
	 * Ask BTCPay which permissions the key has (GET /api/v1/api-keys/current, header Authorization: token <key>).
	 *
	 * @param string $btcpayUrl The merchant's BTCPay server URL from the saved settings, never from the request.
	 * @param string $apiKey    The key to check.
	 *
	 * @return self|null null when the key is empty, BTCPay is unreachable, or the key is not valid there.
	 */
	public static function fromApiKey(string $btcpayUrl, string $apiKey, ?ClientInterface $client = null): ?self {
		$btcpayUrl = rtrim(trim($btcpayUrl), '/');
		if ($btcpayUrl === '' || $apiKey === '') {
			return null;
		}
		$client = $client ?? new WPRemoteClient();
		try {
			$response = $client->request('GET', $btcpayUrl . '/api/v1/api-keys/current', [
				'Accept' => 'application/json',
				'Authorization' => 'token ' . $apiKey,
			]);
		} catch (CSException $e) {
			return null;
		}
		if ($response->getStatus() !== 200) {
			return null;
		}
		$key = json_decode($response->getBody(), true);
		if (!is_array($key) || !isset($key['permissions']) || !is_array($key['permissions'])) {
			return null;
		}
		$auth = new self(['apiKey' => $apiKey, 'permissions' => $key['permissions']]);
		$auth->verified = true;
		return $auth;
	}

	/**
	 * Create a one-time state for the BTCPay authorize redirect and store its hash in a transient.
	 * Call it on the admin page, after the capability and nonce checks, never in the callback itself.
	 *
	 * @param string $transientKey A name only your plugin uses, e.g. 'coinsnap_myplugin_btcpay_state'.
	 */
	public static function startState(string $transientKey): string {
		$state = bin2hex(random_bytes(32));
		set_transient($transientKey, hash('sha256', $state), self::STATE_TTL);
		return $state;
	}

	/**
	 * Check the state from the callback. It is deleted on the first try, even when the check fails.
	 */
	public static function consumeState(string $transientKey, string $state): bool {
		$expected = get_transient($transientKey);
		delete_transient($transientKey);
		return is_string($expected) && $expected !== '' && $state !== '' && hash_equals($expected, hash('sha256', $state));
	}

	public function getApiKey(): ?string
	{
		return $this->apiKey;
	}

	/** @return string[] */
	public function getPermissions(): array
	{
		return $this->permissions;
	}

	/** True only when the permissions were read from BTCPay by fromApiKey(). */
	public function isVerified(): bool
	{
		return $this->verified;
	}

	/**
	 * The store ID of the first permission, or '' if it has none.
	 * Only meaningful after isStoreLimited() or isAcceptable() returned true.
	 */
	public function getStoreID(): string
	{
		$first = explode(':', (string) ($this->permissions[0] ?? ''), 2);
		return $first[1] ?? '';
	}

	/**
	 * Every permission is a btcpay.store.* permission limited to one and the same store.
	 * Unrestricted keys, server/user permissions and permissions for all stores are refused.
	 */
	public function isStoreLimited(): bool
	{
		$storeId = $this->getStoreID();
		return $storeId !== '' && self::keyIsAcceptable($this->permissions, $storeId, []);
	}

	/**
	 * Safe acceptance check for a connect callback or a pasted key: the permissions came from BTCPay
	 * (fromApiKey()), the key is limited to one store (or to $storeId if given), and it has $needed.
	 *
	 * @param string[] $needed Permissions without store suffix; defaults to MINIMUM_PERMISSIONS.
	 */
	public function isAcceptable(?string $storeId = null, ?array $needed = null): bool
	{
		if (!$this->verified) {
			return false;
		}
		$storeId = $storeId ?? $this->getStoreID();
		return self::keyIsAcceptable($this->permissions, $storeId, $needed ?? self::MINIMUM_PERMISSIONS);
	}

	/**
	 * Pure check of a permission list as returned by GET /api/v1/api-keys/current.
	 * Every permission must be "btcpay.store.<name>:<storeId>" and every $needed permission must be present.
	 *
	 * @param string[] $permissions
	 * @param string[] $needed Permissions without store suffix.
	 */
	public static function keyIsAcceptable(array $permissions, string $storeId, array $needed = self::MINIMUM_PERMISSIONS): bool
	{
		if ($permissions === [] || $storeId === '') {
			return false;
		}
		foreach ($permissions as $permission) {
			if (!is_string($permission)) {
				return false;
			}
			$parts = explode(':', $permission, 2);
			$policy = $parts[0];
			$scope = $parts[1] ?? '';
			if (strpos($policy, 'btcpay.store.') !== 0 || $scope !== $storeId) {
				return false; // unrestricted, server or user rights, or not limited to this store
			}
		}
		foreach ($needed as $p) {
			if (!in_array($p . ':' . $storeId, $permissions, true)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @deprecated Since 1.2.1. Checks only the permission names, not that they belong to one store, and
	 *             on its own trusts whatever permissions the object was built with. Use isAcceptable().
	 */
	public function hasRequiredPermissions(): bool
	{
		$permissions = $this->permissionNames();

		// Remove optional permissions so that only required ones are left.
		$permissions = array_diff($permissions, self::OPTIONAL_PERMISSIONS);

		return empty(array_merge(
			array_diff(self::REQUIRED_PERMISSIONS, $permissions),
			array_diff($permissions, self::REQUIRED_PERMISSIONS)
		));
	}

	/**
	 * @deprecated Since 1.2.1. Use isStoreLimited() or isAcceptable(). Now returns false for an empty
	 *             permission list (it used to return true).
	 */
	public function hasSingleStore(): bool
	{
		if ($this->permissions === []) {
			return false;
		}
		$storeId = null;
		foreach ($this->permissions as $perms) {
			$exploded = explode(':', $perms);
			if (2 !== count($exploded) || $exploded[1] === '') {
				return false;
			}
			if ($storeId === null) {
				$storeId = $exploded[1];
			} elseif ($storeId !== $exploded[1]) {
				return false;
			}
		}
		return true;
	}

	public function hasRefundsPermission(): bool {
		return in_array('btcpay.store.cancreatenonapprovedpullpayments', $this->permissionNames(), true);
	}

	public function hasWebhookPermission(): bool {
		return in_array('btcpay.store.webhooks.canmodifywebhooks', $this->permissionNames(), true);
	}

	/** @return string[] */
	private function permissionNames(): array {
		return array_map(static function (string $permission): string {
			return explode(':', $permission)[0];
		}, $this->permissions);
	}
}
