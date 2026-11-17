<?php
declare(strict_types=1);
namespace Coinsnap\Result;

if (!defined('ABSPATH')) {
    exit;
}

use Coinsnap\Util\PreciseNumber;

class Invoice extends AbstractResult{
    public const STATUS_NEW = 'New';
    public const STATUS_INVALID = 'Invalid';
    public const STATUS_SETTLED = 'Settled';
    public const STATUS_EXPIRED = 'Expired';
    public const STATUS_PROCESSING = 'Processing';
    public const ADDITIONAL_STATUS_PAID_PARTIAL = 'PaidPartial';
    public const ADDITIONAL_STATUS_PAID_OVER = 'PaidOver';
    public const ADDITIONAL_STATUS_MARKED = 'Marked';
    public const ADDITIONAL_STATUS_PAID_LATE = 'PaidLate';

    public function getId(): string {
        return $this->getData()['id'];
    }

    public function getAmount(): PreciseNumber {
        return PreciseNumber::parseString($this->getData()['amount']);
    }

    public function getCurrency(): string {
        return $this->getData()['currency'];
    }

    public function getType(): string {
        return $this->getData()['type'];
    }

    public function getCheckoutLink(): string {
        return $this->getData()['checkoutLink'];
    }

    public function getCreatedTime(): int {
        return $this->getData()['createdTime'];
    }

    public function getExpirationTime(): int {
        return $this->getData()['expirationTime'];
    }

    public function getMonitoringTime(): int {
        return $this->getData()['monitoringTime'];
    }

    public function isArchived(): bool {
        return $this->getData()['archived'];
    }

    /**
     * True only for a Settled invoice. Before 1.2.1 this also returned true for an underpaid
     * (PaidPartial) invoice, which must never unlock an item.
     *
     * To decide whether an item is paid, use paysAmount(): it also checks the amount and currency.
     */
    public function isPaid(): bool {
        $data = $this->getData();
        return ($data['status'] ?? '') === self::STATUS_SETTLED;
    }

    /**
     * Whether this invoice, as returned by the API, pays an item of $price in $currency:
     * status Settled (overpaid / paid late still count), same currency, same amount.
     * A price of 0 or no amount is never paid. BTCPay's Marked (settled by hand) counts only if
     * $allowMarked is true. The caller also checks that the invoice belongs to the item (its own
     * metadata ID and a stored invoice ID).
     *
     * Amounts: SATS are compared exactly as whole sats (field amount). Other currencies are compared in
     * whole cents with 1 cent tolerance: Coinsnap fiatAmount, BTCPay amount.
     *
     * @param string|int|float $price
     */
    public function paysAmount($price, string $currency, bool $isBtcpay = false, bool $allowMarked = false): bool {
        $data = $this->getData();
        if (($data['status'] ?? '') !== self::STATUS_SETTLED) {
            return false;
        }
        if ($isBtcpay && ($data['additionalStatus'] ?? '') === self::ADDITIONAL_STATUS_MARKED && !$allowMarked) {
            return false;
        }
        $currency = strtoupper(trim($currency));
        if ($currency === '' || strtoupper((string) ($data['currency'] ?? '')) !== $currency) {
            return false;
        }
        if ($currency === 'SATS') {
            $expected = self::toWhole($price);
            $paid = self::toWhole($data['amount'] ?? '');
            return $expected !== null && $expected > 0 && $paid === $expected;
        }
        $expected = self::toCents($price);
        if ($expected === null || $expected <= 0) {
            return false;
        }
        $paid = self::toCents($isBtcpay ? ($data['amount'] ?? '') : ($data['fiatAmount'] ?? ''));
        return $paid !== null && abs($paid - $expected) <= 1;
    }

    /** Whole cents, so amounts are never compared as floats. Assumes 2 decimal places. */
    public static function toCents($value): ?int {
        if (is_int($value) || is_float($value)) {
            $value = number_format((float) $value, 2, '.', '');
        }
        if (!is_string($value) || !preg_match('/^(\d+)(?:\.(\d{1,2}))?$/', trim($value), $m)) {
            return null;
        }
        return (int) $m[1] * 100 + (int) str_pad($m[2] ?? '', 2, '0');
    }

    /** A whole number such as "1000" or "1000.0"; anything else is null. */
    private static function toWhole($value): ?int {
        if (is_int($value)) {
            return $value;
        }
        if (is_float($value)) {
            return floor($value) === $value ? (int) $value : null;
        }
        if (!is_string($value) || !preg_match('/^(\d+)(?:\.0+)?$/', trim($value), $m)) {
            return null;
        }
        return (int) $m[1];
    }

    public function isNew(): bool {
        $data = $this->getData();
        return ($data['status'] ?? '') === self::STATUS_NEW;
    }

    public function isFullyPaid(): bool {
        $data = $this->getData();
        return ($data['status'] ?? '') === self::STATUS_SETTLED;
    }

    public function getStatus(): string {
        return $this->getData()['status'];
    }

    public function isExpired(): bool {
        $data = $this->getData();
        return ($data['status'] ?? '') === self::STATUS_EXPIRED;
    }

    public function isProcessing(): bool {
        $data = $this->getData();
        return ($data['status'] ?? '') === self::STATUS_PROCESSING;
    }

    public function isInvalid(): bool {
        $data = $this->getData();
        return ($data['status'] ?? '') === self::STATUS_INVALID;
    }

    public function isOverpaid(): bool {
        $data = $this->getData();
        return ($data['additionalStatus'] ?? '') === self::ADDITIONAL_STATUS_PAID_OVER;
    }

    public function isPartiallyPaid(): bool {
        $data = $this->getData();
        return ($data['additionalStatus'] ?? '') === self::ADDITIONAL_STATUS_PAID_PARTIAL;
    }

    public function isMarked(): bool {
        $data = $this->getData();
        return ($data['additionalStatus'] ?? '') === self::ADDITIONAL_STATUS_MARKED;
    }

    public function isPaidLate(): bool {
        $data = $this->getData();
        return ($data['additionalStatus'] ?? '') === self::ADDITIONAL_STATUS_PAID_LATE;
    }

    public function getAvailableStatusesForManualMarking(): array { //    @return string[] Example: ["Settled", "Invalid"]
        return $this->getData()['availableStatusesForManualMarking'];
    }
}
