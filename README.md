# Coinsnap Wordpress Library #
![Coinsnap Wordpress Library](https://resources.coinsnap.org/products/wp-library/images/1.png)

## Bitcoin and Lightning payments in WordPress ##

# Coinsnap Wordpress Library 1.2.0 #

* Contributors: coinsnap
* Tags: Lightning, Lightning Payment, SATS, Satoshi sats, bitcoin, Wordpress, accept bitcoin, bitcoin plugin, bitcoin payment processor, bitcoin e-commerce, Lightning Network, cryptocurrency, lightning payment processor
* Requires at least: 5.2
* Tested up to: 6.7.1
* Requires PHP: 7.4
* Stable tag: 1.2.0
* License: GPL2
* License URI: https://www.gnu.org/licenses/gpl-2.0.html

Coinsnap is a Lightning payment provider and offers a payment gateway for processing Bitcoin and Lightning payments in Wordpress. A merchant only needs a Lightning wallet with a lightning address to accept Bitcoin and Lightning payments on their website.

## Coinsnap Wordpress library for PHP 7.4+ ## 

This API library is created for PHP developers to connect online store to Coinsnap payment gateway fast and easy. You can include this library inside your plug-in or use it as plugin inside your system.
5 steps to receive payments in via Bitcoin/Lightning payment gateway

* Registration in Coinsnap App
* Settings saving and payment statuses matching
* Connecting to Coinsnap App and Webhook saving
* Invoice and payment link receiving
* Payment status update

1. Registration in Coinsnap App

Register you account on Coinsnap App, fill all the necessary fields and receive Store Id and API Key.
2. Settings saving and payment statuses matching

You need to save Store Id and API Key in your database as Coinsnap connection configuration. Later you'll add there webhook data. If your store has reserved payment statuses, you can match your payment statuses to Coinsnap's:

* New - for new invoice
* Processing - for invoice in processing
* Settled - for paid invoice
* Expired - for expired invoice

If you can add Coinsnap payment statuses to existing, you can do it too. It depends of your system.
3. Connecting to Coinsnap App and Webhook saving

Every request to Coinsnap App needs necessary headers:

'Accept': 'application/json', 'Content-Type': 'application/json', 'x-api-key': «API Key»

The method Coinsnap\Client\AbstractClient::getRequestHeaders() creates them automatically.

3.1. Check connection to Coinsnap by the method Coinsnap\Client\Store::getStore(«Store ID»).

3.2. If Coinsnap server is available, we can create webhook by the method Coinsnap\Client\Webhook::createWebhook(«Store ID»,«Callback URL»), where «Callback URL» - URL for payment status updates via callback from Coinsnap server.

If webhook is created successfully, you will receive JSON-object with webhook data: {'id', 'secret', 'url'}. You need to store it in your database as an object or in separate fields.

3.3. You don't need to create webhook every time when you save your connection features, but you can check it by the method Coinsnap\Client\Webhook::getWebhook( «Store ID», «Webhook ID» ); Webhook ID is an id parameter, that you have received early on webhook creation stage. If webhook exists, you don't need to create it again.

3.4. If your Coinsnap credentians have been changed, you need to update webhook by the method updateWebhook(«Store ID»,«Webhook URL»,«Webhook ID»); Please save updates webhook data from JSON-object with webhook data: {'id', 'secret', 'url'} over old values.
4. Invoice and payment link receiving

You don't need to change your catalog, basket and order mechanism, but there will be necessary changes on the checkout stage. You your user has chosen "Bitcoin + Lightning" as payment method, you need to request invoice from Coinsnap App by method Coinsnap\Client\Invoice\createInvoice(«Store ID»,«Currency»,«Amount»,«Order ID»,«Buyer e-mail»,«Customer name»,«Redirect URL») in short variant.

After sending invoice request you will receive payment link and QR-codes for payment in Lightning or Bitcoin. You need to store in order or transaction data received Invoice ID to check payment statuses on fifth step.
5. Payment status update
After invoice creation and payment receiving Coinsnap App will connect to callback URL that you have sent to Coinsnap earlier. The body of the request is JSON-object {"type":«Payment status»,"invoiceId":«Invoice ID»}. Never trust the body: it only tells you which invoice to look at.

5.1. Check the signature over the raw request body before anything else. Coinsnap sends «X-Coinsnap-Signature: t=«unix time»,v1=«hex»»; use Coinsnap\Client\Webhook::isValidCoinsnapSignature(«Raw body», «Header», «Webhook secret») (or coinsnapSignatureError() to log the reason). It rejects an empty secret and a timestamp older than 5 minutes. For BTCPay use Webhook::isValidBTCPaySignature() with the «BTCPay-Sig» header. Reply 401 if the check fails. The old «X-Coinsnap-Sig» header and Webhook::isIncomingWebhookRequestValid() are deprecated.

5.2. Take only the invoice ID (Webhook::getInvoiceIdFromBody()) and fetch the invoice with Coinsnap\Client\Invoice::fetchInvoice(«Store ID», «Invoice ID»). It returns the invoice, null if the invoice doesn't exist (e.g. the dashboard's "Send test webhook": reply 200), or throws when the API can't answer (reply 503 so the webhook is retried).

5.3. Mark your order paid only if the invoice is the one you saved for that order and $invoice->paysAmount(«Price», «Currency», «Is BTCPay») is true (Settled, same currency and amount). Do it once per invoice ID.

6. BTCPay connect callback
Never read the key's permissions or store ID from the POST. Create a one-time state with Coinsnap\Client\BTCPayApiAuthorization::startState() when the admin clicks "Connect", check it in the callback with consumeState(), then ask BTCPay with BTCPayApiAuthorization::fromApiKey(«Saved BTCPay URL», «API key») and accept the key only if isAcceptable() is true (every permission limited to one store, with the permissions the plugin needs).
