<?php

/**
 * Developer: Andy Goldau
 * © 2026 PK-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 *
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * PK-Register is an independent software solution and is not affiliated with,
 * endorsed by, or sponsored by Plesk International GmbH or its affiliates.
 */

/**
 * Demo Mode Account Cleanup Script (Cronjob)
 * --------------------------------------------------
 * Deletes expired demo Plesk accounts created by PK-Register.
 * Supports dual-mode authentication (set in config.php):
 *
 *   PLESK_AUTH_METHOD = 'rest_api'  →  REST API v2 (GET /api/v2/clients + DELETE /api/v2/clients/{id})
 *                                       Requires admin API token (PLESK_API_KEY)
 *
 *   PLESK_AUTH_METHOD = 'xmlrpc'    →  XML-RPC API (<customer><del>)
 *                                       Works with reseller login/password credentials
 *
 * Setup: Add to crontab (runs every 30 minutes):
 *   crontab -e
 *   Then add: php /home/YOUR_USER/public_html/cron_cleanup.php >> /dev/null 2>&1
 *
 * Crontab expression for every 30 minutes: [asterisk]/30 [asterisk] [asterisk] [asterisk] [asterisk]
 *
 * PREREQUISITE for xmlrpc mode: The Plesk Admin must enable "Ability to use XML API"
 * for your account (Plesk Panel -> Resellers -> [your account] -> Permissions tab).
 */

@set_time_limit(300);

$configPath = __DIR__ . '/config.php';
if (!is_file($configPath)) {
    echo "[" . date('Y-m-d H:i:s') . "] ERROR: Configuration file not found at $configPath\n";
    exit(1);
}
require_once $configPath;

// Security check: allow access via CLI or HTTP URL with valid ?key=CRON_SECRET_KEY
$isCli       = (php_sapi_name() === 'cli');
$providedKey = (string) ($_GET['key'] ?? $_POST['key'] ?? '');
$isValidKey  = defined('CRON_SECRET_KEY') && trim(CRON_SECRET_KEY) !== '' && hash_equals(CRON_SECRET_KEY, $providedKey);

if (!$isCli && !defined('CRON_ALLOWED') && !$isValidKey) {
    header('HTTP/1.1 403 Forbidden');
    echo "Access denied. This script can be run via CLI or via URL: https://your-domain.com/cron_cleanup.php?key=CRON_SECRET_KEY\n";
    exit(1);
}

if (!defined('DEMO_MODE') || !DEMO_MODE) {
    echo "[" . date('Y-m-d H:i:s') . "] DEMO MODE IS DISABLED in config.php. Exiting.\n";
    exit(0);
}

$authMethod = defined('PLESK_AUTH_METHOD') ? PLESK_AUTH_METHOD : 'xmlrpc';

if ($authMethod === 'rest_api') {
    if (!defined('PLESK_API_KEY') || trim(PLESK_API_KEY) === '' || PLESK_API_KEY === 'your-plesk-api-token') {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: PLESK_API_KEY is not configured (required for rest_api mode). Exiting.\n";
        exit(1);
    }
} else {
    if (!defined('PLESK_API_LOGIN') || trim(PLESK_API_LOGIN) === '' || PLESK_API_LOGIN === 'your-reseller-login') {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: PLESK_API_LOGIN is not configured (required for xmlrpc mode). Exiting.\n";
        exit(1);
    }
}

$dataFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');

if (!is_file($dataFile)) {
    echo "[" . date('Y-m-d H:i:s') . "] No demo accounts file found ($dataFile). Nothing to clean up.\n";
    exit(0);
}

$raw      = file_get_contents($dataFile);
$accounts = json_decode((string) $raw, true);

if (!is_array($accounts) || empty($accounts)) {
    echo "[" . date('Y-m-d H:i:s') . "] Demo accounts list is empty. Nothing to clean up.\n";
    exit(0);
}

$now          = time();
$deletedCount = 0;
$keptCount    = 0;
$sslVerify    = PLESK_SSL_VERIFY;
$timeout      = defined('PLESK_TIMEOUT') ? PLESK_TIMEOUT : 90;

// ── REST API v2 deletion helper ──────────────────────────────────────────────
function deleteAccountRest(string $username): bool
{
    global $sslVerify, $timeout;

    $baseUrl = rtrim(PLESK_HOST, '/') . ':' . PLESK_PORT;
    $headers = [
        'Accept: application/json',
        'Content-Type: application/json',
        'X-API-Key: ' . PLESK_API_KEY,
    ];

    // Step 1: Find client ID by login name
    $ch = curl_init($baseUrl . '/api/v2/clients');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_SSL_VERIFYPEER => $sslVerify,
        CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => $timeout,
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $clientId = null;
    if ($code === 200 && is_string($resp)) {
        $list = json_decode($resp, true);
        if (is_array($list)) {
            foreach ($list as $client) {
                if (isset($client['login']) && strtolower($client['login']) === strtolower($username)) {
                    $clientId = $client['id'] ?? null;
                    break;
                }
            }
        }
    }

    if (!$clientId) {
        echo "[" . date('Y-m-d H:i:s') . "] NOTICE: Client '$username' not found in Plesk via REST API (already deleted?). Removing from tracking.\n";
        return true; // treat as success
    }

    // Step 2: Delete client by ID
    $chDel = curl_init($baseUrl . '/api/v2/clients/' . $clientId);
    curl_setopt_array($chDel, [
        CURLOPT_CUSTOMREQUEST  => 'DELETE',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_SSL_VERIFYPEER => $sslVerify,
        CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => $timeout,
    ]);
    curl_exec($chDel);
    $delCode = curl_getinfo($chDel, CURLINFO_HTTP_CODE);
    $delErr  = curl_error($chDel);
    curl_close($chDel);

    if (in_array($delCode, [200, 204, 404], true)) {
        return true;
    }
    echo "[" . date('Y-m-d H:i:s') . "] ERROR: REST API DELETE failed for '$username' (HTTP $delCode): $delErr\n";
    return false;
}

// ── XML-RPC deletion helper ──────────────────────────────────────────────────
function deleteAccountXmlRpc(string $username): bool
{
    global $sslVerify, $timeout;

    $endpoint  = PLESK_XML_API_ENDPOINT;
    $safeLogin = htmlspecialchars($username, ENT_XML1, 'UTF-8');

    $deleteXml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<packet version="1.6.9.1">' . "\n"
        . '  <customer>' . "\n"
        . '    <del>' . "\n"
        . '      <filter>' . "\n"
        . '        <login>' . $safeLogin . '</login>' . "\n"
        . '      </filter>' . "\n"
        . '    </del>' . "\n"
        . '  </customer>' . "\n"
        . '</packet>';

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $deleteXml,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => $sslVerify,
        CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: text/xml',
            'HTTP_AUTH_LOGIN: '  . PLESK_API_LOGIN,
            'HTTP_AUTH_PASSWD: ' . PLESK_API_PASSWORD,
        ],
    ]);

    $body  = curl_exec($ch);
    $code  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno = curl_errno($ch);
    $err   = curl_error($ch);
    curl_close($ch);

    if ($errno || $body === false) {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: XML-RPC connection failed for '$username': $err\n";
        return false;
    }

    libxml_use_internal_errors(true);
    $xml = simplexml_load_string((string) $body);
    libxml_clear_errors();

    if ($xml === false) {
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: Could not parse XML-RPC response for '$username'.\n";
        return false;
    }

    $status  = isset($xml->customer->del->result->status)  ? (string) $xml->customer->del->result->status  : '';
    $errcode = isset($xml->customer->del->result->errcode) ? (string) $xml->customer->del->result->errcode : '';
    $errtext = isset($xml->customer->del->result->errtext) ? (string) $xml->customer->del->result->errtext : '';

    if ($status === 'ok') {
        return true;
    }
    if ($status === 'error') {
        // 1013 = object not found – treat as already deleted
        if ($errcode === '1013' || stripos($errtext, 'not found') !== false || stripos($errtext, 'does not exist') !== false) {
            echo "[" . date('Y-m-d H:i:s') . "] NOTICE: Account '$username' not found in Plesk (already deleted). Removing from tracking.\n";
            return true;
        }
        echo "[" . date('Y-m-d H:i:s') . "] ERROR: XML-RPC deletion failed for '$username': [$errcode] $errtext\n";
        return false;
    }

    echo "[" . date('Y-m-d H:i:s') . "] ERROR: Unexpected XML-RPC response for '$username'.\n";
    return false;
}

echo "[" . date('Y-m-d H:i:s') . "] Starting demo accounts cleanup scan (" . count($accounts) . " accounts tracked, method: $authMethod)...\n";

foreach ($accounts as $username => $info) {
    $deleteAfter = (int) ($info['delete_after'] ?? 0);

    if ($now >= $deleteAfter) {
        echo "[" . date('Y-m-d H:i:s') . "] Account '$username' expired (Created: " . date('Y-m-d H:i:s', $info['created_at'] ?? 0) . "). Terminating...\n";

        $success = ($authMethod === 'rest_api')
            ? deleteAccountRest($username)
            : deleteAccountXmlRpc($username);

        if ($success) {
            echo "[" . date('Y-m-d H:i:s') . "] SUCCESS: Account '$username' deleted.\n";
            unset($accounts[$username]);
            $deletedCount++;
        }
    } else {
        $remainingMin = ceil(($deleteAfter - $now) / 60);
        echo "[" . date('Y-m-d H:i:s') . "] Account '$username' active ($remainingMin minutes remaining).\n";
        $keptCount++;
    }
}

file_put_contents($dataFile, json_encode($accounts, JSON_PRETTY_PRINT), LOCK_EX);

echo "[" . date('Y-m-d H:i:s') . "] Cleanup complete. Deleted: $deletedCount account(s), Active: $keptCount account(s).\n";
