<?php

/**
 * Developer: Andy Goldau
 * © 2026 PK-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 * 
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * PK-Register is an independent software solution and is not affiliated with,
 * endorsed by, or sponsored by Plesk International GmbH or its affiliates.
 */

// Suppress PHP error output to prevent information disclosure
error_reporting(0);
ini_set('display_errors', '0');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
  || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
  || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

session_start([
  'cookie_httponly' => true,
  'cookie_samesite' => 'Lax',
  'cookie_secure'   => $isHttps,
]);
require_once __DIR__ . '/config.php';

// ── Early Startup Validation ─────────────────────────────────────────────
// Catch obvious misconfiguration before any API call is attempted.
$_pleskAuthMethod = defined('PLESK_AUTH_METHOD') ? PLESK_AUTH_METHOD : 'xmlrpc';
if (!in_array($_pleskAuthMethod, ['rest_api', 'xmlrpc'], true)) {
  error_log('[PK-Register] FATAL: PLESK_AUTH_METHOD must be "rest_api" or "xmlrpc". Check config.php.');
  http_response_code(500);
  die('<h1>Configuration Error</h1><p>PLESK_AUTH_METHOD must be "rest_api" or "xmlrpc". Please check config.php.</p>');
}
if ($_pleskAuthMethod === 'rest_api') {
  if (!defined('PLESK_API_KEY') || trim(PLESK_API_KEY) === '' || PLESK_API_KEY === 'your-plesk-api-token') {
    error_log('[PK-Register] FATAL: PLESK_API_KEY is not configured (required for rest_api mode). Check config.php.');
    http_response_code(500);
    die('<h1>Configuration Error</h1><p>PLESK_API_KEY is not set (required when PLESK_AUTH_METHOD = "rest_api"). Please check config.php.</p>');
  }
} else {
  if (!defined('PLESK_API_LOGIN') || trim(PLESK_API_LOGIN) === '' || PLESK_API_LOGIN === 'your-reseller-login') {
    error_log('[PK-Register] FATAL: PLESK_API_LOGIN is not configured (required for xmlrpc mode). Check config.php.');
    http_response_code(500);
    die('<h1>Configuration Error</h1><p>PLESK_API_LOGIN is not set (required when PLESK_AUTH_METHOD = "xmlrpc"). Please check config.php.</p>');
  }
}
if (!filter_var(PLESK_IP, FILTER_VALIDATE_IP)) {
  error_log('[PK-Register] FATAL: PLESK_IP ("' . PLESK_IP . '") is not a valid IP address. Check config.php.');
  http_response_code(500);
  die('<h1>Configuration Error</h1><p>PLESK_IP is not a valid IP address. Please check config.php.</p>');
}
if (defined('PLESK_IPV6') && !empty(PLESK_IPV6) && !filter_var(PLESK_IPV6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
  error_log('[PK-Register] FATAL: PLESK_IPV6 ("' . PLESK_IPV6 . '") is not a valid IPv6 address. Check config.php.');
  http_response_code(500);
  die('<h1>Configuration Error</h1><p>PLESK_IPV6 is not a valid IPv6 address. Please check config.php.</p>');
}

// ── Security Headers ───────────────────────────────────────────────────────
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
// HSTS: force HTTPS for 1 year, include subdomains. Only sent over HTTPS.
if ($isHttps) {
  header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
}
header(
  "Content-Security-Policy: default-src 'self'; "
  . "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net "
  . "https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com https://www.google.com https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
  . "font-src 'self' https://fonts.gstatic.com; "
  . "connect-src 'self' https://api.hcaptcha.com https://*.hcaptcha.com https://challenges.cloudflare.com https://www.google.com https://service.mtcaptcha.com https://service2.mtcaptcha.com https://api.pwnedpasswords.com; "
  . "img-src 'self' data: https://*.hcaptcha.com https://www.google.com https://www.gstatic.com https://service.mtcaptcha.com https://service2.mtcaptcha.com;"
);


// ── CSRF Token ─────────────────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

// ── Rate Limiting (Token Bucket) ──────────────────────────────────────────
if (defined('TRUST_PROXY_HEADERS') && TRUST_PROXY_HEADERS) {
  $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
} else {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
$ip = trim(explode(',', $ip)[0]);

$rateLimitDir = __DIR__ . '/data/limits';
if (!is_dir($rateLimitDir)) @mkdir($rateLimitDir, 0750, true);

$ipHash = hash('sha256', (defined('LOG_IP_SALT') ? LOG_IP_SALT : 'fallback') . $ip);
$limitFile = $rateLimitDir . '/limit_' . $ipHash . '.php';

$capacity = RATE_LIMIT_MAX;
$refillRate = $capacity / RATE_LIMIT_WINDOW;
$tokens = $capacity;
$lastUpdate = time();

$rateLimited = false;
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

$fp = @fopen($limitFile, 'c+');
if ($fp) {
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    if (strlen($raw) > 15) {
      $data = json_decode(substr($raw, 15), true);
      if (is_array($data)) {
        $tokens = $data['tokens'] ?? $capacity;
        $lastUpdate = $data['last_update'] ?? time();
      }
    }
    
    $now = time();
    $elapsed = $now - $lastUpdate;
    $tokens += $elapsed * $refillRate;
    if ($tokens > $capacity) $tokens = $capacity;
    
    if ($isPost) {
      if ($tokens >= 1) {
        $tokens -= 1;
        $rateLimited = false;
      } else {
        $rateLimited = true;
      }
    } else {
      $rateLimited = ($tokens < 1);
    }
    
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, "<?php exit; ?>\n" . json_encode([
      'tokens' => $tokens,
      'last_update' => $now
    ]));

    flock($fp, LOCK_UN);
  }
  fclose($fp);

  // ── Probabilistic cleanup of stale rate-limit files (runs ~1% of requests)
  // Prevents unbounded accumulation of per-IP token files in data/limits/.
  if (mt_rand(1, 100) === 1) {
    $staleThreshold = time() - max(RATE_LIMIT_WINDOW * 2, 3600); // keep for at least 1h
    foreach (glob($rateLimitDir . '/limit_*.php') ?: [] as $f) {
      if (filemtime($f) < $staleThreshold) {
        @unlink($f);
      }
    }
  }
}

// ── Plesk XML-RPC API Helper ───────────────────────────────────────────────────────
/**
 * Sends an XML packet to the Plesk XML-RPC API endpoint.
 * Authenticates using the reseller's login and password (not admin API token).
 *
 * @param  string $xmlBody  Full XML packet string
 * @return array{success:bool, code:int, body:string, xml:SimpleXMLElement|null}
 */
function pleskXmlRequest(string $xmlBody): array
{
  $endpoint  = PLESK_XML_API_ENDPOINT;
  $login     = PLESK_API_LOGIN;
  $password  = PLESK_API_PASSWORD;
  $sslVerify = PLESK_SSL_VERIFY;
  $timeout   = defined('PLESK_TIMEOUT') ? PLESK_TIMEOUT : 90;

  $ch = curl_init($endpoint);
  curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $xmlBody,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_SSL_VERIFYPEER => $sslVerify,
    CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT        => $timeout,
    CURLOPT_USERPWD        => $login . ':' . $password,
    CURLOPT_HTTPHEADER     => [
      'Content-Type: text/xml',
      'HTTP_AUTH_LOGIN: '  . $login,
      'HTTP_AUTH_PASSWD: ' . $password,
    ],
  ]);

  $body  = curl_exec($ch);
  $code  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $errno = curl_errno($ch);
  $err   = curl_error($ch);
  curl_close($ch);

  if ($errno || $body === false) {
    return ['success' => false, 'code' => $code, 'body' => $err, 'xml' => null];
  }

  libxml_use_internal_errors(true);
  $xml = simplexml_load_string((string) $body);
  libxml_clear_errors();

  return [
    'success' => ($xml !== false),
    'code'    => $code,
    'body'    => (string) $body,
    'xml'     => ($xml !== false) ? $xml : null,
  ];
}

// ── REST API v2 Implementation ──────────────────────────────────────────────
/**
 * Creates a new Plesk customer + subscription via Plesk REST API v2.
 * Requires an admin-level API token (PLESK_API_KEY).
 *   Step 1: POST /api/v2/clients  → creates the customer, returns {id}
 *   Step 2: POST /api/v2/domains  → creates the subscription linked to that customer
 */
function pleskRestCreateUser(array $data): array
{
  $baseUrl   = rtrim(PLESK_HOST, '/') . ':' . PLESK_PORT;
  $sslVerify = PLESK_SSL_VERIFY;
  $timeout   = defined('PLESK_TIMEOUT') ? PLESK_TIMEOUT : 90;
  $headers   = [
    'Content-Type: application/json',
    'Accept: application/json',
    'X-API-Key: ' . PLESK_API_KEY,
  ];

  // ── Step 1: Create the client (customer) account ──────────────────────────
  $clientName = (defined('PLESK_USERNAME_AS_NAME') && PLESK_USERNAME_AS_NAME)
    ? $data['username']
    : ($data['fullname'] ?? $data['name'] ?? $data['username']);

  $clientPayload = json_encode([
    'name'     => $clientName,
    'login'    => $data['username'],
    'password' => $data['passwd'],
    'email'    => $data['email'],
    'type'     => 'customer',
  ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

  if ($clientPayload === false) {
    return ['success' => false, 'message' => 'Failed to encode client data. Please check your input and try again.'];
  }

  $ch = curl_init($baseUrl . '/api/v2/clients');
  curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $clientPayload,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => $headers,
    CURLOPT_SSL_VERIFYPEER => $sslVerify,
    CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT        => $timeout,
  ]);
  $clientResponse = curl_exec($ch);
  $httpCode       = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $errno          = curl_errno($ch);
  $errorMsg       = curl_error($ch);
  curl_close($ch);

  if ($errno) {
    return ['success' => false, 'message' => 'Connection to Plesk server failed: ' . $errorMsg];
  }
  if ($httpCode === 401) {
    return ['success' => false, 'message' => 'Authentication failed (401). Please verify PLESK_API_KEY in config.php is correct and the token has not expired.'];
  }
  if ($httpCode === 403) {
    return ['success' => false, 'message' => 'Access forbidden (403). Your API token does not have permission to create customer accounts.'];
  }

  $parsedClient = json_decode((string) $clientResponse, true) ?? [];
  if ($httpCode !== 201) {
    $msg = $parsedClient['message'] ?? $parsedClient['error'] ?? ('HTTP ' . $httpCode);
    $msg = (mb_strlen((string)$msg) > 300) ? mb_substr((string)$msg, 0, 300) . '...' : (string)$msg;
    return ['success' => false, 'message' => 'Failed to create client account: ' . $msg];
  }

  $clientId = $parsedClient['id'] ?? null;
  if (!$clientId) {
    return ['success' => false, 'message' => 'Unexpected response from Plesk: no client ID returned. Check your Plesk server logs.'];
  }

  // ── Step 2: Create the domain / subscription ──────────────────────────────
  $domainPayload = [
    'name'             => $data['domain'],
    'hosting_type'     => 'virtual',
    'hosting_settings' => [
      'ftp_login'    => $data['username'],
      'ftp_password' => $data['passwd'],
    ],
    'owner_client'     => ['id' => $clientId],
    'ipv4'             => [PLESK_IP],
    'plan'             => ['name' => PLESK_SERVICE_PLAN],
  ];
  if (defined('PLESK_IPV6') && !empty(PLESK_IPV6)) {
    $domainPayload['ipv6'] = [PLESK_IPV6];
  }
  $domainPayload = json_encode($domainPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  if ($domainPayload === false) {
    return ['success' => false, 'message' => 'Failed to encode domain data. Please contact support.'];
  }

  $ch2 = curl_init($baseUrl . '/api/v2/domains');
  curl_setopt_array($ch2, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $domainPayload,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => $headers,
    CURLOPT_SSL_VERIFYPEER => $sslVerify,
    CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT        => $timeout,
  ]);
  $domainResponse = curl_exec($ch2);
  $httpCode2      = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
  $errno2         = curl_errno($ch2);
  $errorMsg2      = curl_error($ch2);
  curl_close($ch2);

  if ($errno2) {
    return ['success' => false, 'message' => 'Client account created, but subscription setup failed (connection error): ' . $errorMsg2 . '. Please contact support.'];
  }
  $parsedDomain = json_decode((string) $domainResponse, true) ?? [];
  if ($httpCode2 !== 201) {
    $msg2 = $parsedDomain['message'] ?? $parsedDomain['error'] ?? ('HTTP ' . $httpCode2);
    $msg2 = (mb_strlen((string)$msg2) > 300) ? mb_substr((string)$msg2, 0, 300) . '...' : (string)$msg2;
    return ['success' => false, 'message' => 'Client account created, but subscription assignment failed: ' . $msg2 . '. Please contact support.'];
  }

  return ['success' => true, 'message' => 'Account successfully created!'];
}

// ── XML-RPC Implementation ──────────────────────────────────────────────────
/**
 * Creates a new Plesk customer + subscription via Plesk XML-RPC API.
 * Works with reseller or admin login/password credentials (PLESK_API_LOGIN / PLESK_API_PASSWORD).
 *   Step 1: <customer><add>  → creates the customer account
 *   Step 2: <webspace><add>  → creates the subscription/hosting linked to that customer
 *
 * Authentication uses HTTP_AUTH_LOGIN / HTTP_AUTH_PASSWD headers + HTTP Basic Auth
 * with the reseller's own Plesk panel credentials (PLESK_API_LOGIN / PLESK_API_PASSWORD).
 *
 * PREREQUISITE: The Plesk Admin must enable "Ability to use XML API" for your
 * reseller account (one-time setup in Plesk Panel → Resellers → Permissions).
 */
function pleskXmlCreateUser(array $data): array
{
  $username = htmlspecialchars($data['username'],  ENT_XML1, 'UTF-8');
  $passwd   = htmlspecialchars($data['passwd'],    ENT_XML1, 'UTF-8');
  $email    = htmlspecialchars($data['email'],     ENT_XML1, 'UTF-8');
  $domain   = htmlspecialchars($data['domain'],    ENT_XML1, 'UTF-8');
  $ip       = htmlspecialchars(PLESK_IP,           ENT_XML1, 'UTF-8');
  $plan     = htmlspecialchars(PLESK_SERVICE_PLAN, ENT_XML1, 'UTF-8');

  $clientName = (defined('PLESK_USERNAME_AS_NAME') && PLESK_USERNAME_AS_NAME)
    ? $username
    : htmlspecialchars($data['fullname'] ?? $data['name'] ?? $data['username'], ENT_XML1, 'UTF-8');

  // ── Step 1: Create the customer account ──────────────────────────────────────────
  $customerXml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<packet version="1.6.9.1">
  <customer>
    <add>
      <gen_info>
        <pname>{$clientName}</pname>
        <login>{$username}</login>
        <passwd>{$passwd}</passwd>
        <email>{$email}</email>
      </gen_info>
    </add>
  </customer>
</packet>
XML;

  $resp1 = pleskXmlRequest($customerXml);

  if (!$resp1['success'] || $resp1['xml'] === null) {
    $detail = trim($resp1['body']);
    $detail = (mb_strlen($detail) > 300) ? mb_substr($detail, 0, 300) . '...' : $detail;
    if ($resp1['code'] === 401 || $resp1['code'] === 403) {
      return ['success' => false, 'message' => 'Authentication failed (' . $resp1['code'] . '). Please verify PLESK_API_LOGIN / PLESK_API_PASSWORD and ensure the XML API permission is enabled for your reseller account.'];
    }
    return ['success' => false, 'message' => 'Connection to Plesk server failed: ' . ($detail ?: 'No response')];
  }

  if ($resp1['code'] === 401) {
    return ['success' => false, 'message' => 'Authentication failed (401). Check PLESK_API_LOGIN / PLESK_API_PASSWORD and ensure the XML API permission is enabled for your reseller account.'];
  }

  $xml1     = $resp1['xml'];
  $status1  = isset($xml1->customer->add->result->status)  ? (string) $xml1->customer->add->result->status  : '';
  $errcode1 = isset($xml1->customer->add->result->errcode) ? (string) $xml1->customer->add->result->errcode : '';
  $errtext1 = isset($xml1->customer->add->result->errtext) ? (string) $xml1->customer->add->result->errtext : '';

  if ($status1 !== 'ok') {
    $sysText = isset($xml1->system->errtext) ? (string)$xml1->system->errtext : '';
    $sysCode = isset($xml1->system->errcode) ? (string)$xml1->system->errcode : '';
    $xpathErr = '';
    if ($xml1 !== null) {
      $errNodes = $xml1->xpath('//errtext');
      if (!empty($errNodes)) {
        $xpathErr = trim((string)$errNodes[0]);
      }
    }
    $msg = $errtext1 ?: $sysText ?: $xpathErr ?: ($errcode1 ? 'Error code: ' . $errcode1 : ($sysCode ? 'System error code: ' . $sysCode : null));
    if (!$msg) {
      $cleanBody = strip_tags(trim($resp1['body']));
      $msg = $cleanBody ?: 'Unknown error from Plesk';
    }
    $msg = (mb_strlen($msg) > 300) ? mb_substr($msg, 0, 300) . '...' : $msg;
    return ['success' => false, 'message' => 'Failed to create customer account: ' . $msg];
  }

  // ── Step 2: Create the subscription (webspace) ──────────────────────────────────
  $webspaceXml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<packet version="1.6.9.1">
  <webspace>
    <add>
      <gen_setup>
        <name>{$domain}</name>
        <owner-login>{$username}</owner-login>
        <ip_address>{$ip}</ip_address>
      </gen_setup>
      <hosting>
        <vrt_hst>
          <property>
            <name>ftp_login</name>
            <value>{$username}</value>
          </property>
          <property>
            <name>ftp_password</name>
            <value>{$passwd}</value>
          </property>
          <ip_address>{$ip}</ip_address>
        </vrt_hst>
      </hosting>
      <plan-name>{$plan}</plan-name>
    </add>
  </webspace>
</packet>
XML;

  $resp2 = pleskXmlRequest($webspaceXml);

  if (!$resp2['success'] || $resp2['xml'] === null) {
    $detail = trim($resp2['body']);
    $detail = (mb_strlen($detail) > 300) ? mb_substr($detail, 0, 300) . '...' : $detail;
    return ['success' => false, 'message' => 'Customer account created, but subscription/hosting setup failed: ' . ($detail ?: 'No response') . '. Please contact support to complete setup.'];
  }

  $xml2     = $resp2['xml'];
  $status2  = isset($xml2->webspace->add->result->status)  ? (string) $xml2->webspace->add->result->status  : '';
  $errcode2 = isset($xml2->webspace->add->result->errcode) ? (string) $xml2->webspace->add->result->errcode : '';
  $errtext2 = isset($xml2->webspace->add->result->errtext) ? (string) $xml2->webspace->add->result->errtext : '';

  if ($status2 !== 'ok') {
    $sysText2 = isset($xml2->system->errtext) ? (string)$xml2->system->errtext : '';
    $sysCode2 = isset($xml2->system->errcode) ? (string)$xml2->system->errcode : '';
    $xpathErr2 = '';
    if ($xml2 !== null) {
      $errNodes2 = $xml2->xpath('//errtext');
      if (!empty($errNodes2)) {
        $xpathErr2 = trim((string)$errNodes2[0]);
      }
    }
    $msg2 = $errtext2 ?: $sysText2 ?: $xpathErr2 ?: ($errcode2 ? 'Error code: ' . $errcode2 : ($sysCode2 ? 'System error code: ' . $sysCode2 : null));
    if (!$msg2) {
      $cleanBody2 = strip_tags(trim($resp2['body']));
      $msg2 = $cleanBody2 ?: 'Unknown error from Plesk';
    }
    $msg2 = (mb_strlen($msg2) > 300) ? mb_substr($msg2, 0, 300) . '...' : $msg2;
    return ['success' => false, 'message' => 'Customer account created, but subscription/hosting assignment failed: ' . $msg2 . '. Please contact support.'];
  }

  return ['success' => true, 'message' => 'Account successfully created!'];
}

// ── API Dispatcher ─────────────────────────────────────────────────────────
/**
 * Routes to the correct Plesk API implementation based on PLESK_AUTH_METHOD:
 *   'rest_api' → pleskRestCreateUser() – Plesk REST API v2 (admin API token)
 *   'xmlrpc'   → pleskXmlCreateUser()  – Plesk XML-RPC API (reseller login/password)
 */
function pleskCreateUser(array $data): array
{
  $method = defined('PLESK_AUTH_METHOD') ? PLESK_AUTH_METHOD : 'xmlrpc';
  if ($method === 'rest_api') {
    return pleskRestCreateUser($data);
  }
  return pleskXmlCreateUser($data);
}

// ── Audit Log ──────────────────────────────────────────────────────────────
/**
 * Writes a GDPR-compliant, JSON-Lines audit entry to the log file.
 * IPs are pseudonymized via a salted SHA-256 hash (not reversible without the salt).
 * Email addresses are masked to protect PII (e.g. j***@gmail.com).
 * The log file is rotated when it exceeds AUDIT_LOG_MAX_SIZE bytes.
 */
function auditLog(string $username, string $email, string $domain, string $result, string $reason): void
{
  if (!defined('AUDIT_LOG_ENABLED') || !AUDIT_LOG_ENABLED) return;

  $logPath = AUDIT_LOG_PATH;
  $logDir  = dirname($logPath);
  if (!is_dir($logDir)) @mkdir($logDir, 0750, true);

  // Rotate if over size limit
  if (file_exists($logPath) && filesize($logPath) > AUDIT_LOG_MAX_SIZE) {
    @rename($logPath, $logPath . '.' . date('Ymd-His'));
  }

  // Pseudonymize IP (GDPR: no plaintext personal data)
  // Respect TRUST_PROXY_HEADERS to match the rate limiter's IP resolution.
  if (defined('TRUST_PROXY_HEADERS') && TRUST_PROXY_HEADERS) {
    $rawIp = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $rawIp = explode(',', trim($rawIp))[0];
  } else {
    $rawIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  }
  $anonIp = substr(hash('sha256', $rawIp . LOG_IP_SALT), 0, 16);

  // Mask email (keep first char + domain for debugging)
  $maskedEmail = '';
  if ($email && strpos($email, '@') !== false) {
    [$local, $dom] = explode('@', $email, 2);
    $maskedEmail   = substr($local, 0, 1) . '***@' . $dom;
  }

  $entry = json_encode([
    't'      => date('c'),
    'ip'     => $anonIp,
    'user'   => $username,
    'domain' => $domain,
    'email'  => $maskedEmail,
    'result' => $result,
    'reason' => $reason ?: null,
  ], JSON_UNESCAPED_UNICODE);

  $fp = @fopen($logPath, 'a');
  if ($fp) {
    flock($fp, LOCK_EX);
    if (filesize($logPath) === 0) {
      fwrite($fp, "<?php exit; ?>\n");
    }
    fwrite($fp, $entry . "\n");
    flock($fp, LOCK_UN);
    fclose($fp);
  }
}

// ── DNS MX Check ───────────────────────────────────────────────────────────
/**
 * Checks if a domain has valid MX records.
 * Results are cached in the session for 60s to prevent DNS flooding on retries.
 * Fail-open: returns true if DNS resolution itself fails.
 */
function checkEmailMx(string $domain): bool
{
  if (!defined('ENABLE_MX_CHECK') || !ENABLE_MX_CHECK) return true;
  if (!$domain) return false;

  $cacheKey = 'mx_' . md5($domain);
  if (isset($_SESSION[$cacheKey]) && (time() - $_SESSION[$cacheKey]['ts']) < 60) {
    return $_SESSION[$cacheKey]['result'];
  }

  // checkdnsrr returns false on both "no MX" and "resolution failure"
  // Use dns_get_record for more control; fall back to true on error (fail-open)
  set_error_handler(function() {}, E_WARNING);
  $records = dns_get_record($domain, DNS_MX | DNS_A);
  restore_error_handler();

  // Fail-open: if dns_get_record returns false (DNS unavailable), allow registration
  if ($records === false) {
    $_SESSION[$cacheKey] = ['result' => true, 'ts' => time()];
    return true;
  }

  $hasMx = !empty($records);
  $_SESSION[$cacheKey] = ['result' => $hasMx, 'ts' => time()];
  return $hasMx;
}

// ── Invite Code Validation ─────────────────────────────────────────────────
/**
 * Validates an invite code and marks it as used if INVITE_SINGLE_USE is true.
 * Uses exclusive file locking to prevent race conditions.
 */
function validateInviteCode(string $code): bool
{
  if (!defined('INVITE_ONLY_MODE') || !INVITE_ONLY_MODE) return true;

  $code = strtoupper(trim($code));
  if (!$code) return false;

  // Check against configured valid codes (timing-safe loop)
  $isValid = false;
  foreach (INVITE_CODES as $validCode) {
    if (hash_equals(strtoupper(trim($validCode)), $code)) {
      $isValid = true;
      break;
    }
  }
  if (!$isValid) return false;

  if (!defined('INVITE_SINGLE_USE') || !INVITE_SINGLE_USE) return true;

  // Check and mark as used via flat file with exclusive lock
  $file = INVITE_CODES_FILE;
  $dir  = dirname($file);
  if (!is_dir($dir)) @mkdir($dir, 0750, true);
  if (!file_exists($file)) file_put_contents($file, "<?php exit; ?>\n" . json_encode(['used' => []]));

  $fp = @fopen($file, 'r+');
  if (!$fp) return false; // Cannot acquire file handle → deny

  $result = false;
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    $jsonStr = substr($raw, 15) ?: '{}';
    $data = json_decode($jsonStr, true) ?? ['used' => []];
    if (!in_array($code, (array)($data['used'] ?? []), true)) {
      $data['used'][] = $code;
      rewind($fp);
      ftruncate($fp, 0);
      fwrite($fp, "<?php exit; ?>\n" . json_encode($data, JSON_PRETTY_PRINT));
      $result = true;
    }
    flock($fp, LOCK_UN);
  }
  fclose($fp);
  return $result;
}



/**
 * Sends a POST request to a CAPTCHA verification API and returns decoded JSON.
 */
function captchaCurl(string $url, array $data): array
{
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => http_build_query($data),
    CURLOPT_RETURNTRANSFER => true,
    // External CAPTCHA APIs (hCaptcha, reCAPTCHA, Turnstile) use valid CA-signed certs.
    // SSL verification must ALWAYS be true here, regardless of PLESK_SSL_VERIFY.
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_TIMEOUT        => 10,
  ]);
  $res = curl_exec($ch);
  curl_close($ch);
  return json_decode((string) $res, true) ?? [];
}

/**
 * Verifies an ALTCHA proof-of-work payload without any external API call.
 * Steps: decode base64-JSON → check algorithm → verify PoW hash → verify HMAC signature → check expiry.
 */
function verifyAltchaPayload(string $payload): bool
{
  if (!$payload)
    return false;
  $data = json_decode(base64_decode($payload), true);
  if (!is_array($data))
    return false;

  $alg = $data['algorithm'] ?? '';
  $challenge = $data['challenge'] ?? '';
  $salt = $data['salt'] ?? '';
  $number = (string) ($data['number'] ?? '');
  $signature = $data['signature'] ?? '';

  // Only SHA-256 is supported
  if ($alg !== 'SHA-256')
    return false;

  // Check expiry embedded in salt params (e.g. "abc123?expires=1234567890")
  $query = parse_url($salt, PHP_URL_QUERY) ?? '';
  parse_str($query, $saltParams);
  if (isset($saltParams['expires']) && time() > (int) $saltParams['expires'])
    return false;

  // Verify Proof-of-Work: hash(salt + number) must equal challenge
  if (hash('sha256', $salt . $number) !== $challenge)
    return false;

  // Verify HMAC signature: prevents crafted challenges
  $expected = hash_hmac('sha256', $challenge, ALTCHA_HMAC_KEY);
  return hash_equals($expected, $signature);
}

/**
 * Dispatches to the configured CAPTCHA provider and returns true on success.
 */
function verifyCaptcha(): bool
{
  $provider = CAPTCHA_PROVIDER;
  if ($provider === 'none')
    return true;

  if ($provider === 'hcaptcha') {
    $token = $_POST['h-captcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://api.hcaptcha.com/siteverify', [
      'secret' => HCAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'recaptcha') {
    $token = $_POST['g-recaptcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://www.google.com/recaptcha/api/siteverify', [
      'secret' => RECAPTCHA_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'altcha') {
    return verifyAltchaPayload($_POST['altcha'] ?? '');
  }

  if ($provider === 'turnstile') {
    $token = $_POST['cf-turnstile-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://challenges.cloudflare.com/turnstile/v0/siteverify', [
      'secret' => TURNSTILE_SECRET_KEY,
      'response' => $token,
      'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
    ]);
    return ($r['success'] ?? false) === true;
  }

  if ($provider === 'mtcaptcha') {
    $token = $_POST['mtcaptcha-verifiedtoken'] ?? '';
    if (!$token)
      return false;
    // MTCaptcha uses GET for verification
    $url = 'https://service.mtcaptcha.com/mtcv1/api/checktoken'
      . '?privatekey=' . urlencode(MTCAPTCHA_PRIVATE_KEY)
      . '&token=' . urlencode($token);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      // MTCaptcha uses CA-signed certs; always verify regardless of PLESK_SSL_VERIFY.
      CURLOPT_SSL_VERIFYPEER => true,
      CURLOPT_SSL_VERIFYHOST => 2,
      CURLOPT_TIMEOUT        => 10,
    ]);
    $res = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno || !$res)
      return false;
    $parsed = json_decode($res, true);
    return ($parsed['success'] ?? false) === true;
  }

  return false;
}

// ── Process Form ───────────────────────────────────────────────────────────
$result = null;
if ($rateLimited && $_SERVER['REQUEST_METHOD'] !== 'POST') {
  $result = ['success' => false, 'message' => 'Too many registration attempts. Please wait a few minutes before trying again.'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Honeypot check
  if (!empty($_POST['website_hp'])) {
    // Silently drop bot registration but pretend it succeeded
    $result = ['success' => true, 'message' => 'Account successfully created!'];
  } elseif (!hash_equals($csrf, $_POST['csrf_token'] ?? '')) {
    $result = ['success' => false, 'message' => 'Invalid security token. Please refresh the page.'];
  } elseif ($rateLimited) {
    $result = ['success' => false, 'message' => 'Too many registrations. Please wait a few minutes.'];
  } elseif (CAPTCHA_PROVIDER !== 'none' && !verifyCaptcha()) {
    $result = ['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.'];
  } else {
    $username = strtolower(trim($_POST['username'] ?? ''));
    $fullname = trim($_POST['fullname'] ?? '');
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $domain = strtolower(trim($_POST['domain'] ?? ''));
    $passwd = $_POST['passwd'] ?? '';
    $passwd2 = $_POST['passwd2'] ?? '';
    $emailDomain = $email ? substr(strrchr($email, "@"), 1) : '';

    // Reserved Names Check
    $isReservedDomain = false;
    if (!empty($domain)) {
      $lowerDomain = strtolower($domain);
      $blockSub = defined('BLOCK_RESERVED_SUBDOMAINS') && BLOCK_RESERVED_SUBDOMAINS;
      foreach (RESERVED_DOMAINS as $rd) {
        $lowerRd = strtolower($rd);
        if ($lowerDomain === $lowerRd) {
          $isReservedDomain = true;
          break;
        }
        if ($blockSub && str_ends_with($lowerDomain, '.' . $lowerRd)) {
          $isReservedDomain = true;
          break;
        }
      }
    }

    if (MAINTENANCE_MODE) {
      $result = ['success' => false, 'message' => 'Registrations are currently paused.'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'maintenance_mode');
    } elseif ((!empty(TOS_URL) || !empty(PRIVACY_URL)) && empty($_POST['tos_agree'])) {
      $result = ['success' => false, 'message' => 'You must agree to the Terms of Service and Privacy Policy.'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'tos_not_agreed');
    } elseif (INVITE_ONLY_MODE && !validateInviteCode($_POST['invite_code'] ?? '')) {
      $result = ['success' => false, 'message' => 'Invalid or already used invitation code.'];
      auditLog($username ?? '', $email ?: '', $domain ?? '', 'fail', 'invite_invalid');
    } elseif (!preg_match('/^[a-z][a-z0-9\-\_]{3,15}$/', $username)) {
      $result = ['success' => false, 'message' => 'Username must be 4–16 characters, start with a letter, and contain only lowercase letters, digits, hyphens (-) or underscores (_).'];
      auditLog($username, $email ?: '', $domain ?? '', 'fail', 'username_invalid');
    } elseif ((!defined('PLESK_USERNAME_AS_NAME') || !PLESK_USERNAME_AS_NAME) && (empty($fullname) || mb_strlen($fullname) < 2)) {
      $result = ['success' => false, 'message' => 'Please enter your full name (at least 2 characters).'];
      auditLog($username, $email ?: '', $domain ?? '', 'fail', 'fullname_invalid');
    } elseif (in_array(strtolower($username), RESERVED_USERNAMES)) {
      $result = ['success' => false, 'message' => 'This username is reserved and cannot be registered.'];
      auditLog($username, $email ?: '', $domain ?? '', 'fail', 'username_reserved');
    } elseif (!$email) {
      $result = ['success' => false, 'message' => 'Please enter a valid email address.'];
      auditLog($username, '', $domain ?? '', 'fail', 'email_invalid');
    } elseif ($emailDomain && in_array(strtolower($emailDomain), BLOCKED_EMAIL_DOMAINS)) {
      $result = ['success' => false, 'message' => 'This email provider is not allowed. Please use a valid email address.'];
      auditLog($username, $email, $domain ?? '', 'fail', 'email_domain_blocked');
    } elseif ($emailDomain && !checkEmailMx($emailDomain)) {
      $result = ['success' => false, 'message' => 'The email domain does not appear to accept mail.'];
      auditLog($username, $email, $domain ?? '', 'fail', 'email_mx_no_records');
    } elseif (empty($domain) || !filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || strpos($domain, '.') === false) {
      $result = ['success' => false, 'message' => 'Please enter a valid domain (e.g. example.com).'];
      auditLog($username, $email, $domain ?? '', 'fail', 'domain_invalid');
    } elseif ($isReservedDomain) {
      $result = ['success' => false, 'message' => 'This domain is reserved and cannot be registered.'];
      auditLog($username, $email, $domain, 'fail', 'domain_reserved');
    } elseif (strlen($passwd) < PASSWD_MIN_LENGTH) {
      $result = ['success' => false, 'message' => 'Password must be at least ' . PASSWD_MIN_LENGTH . ' characters long.'];
      auditLog($username, $email, $domain, 'fail', 'password_too_short');
    } elseif (PASSWD_REQUIRE_COMPLEXITY && (!preg_match('/[A-Z]/', $passwd) || !preg_match('/[a-z]/', $passwd) || !preg_match('/[0-9]/', $passwd))) {
      $result = ['success' => false, 'message' => 'Password must contain at least one uppercase letter, one lowercase letter, and one number.'];
      auditLog($username, $email, $domain, 'fail', 'password_complexity');
    } elseif ($passwd !== $passwd2) {
      $result = ['success' => false, 'message' => 'Passwords do not match.'];
      auditLog($username, $email, $domain, 'fail', 'password_mismatch');
    } else {
      // Allow up to 120 seconds for slow Plesk server responses
      @set_time_limit(120);

      // Release PHP session lock so session file is not locked during long Plesk cURL request
      if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
      }

      $result = pleskCreateUser([
        'username' => $username,
        'fullname' => $fullname,
        'email'    => $email,
        'domain'   => $domain,
        'passwd'   => $passwd,
      ]);

      auditLog($username, $email, $domain, $result['success'] ? 'success' : 'fail', $result['success'] ? '' : 'plesk_api_error');
      if ($result['success']) {
        if (WEBHOOK_ENABLED && !empty(WEBHOOK_URL)) {
          $payload = json_encode(['content' => "🔔 **New Registration**\nUser: `{$username}`\nDomain: `{$domain}`\nEmail: `{$email}`"]);
          $ch = curl_init(WEBHOOK_URL);
          curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
          curl_setopt($ch, CURLOPT_POST, 1);
          curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
          curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
          curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
          curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
          curl_setopt($ch, CURLOPT_TIMEOUT, 3);
          curl_exec($ch);
          curl_close($ch);
        }

        if (!empty(ADMIN_EMAIL)) {
          $subject = "New Registration: $username";
          $msg = "A new user has registered.\n\nUsername: $username\nDomain: $domain\nEmail: $email\nDate: " . date('Y-m-d H:i:s') . "\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
          $rawHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
          $host = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $rawHost) ?: 'localhost';
          $safeReplyTo = str_replace(["\r", "\n", "\0"], '', filter_var($email, FILTER_SANITIZE_EMAIL));
          $headers = "From: no-reply@" . $host . "\r\n" .
            "Reply-To: " . $safeReplyTo . "\r\n" .
            "X-Mailer: PHP/" . phpversion();
          @mail(ADMIN_EMAIL, $subject, $msg, $headers);
        }

        // ── Demo Mode: Track account for scheduled deletion ─────────────────
        if (defined('DEMO_MODE') && DEMO_MODE) {
          $demoFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');
          $demoDir  = dirname($demoFile);
          if (!is_dir($demoDir)) { @mkdir($demoDir, 0750, true); }
          $accounts = [];
          if (is_file($demoFile)) {
            $raw = file_get_contents($demoFile);
            $accounts = json_decode($raw, true) ?: [];
          }
          $accounts[$username] = [
            'domain'      => $domain,
            'email'       => $email,
            'created_at'  => time(),
            'delete_after'=> time() + (defined('DEMO_LIFETIME_HOURS') ? (int)DEMO_LIFETIME_HOURS : 2) * 3600,
          ];
          file_put_contents($demoFile, json_encode($accounts, JSON_PRETTY_PRINT), LOCK_EX);
        }
      }
    }
  }

  // Re-open session if closed to safely update CSRF token on success
  if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start([
      'cookie_httponly' => true,
      'cookie_samesite' => 'Lax',
      'cookie_secure'   => $isHttps,
    ]);
  }

  if ($result && $result['success']) {
    // Regenerate CSRF token only on successful account creation
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $csrf = $_SESSION['csrf_token'];
  } else {
    // Keep existing CSRF token intact on form re-display / validation error
    $csrf = $_SESSION['csrf_token'] ?? $csrf;
  }
}

$now = date('j.n.Y, H:i');
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#375e6e" />
  <title><?= SITE_TITLE ?></title>
  <meta name="description" content="Plesk Account Registration" />
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet" />
  <meta name="googlebot" content="noindex, nofollow" />
  <link rel="icon" type="image/svg+xml"
    href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 42 42'%3E%3Crect width='42' height='42' rx='10' fill='%23375e6e'/%3E%3Cpath d='M8 21L16 13L24 21L16 29L8 21Z' fill='%23ffffff'/%3E%3Cpath d='M18 21L26 13L34 21L26 29L18 21Z' fill='%23ffffff' opacity='.6'/%3E%3C/svg%3E" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet" />
  <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"></script>
  <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
    <script>
      var mtcaptchaConfig = { "sitekey": "<?= htmlspecialchars(MTCAPTCHA_SITE_KEY) ?>" };
      (function () {
        var mt_service = document.createElement('script');
        mt_service.async = true;
        mt_service.src = 'https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service);
        var mt_service2 = document.createElement('script');
        mt_service2.async = true;
        mt_service2.src = 'https://service2.mtcaptcha.com/mtcv1/client/mtcaptcha2.min.js';
        (document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(mt_service2);
      })();
    </script>
  <?php endif; ?>
  <style>
    /* ── Plesk-Style Design System ─────────────────────────────────────────── */
    :root {
      /* Plesk Core Colors */
      --plesk-bg:       #555961;
      --plesk-header:   #3d6778;
      --plesk-header-2: #345a6a;
      --card-bg:        #f5f6f7;
      --card-body:      #ffffff;
      --plesk-blue:     #375e6e;
      --plesk-blue-h:   #2b4b58;
      --plesk-blue-dk:  #203943;
      --input-bg:       #ffffff;
      --input-border:   #c8cdd2;
      --input-focus:    #375e6e;
      --text-main:      #333333;
      --text-label:     #464646;
      --text-muted:     #8a8a8a;
      --link-color:     #375e6e;
      --ok-bg:          rgba(39, 170, 90, .1);
      --ok-border:      rgba(39, 170, 90, .35);
      --ok-text:        #1e8a44;
      --err-bg:         rgba(210, 50, 50, .08);
      --err-border:     rgba(210, 50, 50, .35);
      --err-text:       #c0392b;
      --btn:            #375e6e;
      --btn-h:          #2b4b58;
      --btn-text:       #ffffff;
      --sub:            #6a7585;
      --sb-track:       rgba(0,0,0,.08);
      --sb-thumb:       rgba(0,0,0,.22);
      --sb-thumb-h:     rgba(0,0,0,.38);
    }

    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    * {
      scrollbar-width: thin;
      scrollbar-color: var(--sb-thumb) var(--sb-track);
    }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--sb-track); border-radius: 3px; }
    ::-webkit-scrollbar-thumb { background: var(--sb-thumb); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--sb-thumb-h); }

    body {
      font-family: 'Open Sans', 'Inter', 'Helvetica Neue', Arial, sans-serif;
      background: var(--plesk-bg);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      position: relative;
      overflow-x: hidden;
      overflow-y: auto;
    }

    /* ── Preloader ───────────────────────────────────────────────────────── */
    #preloader {
      position: fixed;
      inset: 0;
      background: var(--plesk-bg);
      z-index: 9999;
      display: grid;
      place-content: center;
      transition: opacity .4s ease, visibility .4s ease;
    }
    #preloader.hidden { opacity: 0; visibility: hidden; }
    #preloader-spinner {
      color: var(--plesk-blue);
      display: inline-block;
      position: relative;
      width: 56px;
      height: 56px;
    }
    #preloader-spinner div {
      box-sizing: border-box;
      display: block;
      position: absolute;
      width: 56px;
      height: 56px;
      border: 5px solid currentColor;
      border-radius: 50%;
      animation: lds-ring 1.2s cubic-bezier(.5,0,.5,1) infinite;
      border-color: currentColor transparent transparent transparent;
    }
    #preloader-spinner div:nth-child(1) { animation-delay: -.45s; }
    #preloader-spinner div:nth-child(2) { animation-delay: -.3s; }
    #preloader-spinner div:nth-child(3) { animation-delay: -.15s; }
    @keyframes lds-ring {
      0%   { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    /* ── Header Language Dropdown ───────────────────────────────────────── */
    .card-header-right {
      position: relative;
    }
    .lang-header-btn {
      display: flex;
      align-items: center;
      gap: 5px;
      background: transparent;
      border: none;
      color: rgba(255,255,255,.85);
      font-family: inherit;
      font-size: .82rem;
      font-weight: 500;
      cursor: pointer;
      padding: 4px 8px;
      border-radius: 4px;
      transition: color .18s, background .18s;
    }
    .lang-header-btn:hover {
      color: #ffffff;
      background: rgba(255,255,255,.12);
    }
    .lang-header-btn svg { opacity: .85; }
    .lang-dropdown {
      position: absolute;
      top: calc(100% + 8px);
      right: 0;
      background: #ffffff;
      border: 1px solid #d5d9df;
      border-radius: 4px;
      padding: 4px;
      width: 170px;
      max-height: 260px;
      overflow-y: auto;
      box-shadow: 0 8px 24px rgba(0,0,0,.22);
      display: none;
      z-index: 200;
    }
    .lang-dropdown.show { display: block; }
    .lang-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 6px 10px;
      border: none;
      background: transparent;
      color: var(--text-main);
      font-family: inherit;
      font-size: .82rem;
      border-radius: 4px;
      cursor: pointer;
      text-align: left;
      transition: background .12s;
    }
    .lang-item:hover  { background: #f0f3f6; }
    .lang-item.active { color: var(--plesk-blue); font-weight: 600; }
    .lang-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 6px 10px;
      border: none;
      background: transparent;
      color: var(--text-main);
      font-family: inherit;
      font-size: .82rem;
      border-radius: 4px;
      cursor: pointer;
      text-align: left;
      transition: background .12s;
    }
    .lang-item:hover  { background: #f0f3f6; }
    .lang-item.active { color: var(--plesk-blue); font-weight: 600; }

    /* ── Card ─────────────────────────────────────────────────────────────── */
    .card {
      position: relative;
      z-index: 1;
      background: var(--card-body);
      border-radius: 2px;
      width: 100%;
      max-width: 500px;
      box-shadow: 0 4px 24px rgba(0,0,0,.32), 0 1px 4px rgba(0,0,0,.18);
      overflow: hidden;
      margin: 16px;
    }

    /* ── Card Header (Plesk-style blue-gray bar) ───────────────────────── */
    .card-header {
      background: linear-gradient(135deg, var(--plesk-header) 0%, var(--plesk-header-2) 100%);
      padding: 18px 28px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .card-header-logo {
      display: flex;
      align-items: baseline;
      gap: 10px;
    }
    .card-header-logo h1 {
      font-size: 1.85rem;
      font-weight: 300;
      color: #ffffff;
      letter-spacing: -.01em;
      line-height: 1;
      position: relative;
    }
    /* Cyan underline accent */
    .card-header-logo h1::after {
      content: '';
      display: block;
      width: 28px;
      height: 2.5px;
      background: var(--plesk-blue);
      margin-top: 5px;
      border-radius: 1px;
    }
    .card-header-logo .header-edition {
      font-size: .8rem;
      color: rgba(255,255,255,.7);
      font-weight: 400;
      letter-spacing: .01em;
      white-space: nowrap;
    }
    .card-header-right {
      display: flex;
      align-items: center;
      gap: 6px;
      color: rgba(255,255,255,.75);
      font-size: .82rem;
      cursor: default;
    }
    .card-header-right svg {
      width: 18px;
      height: 18px;
      opacity: .8;
    }

    /* ── Card Body ───────────────────────────────────────────────────────── */
    .card-body {
      padding: 28px 32px 28px;
      background: #ffffff;
    }

    /* ── Alert ────────────────────────────────────────────────────────────── */
    .alert {
      border-radius: 3px;
      padding: 10px 14px;
      font-size: .85rem;
      margin-bottom: 18px;
      border-left: 4px solid;
      line-height: 1.5;
    }
    .alert-error   { background: var(--err-bg);  border-color: var(--err-text); color: var(--err-text); }
    .alert-success { background: var(--ok-bg);   border-color: var(--ok-text);  color: var(--ok-text);  }
    .alert a { color: inherit; font-weight: 600; }

    /* ── Form Fields ─────────────────────────────────────────────────────── */
    .field { margin-bottom: 16px; }

    label {
      display: block;
      font-size: .8rem;
      font-weight: 600;
      margin-bottom: 5px;
      color: var(--text-label);
    }

    .input-wrap { position: relative; }

    input[type=text],
    input[type=email],
    input[type=password] {
      width: 100%;
      background: var(--input-bg);
      border: 1px solid var(--input-border);
      border-radius: 2px;
      color: var(--text-main);
      font-family: inherit;
      font-size: .9rem;
      padding: 9px 13px;
      outline: none;
      transition: border-color .18s, box-shadow .18s;
    }
    input:focus {
      border-color: var(--input-focus);
      box-shadow: 0 0 0 2px rgba(39,170,223,.18);
    }
    input::placeholder { color: #b0b8c2; }

    /* Eye toggle */
    .eye-btn {
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      color: var(--text-muted);
      display: flex;
      padding: 4px;
      transition: color .18s;
    }
    .eye-btn:hover { color: var(--plesk-blue); }
    .eye-btn svg.hide-icon { display: none; }
    .pw-field { padding-right: 40px !important; }

    /* Copy password button */
    .copy-pw-btn {
      background: none;
      border: 1px solid var(--input-border);
      border-radius: 3px;
      cursor: pointer;
      color: var(--text-muted);
      font-size: 0.75rem;
      padding: 3px 8px;
      display: flex;
      align-items: center;
      gap: 4px;
      transition: all .18s;
      white-space: nowrap;
    }
    .copy-pw-btn:hover   { color: var(--text-main); border-color: var(--plesk-blue); }
    .copy-pw-btn.copied  { color: var(--ok-text); border-color: var(--ok-text); }

    /* Field row */
    .field-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    /* ── Submit Button ─────────────────────────────────────────────────────── */
    .btn {
      width: 100%;
      padding: 11px 16px;
      background: var(--btn);
      color: var(--btn-text);
      border: none;
      border-radius: 2px;
      font-family: inherit;
      font-size: .95rem;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: background .18s, opacity .18s;
      margin-top: 20px;
      letter-spacing: .01em;
    }
    .btn:hover    { background: var(--btn-h); }
    .btn:active   { opacity: .88; }
    .btn:disabled { opacity: .55; cursor: not-allowed; }

    .spinner {
      width: 16px;
      height: 16px;
      border: 2px solid rgba(255,255,255,.4);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin .7s linear infinite;
      display: none;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Password Strength ───────────────────────────────────────────────── */
    .pw-meter { margin-top: 8px; }
    .pw-meter-bar {
      height: 3px;
      background: #e0e4e8;
      border-radius: 2px;
      overflow: hidden;
    }
    .pw-meter-fill {
      height: 100%;
      width: 0%;
      transition: width .3s ease, background-color .3s ease;
    }
    .pw-meter-text {
      font-size: .73rem;
      margin-top: 4px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
    }

    /* Password Checklist */
    .pw-checklist {
      list-style: none;
      margin-top: 8px;
      padding: 0;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 5px 8px;
    }
    .pw-check-item {
      display: flex;
      align-items: center;
      gap: 5px;
      font-size: 0.73rem;
      color: var(--text-muted);
      transition: color .18s;
    }
    .pw-check-item .check-icon {
      width: 14px; height: 14px;
      border-radius: 50%;
      border: 1.5px solid #c0c8d0;
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0;
      transition: background .18s, border-color .18s;
      font-size: .6rem;
    }
    .pw-check-item.ok             { color: var(--ok-text); }
    .pw-check-item.ok .check-icon { background: var(--ok-text); border-color: var(--ok-text); color: #fff; }

    /* HIBP status */
    .hibp-status {
      font-size: .78rem;
      margin-top: 6px;
      padding: 6px 10px;
      border-radius: 3px;
      display: none;
    }
    .hibp-status.checking { display:block; color: var(--text-muted); }
    .hibp-status.warning  { display:block; color: var(--err-text); background: var(--err-bg); border: 1px solid var(--err-border); }
    .hibp-status.ok       { display:block; color: var(--ok-text);  background: var(--ok-bg);  border: 1px solid var(--ok-border); }

    /* ── Login / support links area ──────────────────────────────────────── */
    .form-links {
      margin-top: 18px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .form-link-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: .83rem;
      color: var(--link-color);
      text-decoration: none;
      cursor: pointer;
    }
    .form-link-item:hover { text-decoration: underline; }
    .form-link-item svg {
      width: 15px; height: 15px;
      flex-shrink: 0;
      color: var(--link-color);
    }



    /* ── Bottom time ─────────────────────────────────────────────────────── */
    .bottom-time {
      position: fixed;
      bottom: 16px;
      font-size: .76rem;
      color: rgba(255,255,255,.45);
      z-index: 1;
    }

    /* ── ALTCHA widget ───────────────────────────────────────────────────── */
    altcha-widget {
      --altcha-color-border: var(--input-border);
      --altcha-color-border-focus: var(--input-focus);
      --altcha-color-background: var(--input-bg);
      --altcha-color-text: var(--text-main);
      --altcha-color-text-secondary: var(--text-muted);
      --altcha-border-radius: 2px;
      width: 100%;
      margin-top: 16px;
      display: block;
    }

    /* ── Cookie Banner ───────────────────────────────────────────────────── */
    #cookieBanner {
      position: fixed;
      bottom: 0; left: 0; right: 0;
      z-index: 9998;
      background: rgba(255,255,255,.97);
      border-top: 1px solid #d0d5da;
      padding: 14px 22px;
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
      justify-content: space-between;
      transform: translateY(100%);
      transition: transform .35s cubic-bezier(.16,1,.3,1);
      box-shadow: 0 -4px 18px rgba(0,0,0,.1);
    }
    #cookieBanner.visible { transform: translateY(0); }
    #cookieBanner p {
      font-size: .82rem;
      color: var(--text-muted);
      line-height: 1.5;
      margin: 0;
      flex: 1;
      min-width: 200px;
    }
    #cookieAcceptBtn {
      background: var(--btn);
      color: #fff;
      border: none;
      border-radius: 2px;
      padding: 8px 20px;
      font-family: inherit;
      font-size: .84rem;
      font-weight: 600;
      cursor: pointer;
      transition: background .18s;
      white-space: nowrap;
      flex-shrink: 0;
    }
    #cookieAcceptBtn:hover { background: var(--btn-h); }

    /* ── Accessibility Widget ────────────────────────────────────────────── */
    #a11yWidget {
      position: fixed;
      bottom: 18px;
      right: 18px;
      z-index: 500;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
    }
    #a11yToggleBtn {
      width: 38px; height: 38px;
      border-radius: 50%;
      background: var(--plesk-blue);
      border: none;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 3px 12px rgba(39,170,223,.4);
      transition: background .18s, transform .18s;
    }
    #a11yToggleBtn:hover { background: var(--btn-h); transform: scale(1.07); }
    #a11yToggleBtn svg   { width: 18px; height: 18px; }
    #a11yPanel {
      background: #fff;
      border: 1px solid #d0d5da;
      border-radius: 6px;
      padding: 12px 14px;
      width: 205px;
      box-shadow: 0 8px 28px rgba(0,0,0,.15);
      display: none;
      flex-direction: column;
      gap: 10px;
      animation: fadeIn .18s ease-out;
    }
    #a11yPanel.open { display: flex; }
    #a11yPanel h4 {
      font-size: .74rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: .08em;
      margin: 0 0 2px;
      border-bottom: 1px solid #e8ebee;
      padding-bottom: 8px;
    }
    .a11y-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .a11y-label { font-size: .81rem; color: var(--text-main); }
    .a11y-controls { display: flex; align-items: center; gap: 5px; }
    .a11y-btn {
      width: 26px; height: 26px;
      border-radius: 3px;
      background: #f0f3f6;
      border: 1px solid #d0d5da;
      color: var(--text-main);
      font-size: .88rem;
      font-family: inherit;
      cursor: pointer;
      display: flex; align-items: center; justify-content: center;
      transition: background .12s;
    }
    .a11y-btn:hover { background: #e0e5ea; }
    .a11y-toggle-switch { position: relative; width: 34px; height: 19px; cursor: pointer; }
    .a11y-toggle-switch input { opacity: 0; width: 0; height: 0; position: absolute; }
    .a11y-slider {
      position: absolute;
      inset: 0;
      background: #d0d5da;
      border-radius: 10px;
      transition: background .2s;
    }
    .a11y-slider::before {
      content: '';
      position: absolute;
      width: 13px; height: 13px;
      left: 3px; top: 3px;
      background: #fff;
      border-radius: 50%;
      transition: transform .2s;
    }
    .a11y-toggle-switch input:checked + .a11y-slider { background: var(--plesk-blue); }
    .a11y-toggle-switch input:checked + .a11y-slider::before { transform: translateX(15px); }
    #a11yFontSize { font-size: .76rem; color: var(--text-muted); min-width: 20px; text-align: center; }

    /* ── Invite code field ───────────────────────────────────────────────── */
    .invite-field input {
      letter-spacing: .06em;
      text-transform: uppercase;
    }

    /* ── TOS checkbox ────────────────────────────────────────────────────── */
    .tos-wrap {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      margin-top: 12px;
    }
    .tos-wrap input[type=checkbox] {
      margin-top: 2px;
      cursor: pointer;
      width: auto;
      accent-color: var(--plesk-blue);
    }
    .tos-wrap label {
      font-size: .83rem;
      color: var(--text-muted);
      line-height: 1.45;
      font-weight: 400;
      cursor: pointer;
    }
    .tos-wrap a { color: var(--link-color); text-decoration: none; }
    .tos-wrap a:hover { text-decoration: underline; }

    /* ── Animations ──────────────────────────────────────────────────────── */
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(-6px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .card { animation: fadeIn .3s ease-out; }
  </style>
</head>

<body>

  <!-- Preloader -->
  <div id="preloader">
    <div id="preloader-spinner">
      <div></div>
      <div></div>
      <div></div>
    </div>
  </div>



  <!-- Card -->
  <div class="card">
    <!-- Plesk-style header bar -->
    <div class="card-header">
      <div class="card-header-logo">
        <h1><?= htmlspecialchars(CARD_HEADING) ?></h1>
        <span class="header-edition"><?= htmlspecialchars(CARD_SUBHEADING) ?></span>
      </div>
      <!-- Language selector in header right -->
      <div class="card-header-right" id="langWrap">
        <button type="button" class="lang-header-btn" id="langBtn" aria-label="Select language" aria-expanded="false">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
            <circle cx="12" cy="12" r="10" />
            <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
          </svg>
          <span id="currentLangLabel">EN</span>
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </button>
        <div class="lang-dropdown" id="langDropdown" role="menu"></div>
      </div>
    </div>
    <!-- Card Body -->
    <div class="card-body">

    <?php if (MAINTENANCE_MODE): ?>
      <div style="text-align:center; padding: 40px 10px 20px;">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--sub)" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:20px; display:inline-block;">
          <path
            d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z">
          </path>
        </svg>
        <h2 style="margin-bottom:12px; font-weight:600; font-size:1.5rem; color:var(--text);"
          data-i18n="maintenance_heading">Maintenance Mode</h2>
        <p style="color:var(--sub); margin-bottom:20px; font-size: 1rem; line-height:1.5;" data-i18n="maintenance_text">
          New registrations are currently paused for maintenance. Please check back later.
        </p>
      </div>
    <?php elseif ($result && $result['success']): ?>
      <!-- Success page in Plesk style -->
      <div style="animation: fadeIn 0.35s ease-out;">
        <!-- Green success banner -->
        <div style="background: #f0faf4; border-left: 4px solid #27ae60; padding: 20px 24px; display:flex; align-items:center; gap:16px; margin-bottom:0;">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#27ae60" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
            <polyline points="22 4 12 14.01 9 11.01"></polyline>
          </svg>
          <div>
            <div style="font-size:1.05rem; font-weight:700; color:#1e6e3a; margin-bottom:2px;" data-i18n="success_heading">Account Created!</div>
            <div style="font-size:.85rem; color:#2e8b57; line-height:1.4;"><?= htmlspecialchars($result['message']) ?></div>
          </div>
        </div>

        <!-- Account info summary -->
        <div style="padding: 22px 24px; background:#fff; border-top: 1px solid #e8ecee;">
          <table style="width:100%; border-collapse:collapse; font-size:.88rem;">
            <tr style="border-bottom:1px solid #f0f2f4;">
              <td style="padding:8px 0; color:#6a7585; width:40%;" data-i18n="full_name">Full Name</td>
              <td style="padding:8px 0; color:#333; font-weight:600;"><?= htmlspecialchars($fullname ?? '') ?></td>
            </tr>
            <tr style="border-bottom:1px solid #f0f2f4;">
              <td style="padding:8px 0; color:#6a7585;" data-i18n="username">Username</td>
              <td style="padding:8px 0; color:#333; font-weight:600; font-family:monospace;"><?= htmlspecialchars($username ?? '') ?></td>
            </tr>
            <tr style="border-bottom:1px solid #f0f2f4;">
              <td style="padding:8px 0; color:#6a7585;" data-i18n="domain">Domain</td>
              <td style="padding:8px 0; color:#333; font-weight:600; font-family:monospace;"><?= htmlspecialchars($domain ?? '') ?></td>
            </tr>
            <tr>
              <td style="padding:8px 0; color:#6a7585;" data-i18n="email">Email</td>
              <td style="padding:8px 0; color:#333;"><?= htmlspecialchars($email ?? '') ?></td>
            </tr>
          </table>
        </div>

        <!-- 2FA hint -->
        <div style="background:#f5f9ff; border-top:1px solid #dce8f5; padding:12px 24px; display:flex; align-items:center; gap:10px;">
          <svg width="16" height="16" fill="none" stroke="#375e6e" stroke-width="2" viewBox="0 0 24 24" style="flex-shrink:0">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <p style="font-size:.82rem; color:#3a7ab8; margin:0; line-height:1.4;" data-i18n="setup_2fa">We recommend enabling Two-Factor Authentication (2FA) in the panel.</p>
        </div>

        <?php if (defined('DEMO_MODE') && DEMO_MODE): ?>
        <div style="padding:12px 24px 0;">
          <p style="background:rgba(255,108,47,0.12); border:1px solid rgba(255,108,47,0.4); border-radius:10px; padding:12px 16px; margin:0; font-size:0.88rem; line-height:1.5; color:var(--text);"
            data-i18n-demo-hours="<?= (int)(defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?>"
            data-i18n="demo_notice">
            ⏱ This is a demo account and will be automatically deleted after <?= (int)(defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?> hour(s).
          </p>
        </div>
        <?php endif; ?>

        <!-- Login button -->
        <div style="padding:20px 24px;">
          <a href="<?= htmlspecialchars(PANEL_URL) ?>" class="btn" style="text-decoration:none; display:flex;" data-i18n="to_login">To Login</a>
        </div>
      </div>
    <?php else: ?>
      <?php if ($result && !$result['success']): ?>
        <div class="alert alert-error">
          <?= htmlspecialchars($result['message']) ?>
        </div>
      <?php endif; ?>

      <form method="POST" action="" id="regForm" novalidate autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>" />
        <input type="text" name="website_hp" style="display:none" tabindex="-1" autocomplete="off">

        <div class="field">
          <label for="username" data-i18n="username">Username</label>
          <input type="text" id="username" name="username" data-i18n-ph="username_ph" placeholder="4–16 chars, a-z _ 0-9"
            value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" maxlength="16" autocomplete="username" required>
        </div>

        <?php if (!defined('PLESK_USERNAME_AS_NAME') || !PLESK_USERNAME_AS_NAME): ?>
        <div class="field">
          <label for="fullname" data-i18n="full_name">Full Name</label>
          <input type="text" id="fullname" name="fullname" data-i18n-ph="full_name_ph" placeholder="Jane Doe"
            value="<?= htmlspecialchars($_POST['fullname'] ?? '') ?>" maxlength="80" autocomplete="name" required>
        </div>
        <?php endif; ?>

        <div class="field">
          <label for="email" data-i18n="email">Email Address</label>
          <input type="email" id="email" name="email" data-i18n-ph="email_ph" placeholder="user@example.com"
            value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" autocomplete="email" required>
          <div id="emailSuggestion" style="display:none; font-size: 0.85rem; margin-top: 6px; color: var(--sub);">
            <span data-i18n="did_you_mean">Did you mean</span> <a href="#" id="emailSuggestionLink"
              style="color: var(--btn); text-decoration: none; font-weight: 500;"></a>?
          </div>
        </div>

        <div class="field">
          <label for="domain" data-i18n="domain">Domain</label>
          <input type="text" id="domain" name="domain" data-i18n-ph="domain_ph" placeholder="example.com"
            value="<?= htmlspecialchars($_POST['domain'] ?? '') ?>" autocomplete="off" required>
        </div>

        <div class="field-row">
          <div class="field" style="margin-bottom:0">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <label for="passwd" data-i18n="password" style="margin-bottom:0;">Password</label>
              <button type="button" id="generatePwBtn"
                style="background:none; border:none; cursor:pointer; color:var(--btn); font-size:0.75rem; display:flex; align-items:center; gap:4px; padding:0;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round">
                  <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                </svg>
                <span data-i18n="generate">Generate</span>
              </button>
            </div>
            <div class="input-wrap">
              <input type="password" id="passwd" name="passwd" class="pw-field" data-i18n-ph="password_ph"
                placeholder="Min. <?= PASSWD_MIN_LENGTH ?> chars" autocomplete="new-password" required>
              <button type="button" class="eye-btn" data-target="passwd" aria-label="Show password">
                <!-- Eye open (default: password hidden) -->
                <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <!-- Eye closed (shown when password is visible) -->
                <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field" style="margin-bottom:0">
            <label for="passwd2" data-i18n="confirm">Confirm</label>
            <div class="input-wrap">
              <input type="password" id="passwd2" name="passwd2" class="pw-field" data-i18n-ph="confirm_ph"
                placeholder="Repeat" autocomplete="new-password" required>
              <button type="button" class="eye-btn" data-target="passwd2" aria-label="Show password">
                <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none"
                  viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                  <path
                    d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        <div class="pw-meter" id="pwMeter">
          <div class="pw-meter-bar">
            <div class="pw-meter-fill" id="pwMeterFill"></div>
          </div>
          <div class="pw-meter-text">
            <span id="pwHint" data-i18n="pw_hint">A-Z, a-z, 0-9</span>
            <div style="display:flex; align-items:center; gap:10px;">
              <span id="pwMeterText"></span>
              <button type="button" id="copyPwBtn" class="copy-pw-btn" style="display:none;" title="Copy password">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                  stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                <span id="copyPwLabel" data-i18n="copy_pw">Copy</span>
              </button>
            </div>
          </div>
        </div>

        <?php if (defined('PASSWD_SHOW_CHECKLIST') && PASSWD_SHOW_CHECKLIST): ?>
        <ul class="pw-checklist" id="pwChecklist"
            data-min="<?= PASSWD_MIN_LENGTH ?>"
            data-complexity="<?= PASSWD_REQUIRE_COMPLEXITY ? '1' : '0' ?>">
          <li class="pw-check-item" id="chk-length">
            <span class="check-icon">✓</span>
            <span data-i18n-min="pw_req_length">At least <?= PASSWD_MIN_LENGTH ?> characters</span>
          </li>
          <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          <li class="pw-check-item" id="chk-upper">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_upper">One uppercase letter (A-Z)</span>
          </li>
          <li class="pw-check-item" id="chk-lower">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_lower">One lowercase letter (a-z)</span>
          </li>
          <li class="pw-check-item" id="chk-number">
            <span class="check-icon">✓</span>
            <span data-i18n="pw_req_number">One number (0-9)</span>
          </li>
          <?php endif; ?>
        </ul>
        <?php endif; ?>

        <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
        <div class="hibp-status" id="hibpStatus"></div>
        <?php endif; ?>

        <?php if (defined('INVITE_ONLY_MODE') && INVITE_ONLY_MODE): ?>
          <div class="field">
            <label for="invite_code" data-i18n="invite_code">Invitation Code</label>
            <input type="text" id="invite_code" name="invite_code"
                   data-i18n-ph="invite_code_ph" placeholder="Enter your invite code"
                   maxlength="32" autocomplete="off" spellcheck="false"
                   style="text-transform:uppercase; letter-spacing:0.05em;">
          </div>
        <?php endif; ?>

        <?php if (!empty(TOS_URL) || !empty(PRIVACY_URL)): ?>
          <div class="field" style="margin-top: 15px; display: flex; align-items: flex-start; gap: 8px;">
            <input type="checkbox" id="tos_agree" name="tos_agree" value="1" required
              style="margin-top: 3px; cursor: pointer; width: auto;">
            <label for="tos_agree"
              style="font-size: 0.85rem; color: var(--sub); line-height: 1.4; font-weight: normal; cursor: pointer;">
              <span data-i18n="tos_prefix">I agree to the</span>
              <?php if (!empty(TOS_URL)): ?>
                <a href="<?= htmlspecialchars(TOS_URL) ?>" target="_blank" data-i18n="tos_link"
                  style="color: var(--btn);">Terms of Service</a>
              <?php endif; ?>
              <?php if (!empty(TOS_URL) && !empty(PRIVACY_URL)): ?>
                <span data-i18n="tos_and">and</span>
              <?php endif; ?>
              <?php if (!empty(PRIVACY_URL)): ?>
                <a href="<?= htmlspecialchars(PRIVACY_URL) ?>" target="_blank" data-i18n="privacy_link"
                  style="color: var(--btn);">Privacy Policy</a>
              <?php endif; ?>
            </label>
          </div>
        <?php endif; ?>

        <div class="captcha-wrapper" style="margin-top: 18px; display: flex; justify-content: center; width: 100%;">
          <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
            <div class="h-captcha" data-sitekey="<?= htmlspecialchars(HCAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'recaptcha'): ?>
            <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars(RECAPTCHA_SITE_KEY) ?>"></div>
          <?php elseif (CAPTCHA_PROVIDER === 'altcha'): ?>
            <altcha-widget challengeurl="altcha-challenge.php"></altcha-widget>
          <?php elseif (CAPTCHA_PROVIDER === 'turnstile'): ?>
            <div class="cf-turnstile" data-sitekey="<?= htmlspecialchars(TURNSTILE_SITE_KEY) ?>"
              <?= $rateLimited ? 'data-execution="execute"' : '' ?>></div>
          <?php elseif (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
            <div class="mtcaptcha"></div>
          <?php endif; ?>
        </div>

        <button type="submit" class="btn" id="submitBtn" <?= $rateLimited ? 'disabled' : '' ?>>
          <div class="spinner" id="spinner"></div>
          <span id="submitLabel" data-i18n="register">Register</span>
        </button>
      </form>

      <div class="form-links">
        <a href="<?= htmlspecialchars(PANEL_URL) ?>" target="_blank" class="form-link-item">
          <!-- Arrow/login icon -->
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" /><polyline points="10 17 15 12 10 7" /><line x1="15" y1="12" x2="3" y2="12" />
          </svg>
          <span data-i18n="to_login">Already registered? Log in</span>
        </a>
        <a href="<?= defined('RESET_PASSWORD_URL') ? htmlspecialchars(RESET_PASSWORD_URL) : htmlspecialchars(PANEL_URL) . 'get_password.php' ?>" target="_blank" class="form-link-item">
          <!-- Lock icon -->
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <span data-i18n="forgot_password">Forgot your password?</span>
        </a>
        <?php if (!empty(SUPPORT_URL) || !empty(SUPPORT_EMAIL)): ?>
        <a href="<?= !empty(SUPPORT_URL) ? htmlspecialchars(SUPPORT_URL) : 'mailto:' . htmlspecialchars(SUPPORT_EMAIL) ?>" target="_blank" class="form-link-item">
          <!-- Help / Support icon -->
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <span data-i18n="contact_support">Contact Support</span>
        </a>
        <?php endif; ?>
      </div>
    <?php endif; ?>
    </div><!-- /card-body -->
  </div><!-- /card -->

  <div class="bottom-time" id="clock"><?= htmlspecialchars($now) ?></div>

  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
  <!-- Cookie Consent Banner -->
  <div id="cookieBanner" role="dialog" aria-label="Cookie consent" aria-live="polite">
    <p id="cookieBannerText"><?= htmlspecialchars(COOKIE_BANNER_TEXT) ?></p>
    <button id="cookieAcceptBtn" type="button"><?= htmlspecialchars(COOKIE_BANNER_BTN) ?></button>
  </div>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
  <!-- Accessibility Widget -->
  <div id="a11yWidget" role="complementary" aria-label="Accessibility tools">
    <div id="a11yPanel" role="region" aria-label="Accessibility options">
      <h4>Accessibility</h4>
      <div class="a11y-row">
        <span class="a11y-label">Font Size</span>
        <div class="a11y-controls">
          <button class="a11y-btn" id="a11yFontDec" aria-label="Decrease font size" title="Decrease font size">A−</button>
          <span id="a11yFontSize">100%</span>
          <button class="a11y-btn" id="a11yFontInc" aria-label="Increase font size" title="Increase font size">A+</button>
        </div>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">High Contrast</span>
        <label class="a11y-toggle-switch" aria-label="Toggle high contrast">
          <input type="checkbox" id="a11yContrast">
          <span class="a11y-slider"></span>
        </label>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">Grayscale</span>
        <label class="a11y-toggle-switch" aria-label="Toggle grayscale">
          <input type="checkbox" id="a11yGrayscale">
          <span class="a11y-slider"></span>
        </label>
      </div>
      <div class="a11y-row">
        <span class="a11y-label">Reduce Motion</span>
        <label class="a11y-toggle-switch" aria-label="Toggle reduce motion">
          <input type="checkbox" id="a11yMotion">
          <span class="a11y-slider"></span>
        </label>
      </div>
    </div>
    <button id="a11yToggleBtn" aria-label="Open accessibility tools" aria-expanded="false" aria-controls="a11yPanel">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <path d="M12 8v4l2 2"/>
        <circle cx="12" cy="7" r="1" fill="currentColor" stroke="none"/>
        <path d="M9 17l1.5-4.5M15 17l-1.5-4.5M9 12.5h6"/>
      </svg>
    </button>
  </div>
  <?php endif; ?>



  <script>

    // ── Password Strength Meter ───────────────────────────────────────────────
    const pwInput = document.getElementById('passwd');
    const pwMeterFill = document.getElementById('pwMeterFill');
    const pwMeterText = document.getElementById('pwMeterText');

    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const val = this.value;
        if (!val) {
          pwMeterFill.style.width = '0%';
          pwMeterText.textContent = '';
          return;
        }
        let score = 0;
        if (val.length >= <?= PASSWD_MIN_LENGTH ?>) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[a-z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;

        const langCode = localStorage.getItem('pk_lang') || 'en';
        const curDict = I18N[langCode] || I18N['en'];
        let width = '25%', color = '#ff4d4d', label = curDict.pw_weak || 'Weak';
        if (score >= 4) {
          width = '100%'; color = '#2ecc71'; label = curDict.pw_strong || 'Strong';
        } else if (score >= 3) {
          width = '66%'; color = '#ffa64d'; label = curDict.pw_medium || 'Medium';
        } else if (score >= 2) {
          width = '33%'; color = '#ff4d4d'; label = curDict.pw_weak || 'Weak';
        }

        pwMeterFill.style.width = width;
        pwMeterFill.style.backgroundColor = color;
        pwMeterText.textContent = label;
        pwMeterText.style.color = color;
      });
    }

    // ── Multi-Language (i18n) Engine ───────────────────────────────────────────
    const I18N = {
  "en": {
    "name": "English",
    "full_name": "Full Name",
    "full_name_ph": "Jane Doe",
    "subtitle": "web control panel",
    "username": "Username",
    "username_ph": "4–16 chars, a-z _ 0-9",
    "email": "Email Address",
    "email_ph": "user@example.com",
    "domain": "Domain",
    "domain_ph": "example.com",
    "password": "Password",
    "password_ph": "Min. 8 chars",
    "confirm": "Confirm",
    "confirm_ph": "Repeat",
    "register": "Register",
    "already_registered": "Already registered?",
    "to_login": "To Login",
    "to_panel": "Go to Panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Weak",
    "pw_medium": "Medium",
    "pw_strong": "Strong",
    "please_wait": "Please wait...",
    "success_heading": "Account Created!",
    "generate": "Generate",
    "maintenance_heading": "Maintenance Mode",
    "maintenance_text": "New registrations are temporarily paused for maintenance. Please check back later.",
    "tos_prefix": "I agree to the",
    "tos_link": "Terms of Service",
    "tos_and": "and",
    "privacy_link": "Privacy Policy",
    "did_you_mean": "Did you mean",
    "setup_2fa": "We recommend enabling Two-Factor Authentication (2FA) in the panel.",
    "copy_pw": "Copy",
    "need_help": "Need Help?",
    "contact_support": "Contact Support",
    "forgot_password": "Forgot Password?",
    "pw_req_length": "At least {n} characters",
    "pw_req_upper": "One uppercase letter (A-Z)",
    "pw_req_lower": "One lowercase letter (a-z)",
    "pw_req_number": "One number (0-9)",
    "email_mx_invalid": "The email domain does not appear to accept mail.",
    "pw_hibp_warning": "⚠️ This password appeared in {n} data breach(es).",
    "pw_hibp_ok": "✓ Password not found in known data breaches.",
    "pw_hibp_checking": "Checking password security...",
    "invite_code": "Invitation Code",
    "invite_code_ph": "Enter your invitation code",
    "invite_required": "An invitation code is required to register.",
    "invite_invalid": "Invalid or already used invitation code.",
    "demo_notice": "⏱ This is a demo account and will be automatically deleted after {n} hour(s)."
  },
  "de": {
    "name": "Deutsch",
    "full_name": "Vollständiger Name",
    "full_name_ph": "Max Mustermann",
    "subtitle": "Web-Control-Panel",
    "username": "Benutzername",
    "username_ph": "4–16 Zeichen, a-z _ 0-9",
    "email": "E-Mail-Adresse",
    "email_ph": "user@example.com",
    "domain": "Domain",
    "domain_ph": "example.com",
    "password": "Passwort",
    "password_ph": "Mind. 8 Zeichen",
    "confirm": "Bestätigen",
    "confirm_ph": "Wiederholen",
    "register": "Registrieren",
    "already_registered": "Bereits registriert?",
    "to_login": "Zum Login",
    "to_panel": "Zum Panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Schwach",
    "pw_medium": "Mittel",
    "pw_strong": "Stark",
    "please_wait": "Bitte warten...",
    "success_heading": "Konto erstellt!",
    "generate": "Erzeugen",
    "maintenance_heading": "Wartungsmodus",
    "maintenance_text": "Neu-Registrierungen sind wegen Wartungsarbeiten vorübergehend pausiert. Bitte versuche es später erneut.",
    "tos_prefix": "Ich akzeptiere die",
    "tos_link": "Nutzungsbedingungen",
    "tos_and": "und die",
    "privacy_link": "Datenschutzerklärung",
    "did_you_mean": "Meintest du",
    "setup_2fa": "Wir empfehlen, die Zwei-Faktor-Authentifizierung (2FA) im Panel zu aktivieren.",
    "copy_pw": "Kopieren",
    "need_help": "Brauchst du Hilfe?",
    "contact_support": "Support kontaktieren",
    "forgot_password": "Passwort vergessen?",
    "pw_req_length": "Mindestens {n} Zeichen",
    "pw_req_upper": "Ein Großbuchstabe (A-Z)",
    "pw_req_lower": "Ein Kleinbuchstabe (a-z)",
    "pw_req_number": "Eine Zahl (0-9)",
    "email_mx_invalid": "Die E-Mail-Domain scheint keine E-Mails zu empfangen.",
    "pw_hibp_warning": "⚠️ Dieses Passwort tauchte in {n} Datenlecks auf.",
    "pw_hibp_ok": "✓ Passwort in bekannten Datenlecks nicht gefunden.",
    "pw_hibp_checking": "Passwortsicherheit wird geprüft...",
    "invite_code": "Einladungscode",
    "invite_code_ph": "Gib deinen Einladungscode ein",
    "invite_required": "Für die Registrierung ist ein Einladungscode erforderlich.",
    "invite_invalid": "Ungültiger oder bereits verwendeter Einladungscode.",
    "demo_notice": "⏱ Dies ist ein Demo-Konto und wird nach {n} Stunde(n) automatisch gelöscht."
  },
  "fr": {
    "name": "Français",
    "full_name": "Nom complet",
    "full_name_ph": "Jean Dupont",
    "subtitle": "panneau de contrôle web",
    "username": "Nom d'utilisateur",
    "username_ph": "4–16 caract., a-z _ 0-9",
    "email": "Adresse e-mail",
    "email_ph": "user@example.com",
    "domain": "Domaine",
    "domain_ph": "example.com",
    "password": "Mot de passe",
    "password_ph": "Min. 8 caract.",
    "confirm": "Confirmer",
    "confirm_ph": "Répéter",
    "register": "S'inscrire",
    "already_registered": "Déjà inscrit ?",
    "to_login": "Connexion",
    "to_panel": "Accéder au panneau",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Faible",
    "pw_medium": "Moyen",
    "pw_strong": "Fort",
    "please_wait": "Veuillez patienter...",
    "success_heading": "Compte créé !",
    "generate": "Générer",
    "maintenance_heading": "Mode maintenance",
    "maintenance_text": "Les nouvelles inscriptions sont temporairement suspendues pour maintenance. Veuillez réessayer plus tard.",
    "tos_prefix": "J'accepte les",
    "tos_link": "Conditions d'utilisation",
    "tos_and": "et la",
    "privacy_link": "Politique de confidentialité",
    "did_you_mean": "Vouliez-vous dire",
    "setup_2fa": "Nous vous recommandons d'activer l'authentification à deux facteurs (2FA) dans le panneau.",
    "copy_pw": "Copier",
    "need_help": "Besoin d'aide ?",
    "contact_support": "Contacter le support",
    "forgot_password": "Mot de passe oublié ?",
    "pw_req_length": "Au moins {n} caractères",
    "pw_req_upper": "Une lettre majuscule (A-Z)",
    "pw_req_lower": "Une lettre minuscule (a-z)",
    "pw_req_number": "Un chiffre (0-9)",
    "email_mx_invalid": "Le domaine e-mail ne semble pas recevoir de courriels.",
    "pw_hibp_warning": "⚠️ Ce mot de passe est apparu dans {n} fuites de données.",
    "pw_hibp_ok": "✓ Mot de passe non trouvé dans les fuites de données connues.",
    "pw_hibp_checking": "Vérification de la sécurité du mot de passe...",
    "invite_code": "Code d'invitation",
    "invite_code_ph": "Entrez votre code d'invitation",
    "invite_required": "Un code d'invitation est requis pour s'inscrire.",
    "invite_invalid": "Code d'invitation invalide ou déjà utilisé.",
    "demo_notice": "⏱ Ce compte de démonstration sera automatiquement supprimé après {n} heure(s)."
  },
  "es": {
    "name": "Español",
    "full_name": "Nombre completo",
    "full_name_ph": "Juan Pérez",
    "subtitle": "panel de control web",
    "username": "Nombre de usuario",
    "username_ph": "4–16 caráct., a-z _ 0-9",
    "email": "Correo electrónico",
    "email_ph": "user@example.com",
    "domain": "Dominio",
    "domain_ph": "example.com",
    "password": "Contraseña",
    "password_ph": "Mín. 8 caráct.",
    "confirm": "Confirmar",
    "confirm_ph": "Repetir",
    "register": "Registrarse",
    "already_registered": "¿Ya estás registrado?",
    "to_login": "Iniciar sesión",
    "to_panel": "Ir al panel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Débil",
    "pw_medium": "Media",
    "pw_strong": "Fuerte",
    "please_wait": "Por favor, espera...",
    "success_heading": "¡Cuenta creada!",
    "generate": "Generar",
    "maintenance_heading": "Modo de mantenimiento",
    "maintenance_text": "Los nuevos registros están pausados temporalmente por mantenimiento. Por favor, inténtalo más tarde.",
    "tos_prefix": "Acepto los",
    "tos_link": "Términos del Servicio",
    "tos_and": "y la",
    "privacy_link": "Política de Privacidad",
    "did_you_mean": "¿Quisiste decir",
    "setup_2fa": "Recomendamos activar la autenticación de dos factores (2FA) en el panel.",
    "copy_pw": "Copiar",
    "need_help": "¿Necesitas ayuda?",
    "contact_support": "Contactar con soporte",
    "forgot_password": "¿Olvidaste la contraseña?",
    "pw_req_length": "Al menos {n} caracteres",
    "pw_req_upper": "Una letra mayúscula (A-Z)",
    "pw_req_lower": "Una letra minúscula (a-z)",
    "pw_req_number": "Un número (0-9)",
    "email_mx_invalid": "El dominio del correo parece no recibir correos.",
    "pw_hibp_warning": "⚠️ Esta contraseña apareció en {n} filtraciones de datos.",
    "pw_hibp_ok": "✓ Contraseña no encontrada en filtraciones de datos conocidas.",
    "pw_hibp_checking": "Comprobando la seguridad de la contraseña...",
    "invite_code": "Código de invitación",
    "invite_code_ph": "Introduce tu código de invitación",
    "invite_required": "Se requiere un código de invitación para registrarse.",
    "invite_invalid": "Código de invitación no válido o ya utilizado.",
    "demo_notice": "⏱ Esta es una cuenta de demostración y se eliminará automáticamente después de {n} hora(s)."
  },
  "it": {
    "name": "Italiano",
    "full_name": "Nome completo",
    "full_name_ph": "Mario Rossi",
    "subtitle": "pannello di controllo web",
    "username": "Nome utente",
    "username_ph": "4–16 caratt., a-z _ 0-9",
    "email": "Indirizzo e-mail",
    "email_ph": "user@example.com",
    "domain": "Dominio",
    "domain_ph": "example.com",
    "password": "Password",
    "password_ph": "Min. 8 caratt.",
    "confirm": "Conferma",
    "confirm_ph": "Ripeti",
    "register": "Registrati",
    "already_registered": "Già registrato?",
    "to_login": "Accedi",
    "to_panel": "Vai al pannello",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Debole",
    "pw_medium": "Media",
    "pw_strong": "Forte",
    "please_wait": "Attendere prego...",
    "success_heading": "Account creato!",
    "generate": "Genera",
    "maintenance_heading": "Modalità manutenzione",
    "maintenance_text": "Le nuove registrazioni sono momentaneamente sospese per manutenzione. Si prega di riprovare più tardi.",
    "tos_prefix": "Accetto i",
    "tos_link": "Termini di servizio",
    "tos_and": "e la",
    "privacy_link": "Informativa sulla privacy",
    "did_you_mean": "Intendevi",
    "setup_2fa": "Consigliamo di abilitare l'autenticazione a due fattori (2FA) nel pannello.",
    "copy_pw": "Copia",
    "need_help": "Serve aiuto?",
    "contact_support": "Contatta il supporto",
    "forgot_password": "Password dimenticata?",
    "pw_req_length": "Almeno {n} caratteri",
    "pw_req_upper": "Una lettera maiuscola (A-Z)",
    "pw_req_lower": "Una lettera minuscola (a-z)",
    "pw_req_number": "Un numero (0-9)",
    "email_mx_invalid": "Il dominio e-mail sembra non accettare messaggi.",
    "pw_hibp_warning": "⚠️ Questa password è apparsa in {n} violazioni di dati.",
    "pw_hibp_ok": "✓ Password non trovata in violazioni di dati note.",
    "pw_hibp_checking": "Controllo della sicurezza della password...",
    "invite_code": "Codice di invito",
    "invite_code_ph": "Inserisci il tuo codice di invito",
    "invite_required": "È richiesto un codice di invito per registrarsi.",
    "invite_invalid": "Codice di invito non valido o già utilizzato.",
    "demo_notice": "⏱ Questo è un account demo e verrà eliminato automaticamente dopo {n} ora/e."
  },
  "nl": {
    "name": "Nederlands",
    "full_name": "Volledige naam",
    "full_name_ph": "Jan Jansen",
    "subtitle": "webbeheerpaneel",
    "username": "Gebruikersnaam",
    "username_ph": "4–16 tekens, a-z _ 0-9",
    "email": "E-mailadres",
    "email_ph": "user@example.com",
    "domain": "Domein",
    "domain_ph": "example.com",
    "password": "Wachtwoord",
    "password_ph": "Min. 8 tekens",
    "confirm": "Bevestigen",
    "confirm_ph": "Herhalen",
    "register": "Registreren",
    "already_registered": "Al geregistreerd?",
    "to_login": "Inloggen",
    "to_panel": "Ga naar paneel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Zwak",
    "pw_medium": "Gemiddeld",
    "pw_strong": "Sterk",
    "please_wait": "Even geduld...",
    "success_heading": "Account aangemaakt!",
    "generate": "Genereren",
    "maintenance_heading": "Onderhoudsmodus",
    "maintenance_text": "Nieuwe registraties zijn tijdelijk onderbroken voor onderhoud. Probeer het later opnieuw.",
    "tos_prefix": "Ik ga akkoord met de",
    "tos_link": "Algemene Voorwaarden",
    "tos_and": "en het",
    "privacy_link": "Privacybeleid",
    "did_you_mean": "Bedoelde je",
    "setup_2fa": "We raden aan om Twee-Factor Authenticatie (2FA) in te schakelen in het paneel.",
    "copy_pw": "Kopiëren",
    "need_help": "Hulp nodig?",
    "contact_support": "Support contacteren",
    "forgot_password": "Wachtwoord vergeten?",
    "pw_req_length": "Ten minste {n} tekens",
    "pw_req_upper": "Één hoofdletter (A-Z)",
    "pw_req_lower": "Één kleine letter (a-z)",
    "pw_req_number": "Één cijfer (0-9)",
    "email_mx_invalid": "Het e-maildomein lijkt geen e-mail te accepteren.",
    "pw_hibp_warning": "⚠️ Dit wachtwoord is gevonden in {n} datalekken.",
    "pw_hibp_ok": "✓ Wachtwoord niet gevonden in bekende datalekken.",
    "pw_hibp_checking": "Wachtwoordbeveiliging controleren...",
    "invite_code": "Uitnodigingscode",
    "invite_code_ph": "Voer je uitnodigingscode in",
    "invite_required": "Een uitnodigingscode is vereist om te registreren.",
    "invite_invalid": "Ongeldige of reeds gebruikte uitnodigingscode.",
    "demo_notice": "⏱ Dit is een demo-account en wordt automatisch verwijderd na {n} uur."
  },
  "pl": {
    "name": "Polski",
    "full_name": "Pełne imię i nazwisko",
    "full_name_ph": "Jan Kowalski",
    "subtitle": "panel sterowania web",
    "username": "Nazwa użytkownika",
    "username_ph": "4–16 znaków, a-z _ 0-9",
    "email": "Adres e-mail",
    "email_ph": "user@example.com",
    "domain": "Domena",
    "domain_ph": "example.com",
    "password": "Hasło",
    "password_ph": "Min. 8 znaków",
    "confirm": "Potwierdź",
    "confirm_ph": "Powtórz",
    "register": "Zarejestruj się",
    "already_registered": "Masz już konto?",
    "to_login": "Zaloguj się",
    "to_panel": "Przejdź do panelu",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Słabe",
    "pw_medium": "Średnie",
    "pw_strong": "Mocne",
    "please_wait": "Proszę czekać...",
    "success_heading": "Konto utworzone!",
    "generate": "Generuj",
    "maintenance_heading": "Tryb konserwacji",
    "maintenance_text": "Nowe rejestracje są tymczasowo wstrzymane z powodu prac konserwacyjnych. Spróbuj ponownie później.",
    "tos_prefix": "Akceptuję",
    "tos_link": "Warunki korzystania",
    "tos_and": "oraz",
    "privacy_link": "Politykę prywatności",
    "did_you_mean": "Czy chodziło Ci o",
    "setup_2fa": "Zalecamy włączenie uwierzytelniania dwuskładnikowego (2FA) w panelu.",
    "copy_pw": "Kopiuj",
    "need_help": "Potrzebujesz pomocy?",
    "contact_support": "Skontaktuj się z pomocą",
    "forgot_password": "Nie pamiętasz hasła?",
    "pw_req_length": "Co najmniej {n} znaków",
    "pw_req_upper": "Jedna wielka litera (A-Z)",
    "pw_req_lower": "Jedna mała litera (a-z)",
    "pw_req_number": "Jedna cyfra (0-9)",
    "email_mx_invalid": "Domena e-mail wydaje się nie przyjmować poczty.",
    "pw_hibp_warning": "⚠️ To hasło pojawiło się w {n} wyciekach danych.",
    "pw_hibp_ok": "✓ Hasła nie znaleziono w znanych wyciekach danych.",
    "pw_hibp_checking": "Sprawdzanie bezpieczeństwa hasła...",
    "invite_code": "Kod zaproszenia",
    "invite_code_ph": "Wprowadź kod zaproszenia",
    "invite_required": "Kod zaproszenia jest wymagany do rejestracji.",
    "invite_invalid": "Nieprawidłowy lub już użyty kod zaproszenia.",
    "demo_notice": "⏱ To jest konto demonstracyjne i zostanie automatycznie usunięte po {n} godzinie."
  },
  "pt": {
    "name": "Português",
    "full_name": "Nome completo",
    "full_name_ph": "João Silva",
    "subtitle": "painel de controlo web",
    "username": "Nome de utilizador",
    "username_ph": "4–16 caracteres, a-z _ 0-9",
    "email": "Endereço de e-mail",
    "email_ph": "utilizador@exemplo.pt",
    "domain": "Domínio",
    "domain_ph": "exemplo.pt",
    "password": "Palavra-passe",
    "password_ph": "Mín. 8 caracteres",
    "confirm": "Confirmar",
    "confirm_ph": "Repetir",
    "register": "Registar",
    "already_registered": "Já registado?",
    "to_login": "Entrar",
    "to_panel": "Ir para o painel",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Fraca",
    "pw_medium": "Média",
    "pw_strong": "Forte",
    "please_wait": "Por favor, aguarde...",
    "success_heading": "Conta criada!",
    "generate": "Gerar",
    "maintenance_heading": "Modo de manutenção",
    "maintenance_text": "Novos registos estão temporariamente suspensos para manutenção. Por favor, tente mais tarde.",
    "tos_prefix": "Aceito os",
    "tos_link": "Termos de Serviço",
    "tos_and": "e a",
    "privacy_link": "Política de Privacidade",
    "did_you_mean": "Queria dizer",
    "setup_2fa": "Recomendamos a ativação da autenticação de dois fatores (2FA) no painel.",
    "copy_pw": "Copiar",
    "need_help": "Precisa de ajuda?",
    "contact_support": "Contactar o Suporte",
    "forgot_password": "Esqueceu-se da palavra-passe?",
    "pw_req_length": "Pelo menos {n} caracteres",
    "pw_req_upper": "Uma letra maiúscula (A-Z)",
    "pw_req_lower": "Uma letra minúscula (a-z)",
    "pw_req_number": "Um número (0-9)",
    "email_mx_invalid": "O domínio do e-mail parece não aceitar mensagens.",
    "pw_hibp_warning": "⚠️ Esta palavra-passe foi encontrada em {n} fugas de dados.",
    "pw_hibp_ok": "✓ Palavra-passe não encontrada em fugas de dados conhecidas.",
    "pw_hibp_checking": "A verificar a segurança da palavra-passe...",
    "invite_code": "Código de convite",
    "invite_code_ph": "Introduza o seu código de convite",
    "invite_required": "É necessário um código de convite para se registar.",
    "invite_invalid": "Código de convite inválido ou já utilizado.",
    "demo_notice": "⏱ Esta é uma conta de demonstração e será excluída automaticamente após {n} hora(s)."
  },
  "ru": {
    "name": "Русский",
    "full_name": "Полное имя",
    "full_name_ph": "Иван Иванов",
    "subtitle": "панель управления web",
    "username": "Имя пользователя",
    "username_ph": "4–16 симв., a-z _ 0-9",
    "email": "Адрес электронной почты",
    "email_ph": "user@example.com",
    "domain": "Домен",
    "domain_ph": "example.com",
    "password": "Пароль",
    "password_ph": "Мин. 8 симв.",
    "confirm": "Подтверждение",
    "confirm_ph": "Повторите",
    "register": "Зарегистрироваться",
    "already_registered": "Уже зарегистрированы?",
    "to_login": "Войти",
    "to_panel": "Перейти в панель",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Слабый",
    "pw_medium": "Средний",
    "pw_strong": "Надежный",
    "please_wait": "Пожалуйста, подождите...",
    "success_heading": "Аккаунт создан!",
    "generate": "Сгенерировать",
    "maintenance_heading": "Режим обслуживания",
    "maintenance_text": "Новые регистрации временно приостановлены из-за технических работ. Пожалуйста, попробуйте позже.",
    "tos_prefix": "Я принимаю",
    "tos_link": "Условия обслуживания",
    "tos_and": "и",
    "privacy_link": "Политику конфиденциальности",
    "did_you_mean": "Возможно, вы имели в виду",
    "setup_2fa": "Мы рекомендуем включить двухфакторную аутентификацию (2FA) в панели.",
    "copy_pw": "Копировать",
    "need_help": "Нужна помощь?",
    "contact_support": "Связаться с поддержкой",
    "forgot_password": "Забыли пароль?",
    "pw_req_length": "Мин. {n} символов",
    "pw_req_upper": "Одна заглавная буква (A-Z)",
    "pw_req_lower": "Одна строчная буква (a-z)",
    "pw_req_number": "Одна цифра (0-9)",
    "email_mx_invalid": "Почтовый домен, похоже, не принимает почту.",
    "pw_hibp_warning": "⚠️ Этот пароль обнаружен в {n} утечках данных.",
    "pw_hibp_ok": "✓ Пароль не найден в известных утечках данных.",
    "pw_hibp_checking": "Проверка безопасности пароля...",
    "invite_code": "Код приглашения",
    "invite_code_ph": "Введите код приглашения",
    "invite_required": "Для регистрации требуется код приглашения.",
    "invite_invalid": "Недействительный или уже использованный код приглашения.",
    "demo_notice": "⏱ Это демо-аккаунт и будет автоматически удалён через {n} ч."
  },
  "uk": {
    "name": "Українська",
    "full_name": "Повне ім'я",
    "full_name_ph": "Іван Іванов",
    "subtitle": "панель керування web",
    "username": "Ім'я користувача",
    "username_ph": "4–16 симв., a-z _ 0-9",
    "email": "Електронна пошта",
    "email_ph": "user@example.com",
    "domain": "Домен",
    "domain_ph": "example.com",
    "password": "Пароль",
    "password_ph": "Мін. 8 симв.",
    "confirm": "Підтвердження",
    "confirm_ph": "Повторіть",
    "register": "Зареєструватися",
    "already_registered": "Вже маєте акаунт?",
    "to_login": "Увійти",
    "to_panel": "До панелі",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Слабкий",
    "pw_medium": "Середній",
    "pw_strong": "Надійний",
    "please_wait": "Будь ласка, зачекайте...",
    "success_heading": "Акаунт створено!",
    "generate": "Згенерувати",
    "maintenance_heading": "Режим обслуговування",
    "maintenance_text": "Нові реєстрації тимчасово призупинено через технічні роботи. Будь ласка, спробуйте пізніше.",
    "tos_prefix": "Я погоджуюся з",
    "tos_link": "Умовами обслуговування",
    "tos_and": "та",
    "privacy_link": "Політикою конфіденційності",
    "did_you_mean": "Можливо, ви мали на увазі",
    "setup_2fa": "Ми рекомендуємо ввімкнути двофакторну автентифікацію (2FA) у панелі.",
    "copy_pw": "Копіювати",
    "need_help": "Потрібна допомога?",
    "contact_support": "Зв'язатися з підтримкою",
    "forgot_password": "Забули пароль?",
    "pw_req_length": "Мін. {n} символів",
    "pw_req_upper": "Одна велика літера (A-Z)",
    "pw_req_lower": "Одна мала літера (a-z)",
    "pw_req_number": "Одна цифра (0-9)",
    "email_mx_invalid": "Схоже, поштовий домен не приймає пошту.",
    "pw_hibp_warning": "⚠️ Цей пароль знайдено у {n} витоках даних.",
    "pw_hibp_ok": "✓ Пароль не знайдено у відомих витоках даних.",
    "pw_hibp_checking": "Перевірка безпеки пароля...",
    "invite_code": "Код запрошення",
    "invite_code_ph": "Введіть код запрошення",
    "invite_required": "Для реєстрації потрібен код запрошення.",
    "invite_invalid": "Недійсний або вже використаний код запрошення.",
    "demo_notice": "⏱ Це демо-акаунт і буде автоматично видалено через {n} год."
  },
  "uz": {
    "name": "Oʻzbekcha",
    "full_name": "To'liq ism",
    "full_name_ph": "Azamat",
    "subtitle": "veb boshqaruv paneli",
    "username": "Foydalanuvchi nomi",
    "username_ph": "4–16 belgi, a-z _ 0-9",
    "email": "E-pochta manzili",
    "email_ph": "foydalanuvchi@namuna.uz",
    "domain": "Domen",
    "domain_ph": "namuna.uz",
    "password": "Parol",
    "password_ph": "Kamida 8 belgi",
    "confirm": "Tasdiqlash",
    "confirm_ph": "Takrorlang",
    "register": "Roʻyxatdan oʻtish",
    "already_registered": "Roʻyxatdan oʻtganmisiz?",
    "to_login": "Kirish",
    "to_panel": "Panelga oʻtish",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "Zarif",
    "pw_medium": "Oʻrtacha",
    "pw_strong": "Kuchli",
    "please_wait": "Kuting...",
    "success_heading": "Hisob yaratildi!",
    "generate": "Yaratish",
    "maintenance_heading": "Profilaktika rejimi",
    "maintenance_text": "Yangi roʻyxatdan oʻtishlar profilaktika ishlari sababli vaqtincha toʻxtatilgan. Keyinroq qayta urinib koʻring.",
    "tos_prefix": "Men",
    "tos_link": "Xizmat koʻrsatish shartlari",
    "tos_and": "va",
    "privacy_link": "Maxfiylik siyosatiga roziman",
    "did_you_mean": "Buni nazarda tutdingizmi:",
    "setup_2fa": "Panelda Ikki faktorli autentifikatsiyani (2FA) yoqishingizni tavsiya qilamiz.",
    "copy_pw": "Nusxalash",
    "need_help": "Yordam kerakmi?",
    "contact_support": "Qo'llab-quvvatlash bilan bog'lanish",
    "forgot_password": "Parolni unutdingizmi?",
    "pw_req_length": "Kamida {n} ta belgi",
    "pw_req_upper": "Bitta bosh harf (A-Z)",
    "pw_req_lower": "Bitta kichik harf (a-z)",
    "pw_req_number": "Bitta raqam (0-9)",
    "email_mx_invalid": "Elektron pochta domeni xatlarni qabul qilmayotganga o‘xshaydi.",
    "pw_hibp_warning": "⚠️ Ushbu parol {n} ta ma'lumotlar sizib chiqishida paydo bo'lgan.",
    "pw_hibp_ok": "✓ Parol ma'lum bo'lgan ma'lumotlar sizib chiqishida topilmadi.",
    "pw_hibp_checking": "Parol xavfsizligi tekshirilmoqda...",
    "invite_code": "Taklif kodi",
    "invite_code_ph": "Taklif kodini kiriting",
    "invite_required": "Ro'yxatdan o'tish uchun taklif kodi kerak.",
    "invite_invalid": "Yaroqsiz yoki oldin ishlatilgan taklif kodi.",
    "demo_notice": "⏱ Bu demo hisob va {n} soatdan keyin avtomatik o'chiriladi."
  },
  "ja": {
    "name": "日本語",
    "full_name": "氏名",
    "full_name_ph": "山田 太郎",
    "subtitle": "Web コントロールパネル",
    "username": "ユーザー名",
    "username_ph": "4–16文字、a-z _ 0-9",
    "email": "メールアドレス",
    "email_ph": "user@example.jp",
    "domain": "ドメイン",
    "domain_ph": "example.jp",
    "password": "パスワード",
    "password_ph": "最小 8 文字",
    "confirm": "パスワード確認",
    "confirm_ph": "もう一度入力",
    "register": "登録する",
    "already_registered": "既に登録されていますか？",
    "to_login": "ログイン",
    "to_panel": "パネルへ",
    "pw_hint": "A-Z, a-z, 0-9",
    "pw_weak": "弱い",
    "pw_medium": "普通",
    "pw_strong": "強い",
    "please_wait": "少々お待ちください...",
    "success_heading": "アカウントが作成されました！",
    "generate": "自動生成",
    "maintenance_heading": "メンテナンスモード",
    "maintenance_text": "現在、メンテナンスのため新規登録を一時的に停止しています。後ほどもう一度お試しください。",
    "tos_prefix": "私は",
    "tos_link": "利用規約",
    "tos_and": "および",
    "privacy_link": "プライバシーポリシーに同意します",
    "did_you_mean": "もしかして",
    "setup_2fa": "パネル内で2要素認証 (2FA) を有効にすることをお勧めします。",
    "copy_pw": "コピー",
    "need_help": "ヘルプが必要ですか？",
    "contact_support": "サポートに連絡",
    "forgot_password": "パスワードをお忘れですか？",
    "pw_req_length": "最小 {n} 文字以上",
    "pw_req_upper": "大文字1文字以上 (A-Z)",
    "pw_req_lower": "小文字1文字以上 (a-z)",
    "pw_req_number": "数字1文字以上 (0-9)",
    "email_mx_invalid": "メールのドメインがメールを受信できない状態のようです。",
    "pw_hibp_warning": "⚠️ このパスワードは過去に {n} 件のデータ漏洩で確認されています。",
    "pw_hibp_ok": "✓ このパスワードは既知のデータ漏洩では見つかりませんでした。",
    "pw_hibp_checking": "パスワードの安全性を確認中...",
    "invite_code": "招待コード",
    "invite_code_ph": "招待コードを入力してください",
    "invite_required": "登録には招待コードが必要です。",
    "invite_invalid": "招待コードが無効か、または既に使用されています。",
    "demo_notice": "⏱ これはデモアカウントです。{n}時間後に自動的に削除されます。"
  }
};

    const langDropdown = document.getElementById('langDropdown');
    const langBtn = document.getElementById('langBtn');

    // ── Password Generator ─────────────────────────────────────────────────────
    const generatePwBtn = document.getElementById('generatePwBtn');
    if (generatePwBtn) generatePwBtn.addEventListener('click', generatePassword);

    function generatePassword() {
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
      // Use cryptographically secure random numbers (CSPRNG)
      const randByte = () => crypto.getRandomValues(new Uint8Array(1))[0];
      const randChar = (str) => {
        // Rejection sampling to avoid modulo bias
        const max = 256 - (256 % str.length);
        let r;
        do { r = randByte(); } while (r >= max);
        return str[r % str.length];
      };

      // Guarantee at least one character from each required class
      let pwd = [
        randChar('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
        randChar('abcdefghijklmnopqrstuvwxyz'),
        randChar('0123456789'),
      ];
      for (let i = 0; i < 9; i++) pwd.push(randChar(chars));

      // Fisher-Yates shuffle using crypto.getRandomValues()
      for (let i = pwd.length - 1; i > 0; i--) {
        const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
        [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
      }
      const result = pwd.join('');

      const p1 = document.getElementById('passwd');
      const p2 = document.getElementById('passwd2');
      p1.value = result;
      p2.value = result;

      // Briefly show password so user can see what was generated
      p1.type = 'text'; p2.type = 'text';
      // Update eye button icons
      document.querySelectorAll('.eye-btn').forEach(btn => {
        btn.querySelector('.show-icon').style.display = 'none';
        btn.querySelector('.hide-icon').style.display = 'block';
      });
      p1.dispatchEvent(new Event('input'));

      // Show copy button
      const copyBtn = document.getElementById('copyPwBtn');
      if (copyBtn) copyBtn.style.display = 'flex';

      setTimeout(() => {
        p1.type = 'password'; p2.type = 'password';
        document.querySelectorAll('.eye-btn').forEach(btn => {
          btn.querySelector('.show-icon').style.display = 'block';
          btn.querySelector('.hide-icon').style.display = 'none';
        });
      }, 4000);
    }

    // ── Eye Toggle (Password Visibility) ──────────────────────────────────────
    document.querySelectorAll('.eye-btn').forEach(btn => {
      btn.addEventListener('click', function () {
        const targetId = this.dataset.target;
        const input = document.getElementById(targetId);
        if (!input) return;
        const isHidden = input.type === 'password';
        input.type = isHidden ? 'text' : 'password';
        this.querySelector('.show-icon').style.display = isHidden ? 'none' : 'block';
        this.querySelector('.hide-icon').style.display = isHidden ? 'block' : 'none';
      });
    });

    // ── Copy Password Button ───────────────────────────────────────────────────
    const copyPwBtn = document.getElementById('copyPwBtn');
    if (copyPwBtn) {
      copyPwBtn.addEventListener('click', function () {
        const pwEl = document.getElementById('passwd');
        const pw = pwEl ? pwEl.value : '';
        if (!pw) return;
        navigator.clipboard.writeText(pw).then(() => {
          this.classList.add('copied');
          const label = this.querySelector('#copyPwLabel');
          const origText = label.textContent;
          label.textContent = '✓';
          setTimeout(() => {
            this.classList.remove('copied');
            label.textContent = origText;
          }, 2000);
        });
      });
    }

    // Show copy button when user types password manually
    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const copyBtn = document.getElementById('copyPwBtn');
        if (copyBtn) copyBtn.style.display = this.value ? 'flex' : 'none';
      });
    }

    let currentLang = 'en';
    function setLanguage(langCode) {
      currentLang = langCode;
      const dict = I18N[langCode] || I18N['en'];
      localStorage.setItem('pk_lang', langCode);
      const label = document.getElementById('currentLangLabel');
      if (label) label.textContent = langCode.toUpperCase();

      document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (dict[key]) {
          let text = dict[key];
          if (key === 'demo_notice' && el.dataset.i18nDemoHours) {
            text = text.replace('{n}', el.dataset.i18nDemoHours);
          }
          el.textContent = text;
        }
      });

      document.querySelectorAll('[data-i18n-ph]').forEach(el => {
        const key = el.dataset.i18nPh;
        if (dict[key]) el.placeholder = dict[key];
      });

      document.querySelectorAll('[data-i18n-min]').forEach(el => {
        const key = el.dataset.i18nMin;
        const checklist = document.getElementById('pwChecklist');
        const minLen = checklist ? checklist.dataset.min : 8;
        if (dict[key]) el.textContent = dict[key].replace('{n}', minLen);
      });

      document.querySelectorAll('.lang-item').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === langCode);
      });
    }

    if (langDropdown && langBtn) {
      Object.keys(I18N).forEach(code => {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'lang-item';
        item.dataset.lang = code;
        item.textContent = I18N[code].name;
        item.addEventListener('click', () => {
          setLanguage(code);
          langDropdown.classList.remove('show');
        });
        langDropdown.appendChild(item);
      });

      langBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        langDropdown.classList.toggle('show');
      });

      document.addEventListener('click', (e) => {
        const langWrap = document.getElementById('langWrap');
        if (langWrap && !langWrap.contains(e.target)) {
          langDropdown.classList.remove('show');
        }
      });

      // Init language from localStorage or browser settings
      const savedLang = localStorage.getItem('pk_lang') || navigator.language.slice(0, 2);
      setLanguage(I18N[savedLang] ? savedLang : 'en');
    }

    // ── Client-Side Validation & Submit Spinner ───────────────────────────────
    const regForm = document.getElementById('regForm');
    if (regForm) {
      regForm.addEventListener('submit', function (e) {
        const username = document.getElementById('username').value.trim();
        const email = document.getElementById('email').value.trim();
        const domain = document.getElementById('domain').value.trim();
        const pw = document.getElementById('passwd').value;
        const pw2 = document.getElementById('passwd2').value;

        if (!/^[a-z][a-z0-9\-\_]{3,15}$/i.test(username)) {
          e.preventDefault();
          alert('Username must be 4–16 characters, start with a letter, and contain only lowercase letters, digits, hyphens (-) or underscores (_).');
          return;
        }
        const fullnameEl = document.getElementById('fullname');
        if (fullnameEl && fullnameEl.value.trim().length < 2) {
          e.preventDefault();
          alert('Please enter your full name (at least 2 characters).');
          return;
        }
        if (!email.includes('@')) {
          e.preventDefault();
          alert('Please enter a valid email address.');
          return;
        }
        if (!domain.match(/^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$/i)) {
          e.preventDefault();
          alert('Please enter a valid domain (e.g. example.com).');
          return;
        }
        if (pw.length < <?= PASSWD_MIN_LENGTH ?>) {
          e.preventDefault();
          alert('Password must be at least <?= PASSWD_MIN_LENGTH ?> characters long.');
          return;
        }
        <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          if (!/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/[0-9]/.test(pw)) {
            e.preventDefault();
            alert('Password must contain at least one uppercase letter, one lowercase letter, and one number.');
            return;
          }
        <?php endif; ?>
        if (pw !== pw2) {
          e.preventDefault();
          alert('Passwords do not match.');
          return;
        }

        const btn = document.getElementById('submitBtn');
        const spinner = document.getElementById('spinner');
        const label = document.getElementById('submitLabel');
        if (spinner) spinner.style.display = 'block';
        const curLang = localStorage.getItem('pk_lang') || 'en';
        if (label) label.textContent = (I18N[curLang] || I18N['en']).please_wait || 'Please wait...';
        setTimeout(() => { if (btn) btn.disabled = true; }, 10);
      });
    }

    // ── Hide Preloader after page load ────────────────────────────────────────
    window.addEventListener('load', () => {
      const preloader = document.getElementById('preloader');
      if (preloader) {
        preloader.classList.add('hidden');
        // Remove from DOM after transition to free resources
        preloader.addEventListener('transitionend', () => preloader.remove(), { once: true });
      }
    });

    // ── Email Typo Detection ──────────────────────────────────────────────────
    const emailInput = document.getElementById('email');
    const emailSuggestion = document.getElementById('emailSuggestion');
    const emailSuggestionLink = document.getElementById('emailSuggestionLink');

    if (emailInput && emailSuggestion && emailSuggestionLink) {
      const commonDomains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com',
        'gmx.de', 'gmx.net', 'gmx.at', 'gmx.ch', 'web.de', 't-online.de', 'freenet.de', 'posteo.de', 'mailbox.org',
        'yandex.ru', 'mail.ru', 'inbox.ru', 'bk.ru', 'list.ru', 'rambler.ru',
        'proton.me', 'protonmail.com', 'tuta.com', 'tutamail.com',
        'live.com', 'msn.com', 'zoho.com'
      ];

      function calculateDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;
        const matrix = [];
        for (let i = 0; i <= b.length; i++) matrix[i] = [i];
        for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
        for (let i = 1; i <= b.length; i++) {
          for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
              matrix[i][j] = matrix[i - 1][j - 1];
            } else {
              matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1));
            }
          }
        }
        return matrix[b.length][a.length];
      }

      emailInput.addEventListener('blur', function () {
        const val = this.value.trim().toLowerCase();
        const parts = val.split('@');
        if (parts.length === 2 && parts[1].length > 0) {
          const user = parts[0];
          const domain = parts[1];
          let bestMatch = null;
          let minDistance = 3;

          if (commonDomains.includes(domain)) {
            emailSuggestion.style.display = 'none';
            return;
          }

          for (const cd of commonDomains) {
            const d = calculateDistance(domain, cd);
            if (d < minDistance) {
              minDistance = d;
              bestMatch = cd;
            }
          }

          if (bestMatch && bestMatch !== domain) {
            const suggestedEmail = user + '@' + bestMatch;
            emailSuggestionLink.textContent = suggestedEmail;
            emailSuggestion.style.display = 'block';

            emailSuggestionLink.onclick = function (e) {
              e.preventDefault();
              emailInput.value = suggestedEmail;
              emailSuggestion.style.display = 'none';
              emailInput.focus();
            };
          } else {
            emailSuggestion.style.display = 'none';
          }
        } else {
          emailSuggestion.style.display = 'none';
        }
      });
    }



    // ── Password Checklist ──────────────────────────────────────────────────
    (function() {
      const checklist = document.getElementById('pwChecklist');
      if (!checklist) return;

      const minLen     = parseInt(checklist.dataset.min, 10) || 8;
      const complexity = checklist.dataset.complexity === '1';
      const pwInput    = document.getElementById('passwd');
      if (!pwInput) return;

      const chkLength = document.getElementById('chk-length');
      const chkUpper  = document.getElementById('chk-upper');
      const chkLower  = document.getElementById('chk-lower');
      const chkNumber = document.getElementById('chk-number');

      function setCheck(el, ok) {
        if (!el) return;
        el.classList.toggle('ok', ok);
        el.querySelector('.check-icon').textContent = ok ? '✓' : '';
      }

      function updateChecklist() {
        const val = pwInput.value;
        setCheck(chkLength, val.length >= minLen);
        if (complexity) {
          setCheck(chkUpper,  /[A-Z]/.test(val));
          setCheck(chkLower,  /[a-z]/.test(val));
          setCheck(chkNumber, /[0-9]/.test(val));
        }
        // Update i18n placeholder for min-length text
        if (chkLength) {
          const span = chkLength.querySelector('[data-i18n-min]');
          if (span) {
            const key = span.dataset.i18nMin;
            const lang = I18N[currentLang] || I18N['en'] || {};
            const tpl  = lang[key] || `At least ${minLen} characters`;
            span.textContent = tpl.replace('{n}', minLen);
          }
        }
      }

      pwInput.addEventListener('input', updateChecklist);
      updateChecklist();
    })();

    // ── HaveIBeenPwned Check ────────────────────────────────────────────────
    <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
    (function() {
      const pwInput    = document.getElementById('passwd');
      const hibpStatus = document.getElementById('hibpStatus');
      const form       = document.getElementById('regForm');
      if (!pwInput || !hibpStatus) return;

      const blockOnBreach = <?= defined('HIBP_BLOCK_ON_BREACH') && HIBP_BLOCK_ON_BREACH ? 'true' : 'false' ?>;
      let hibpTimer = null;
      let lastBreach = false;

      // Compute SHA-1 using Web Crypto API (no external lib needed)
      async function sha1(str) {
        const buf  = new TextEncoder().encode(str);
        const hash = await crypto.subtle.digest('SHA-1', buf);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      }

      async function checkHibp(password) {
        if (password.length < 4) {
          hibpStatus.className = 'hibp-status';
          lastBreach = false;
          return;
        }

        const lang = I18N[currentLang] || I18N['en'] || {};
        hibpStatus.className = 'hibp-status checking';
        hibpStatus.textContent = lang.pw_hibp_checking || 'Checking password security...';

        try {
          const hash   = await sha1(password);
          const prefix = hash.substring(0, 5);
          const suffix = hash.substring(5);

          const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            headers: { 'Add-Padding': 'true' }
          });
          if (!resp.ok) throw new Error('HIBP API error');

          const text = await resp.text();
          let count  = 0;
          for (const line of text.split('\n')) {
            const [s, c] = line.trim().split(':');
            if (s && s.toUpperCase() === suffix) {
              count = parseInt(c, 10) || 1;
              break;
            }
          }

          if (count > 0) {
            lastBreach = true;
            hibpStatus.className = 'hibp-status warning';
            const tpl = lang.pw_hibp_warning || '⚠️ This password appeared in {n} data breach(es).';
            hibpStatus.textContent = tpl.replace('{n}', count.toLocaleString());
          } else {
            lastBreach = false;
            hibpStatus.className = 'hibp-status ok';
            hibpStatus.textContent = lang.pw_hibp_ok || '✓ Password not found in known data breaches.';
          }
        } catch (e) {
          // Fail-silent: do not block on API unavailability
          hibpStatus.className = 'hibp-status';
          lastBreach = false;
        }
      }

      pwInput.addEventListener('input', function() {
        clearTimeout(hibpTimer);
        hibpTimer = setTimeout(() => checkHibp(pwInput.value), 800);
      });

      // Block form submission if breach found and HIBP_BLOCK_ON_BREACH is enabled
      if (blockOnBreach && form) {
        form.addEventListener('submit', function(e) {
          if (lastBreach) {
            e.preventDefault();
            const lang = I18N[currentLang] || I18N['en'] || {};
            hibpStatus.className = 'hibp-status warning';
            hibpStatus.textContent = lang.pw_hibp_warning
              ? lang.pw_hibp_warning.replace('{n}', '?')
              : '⚠️ Please choose a different password.';
            pwInput.focus();
          }
        }, true);
      }
    })();
    <?php endif; ?>

  </script>

  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
  <script>
    // ── Cookie Consent Banner ──────────────────────────────────────────────────
    (function () {
      const banner = document.getElementById('cookieBanner');
      if (!banner) return;
      const COOKIE_KEY = 'pk_cookie_consent';

      if (localStorage.getItem(COOKIE_KEY) !== '1') {
        // Slide in after a short delay so the page settles first
        setTimeout(() => banner.classList.add('visible'), 400);
      }

      document.getElementById('cookieAcceptBtn').addEventListener('click', function () {
        localStorage.setItem(COOKIE_KEY, '1');
        banner.classList.remove('visible');
        banner.addEventListener('transitionend', () => banner.remove(), { once: true });
      });
    })();
  </script>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
  <script>
    // ── Accessibility Widget ───────────────────────────────────────────────────
    (function () {
      const toggleBtn  = document.getElementById('a11yToggleBtn');
      const panel      = document.getElementById('a11yPanel');
      const fontDecBtn = document.getElementById('a11yFontDec');
      const fontIncBtn = document.getElementById('a11yFontInc');
      const fontLabel  = document.getElementById('a11yFontSize');
      const contrastCb = document.getElementById('a11yContrast');
      const grayscaleCb = document.getElementById('a11yGrayscale');
      const motionCb   = document.getElementById('a11yMotion');

      const STORE = 'pk_a11y';
      let state = { font: 100, contrast: false, grayscale: false, motion: false };

      try {
        const saved = JSON.parse(localStorage.getItem(STORE) || 'null');
        if (saved) state = { ...state, ...saved };
      } catch (e) {}

      function save() {
        try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) {}
      }

      function applyAll() {
        document.documentElement.style.fontSize = state.font + '%';
        fontLabel.textContent = state.font + '%';
        document.documentElement.classList.toggle('a11y-contrast', state.contrast);
        document.documentElement.classList.toggle('a11y-grayscale', state.grayscale);
        document.documentElement.classList.toggle('a11y-motion', state.motion);
        contrastCb.checked  = state.contrast;
        grayscaleCb.checked = state.grayscale;
        motionCb.checked    = state.motion;
      }

      // Inject global a11y CSS rules once
      if (!document.getElementById('a11y-rules')) {
        const style = document.createElement('style');
        style.id = 'a11y-rules';
        style.textContent = [
          '.a11y-contrast { filter: contrast(1.6) brightness(1.05); }',
          '.a11y-grayscale { filter: grayscale(1); }',
          '.a11y-contrast.a11y-grayscale { filter: contrast(1.6) brightness(1.05) grayscale(1); }',
          '.a11y-motion *, .a11y-motion *::before, .a11y-motion *::after { animation-duration: 0.001ms !important; transition-duration: 0.001ms !important; }'
        ].join('\n');
        document.head.appendChild(style);
      }

      applyAll();

      // Toggle panel
      toggleBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        const open = panel.classList.toggle('open');
        toggleBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });

      // Close on outside click
      document.addEventListener('click', function (e) {
        const widget = document.getElementById('a11yWidget');
        if (widget && !widget.contains(e.target)) {
          panel.classList.remove('open');
          toggleBtn.setAttribute('aria-expanded', 'false');
        }
      });

      // Font size
      fontDecBtn.addEventListener('click', function () {
        state.font = Math.max(80, state.font - 10);
        applyAll(); save();
      });
      fontIncBtn.addEventListener('click', function () {
        state.font = Math.min(150, state.font + 10);
        applyAll(); save();
      });

      // Toggles
      contrastCb.addEventListener('change', function () {
        state.contrast = this.checked;
        applyAll(); save();
      });
      grayscaleCb.addEventListener('change', function () {
        state.grayscale = this.checked;
        applyAll(); save();
      });
      motionCb.addEventListener('change', function () {
        state.motion = this.checked;
        applyAll(); save();
      });
    })();
  </script>
  <?php endif; ?>
</body>

</html>