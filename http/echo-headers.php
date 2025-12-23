<?php
/**
 * HTTP Headers Echo API
 * 
 * Returns all HTTP headers as JSON
 * Supports CORS for cross-origin requests
 * Requests all Client Hints via Accept-CH
 * 
 * Usage:
 * - GET /echo.php - returns headers as JSON
 * - GET /echo.php?format=pretty - returns formatted JSON
 * - GET /echo.php?callback=fn - JSONP support
 */

// Request ALL Client Hints
$clientHints = [
    'Sec-CH-UA',
    'Sec-CH-UA-Arch',
    'Sec-CH-UA-Bitness',
    'Sec-CH-UA-Full-Version',
    'Sec-CH-UA-Full-Version-List',
    'Sec-CH-UA-Mobile',
    'Sec-CH-UA-Model',
    'Sec-CH-UA-Platform',
    'Sec-CH-UA-Platform-Version',
    'Sec-CH-UA-WoW64',
    'Sec-CH-UA-Form-Factors',
    'Sec-CH-Prefers-Color-Scheme',
    'Sec-CH-Prefers-Reduced-Motion',
    'Device-Memory',
    'DPR',
    'Viewport-Width',
    'Viewport-Height',
    'Downlink',
    'ECT',
    'RTT',
    'Save-Data'
];

// Send Accept-CH to request all Client Hints
header('Accept-CH: ' . implode(', ', $clientHints));
header('Critical-CH: Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List');

// CORS headers for cross-origin requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: *');
header('Access-Control-Expose-Headers: *');

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Collect all headers
$headers = [];
if (function_exists('getallheaders')) {
    $headers = getallheaders();
} else {
    foreach ($_SERVER as $key => $value) {
        if (substr($key, 0, 5) === 'HTTP_') {
            $header = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
            $headers[$header] = $value;
        }
    }
}

// Build response
$response = [
    'timestamp' => date('c'),
    'request' => [
        'method' => $_SERVER['REQUEST_METHOD'],
        'uri' => $_SERVER['REQUEST_URI'],
        'protocol' => $_SERVER['SERVER_PROTOCOL'],
        'https' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'query_string' => $_SERVER['QUERY_STRING'] ?? ''
    ],
    'client' => [
        'ip' => $_SERVER['REMOTE_ADDR'],
        'port' => $_SERVER['REMOTE_PORT'] ?? null,
        'forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
        'real_ip' => $_SERVER['HTTP_X_REAL_IP'] ?? null
    ],
    'headers' => $headers,
    'headers_categorized' => categorizeHeaders($headers),
    'server' => [
        'software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'php_version' => PHP_VERSION
    ]
];

// Categorize headers
function categorizeHeaders($headers) {
    $categories = [
        'standard' => [],
        'client_hints_ua' => [],
        'client_hints_device' => [],
        'client_hints_network' => [],
        'fetch_metadata' => [],
        'security' => [],
        'other' => []
    ];
    
    foreach ($headers as $name => $value) {
        $nameLower = strtolower($name);
        
        if (strpos($nameLower, 'sec-ch-ua') === 0) {
            $categories['client_hints_ua'][$name] = $value;
        } elseif (in_array($nameLower, ['device-memory', 'dpr', 'viewport-width', 'viewport-height', 'width', 'sec-ch-prefers-color-scheme', 'sec-ch-prefers-reduced-motion'])) {
            $categories['client_hints_device'][$name] = $value;
        } elseif (in_array($nameLower, ['downlink', 'ect', 'rtt', 'save-data'])) {
            $categories['client_hints_network'][$name] = $value;
        } elseif (strpos($nameLower, 'sec-fetch') === 0) {
            $categories['fetch_metadata'][$name] = $value;
        } elseif (in_array($nameLower, ['sec-gpc', 'dnt', 'upgrade-insecure-requests', 'origin'])) {
            $categories['security'][$name] = $value;
        } elseif (in_array($nameLower, ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'host', 'connection', 'referer', 'cookie', 'cache-control', 'pragma'])) {
            $categories['standard'][$name] = $value;
        } else {
            $categories['other'][$name] = $value;
        }
    }
    
    // Remove empty categories
    return array_filter($categories, fn($cat) => !empty($cat));
}

// Determine output format
$format = isset($_GET['format']) && $_GET['format'] === 'pretty' 
    ? JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    : JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;

$json = json_encode($response, $format);

// JSONP support
if (isset($_GET['callback'])) {
    $callback = preg_replace('/[^a-zA-Z0-9_]/', '', $_GET['callback']);
    header('Content-Type: application/javascript; charset=utf-8');
    echo $callback . '(' . $json . ');';
} else {
    header('Content-Type: application/json; charset=utf-8');
    echo $json;
}
