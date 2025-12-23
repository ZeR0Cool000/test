<?php
/**
 * HTTP Headers Diagnostic Tool for Mobile Chrome
 * Displays all HTTP headers sent by the browser
 * Requests high-entropy Client Hints via Accept-CH
 * 
 * Deploy to any PHP server and access from mobile Chrome
 */

// Request ALL Client Hints headers
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
    'Sec-CH-Prefers-Reduced-Transparency',
    'Device-Memory',
    'DPR',
    'Viewport-Width',
    'Viewport-Height',
    'Width',
    'Downlink',
    'ECT',
    'RTT',
    'Save-Data'
];

// Send Accept-CH header to request all Client Hints
header('Accept-CH: ' . implode(', ', $clientHints));
header('Critical-CH: Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List');
header('Permissions-Policy: ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version=*, ch-ua-full-version-list=*, ch-ua-mobile=*, ch-ua-model=*, ch-ua-platform=*, ch-ua-platform-version=*, ch-ua-wow64=*, ch-ua-form-factors=*');

// Get all headers
$headers = [];
$rawHeaders = [];

// Get all HTTP headers
if (function_exists('getallheaders')) {
    $rawHeaders = getallheaders();
} else {
    // Fallback for servers without getallheaders
    foreach ($_SERVER as $key => $value) {
        if (substr($key, 0, 5) === 'HTTP_') {
            $header = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
            $rawHeaders[$header] = $value;
        }
    }
}

// Categorize headers
$categories = [
    'standard' => [
        'title' => 'Standard HTTP Headers',
        'description' => 'Basic request headers',
        'headers' => []
    ],
    'client_hints_ua' => [
        'title' => 'User-Agent Client Hints',
        'description' => 'Browser/platform identification (Sec-CH-UA-*)',
        'headers' => []
    ],
    'client_hints_device' => [
        'title' => 'Device Client Hints',
        'description' => 'Device capabilities and preferences',
        'headers' => []
    ],
    'client_hints_network' => [
        'title' => 'Network Client Hints',
        'description' => 'Connection quality information',
        'headers' => []
    ],
    'fetch_metadata' => [
        'title' => 'Fetch Metadata Headers',
        'description' => 'Request context (Sec-Fetch-*)',
        'headers' => []
    ],
    'security' => [
        'title' => 'Security & Privacy Headers',
        'description' => 'Privacy and security indicators',
        'headers' => []
    ],
    'other' => [
        'title' => 'Other Headers',
        'description' => 'Additional headers',
        'headers' => []
    ]
];

// Categorize each header
foreach ($rawHeaders as $name => $value) {
    $header = ['name' => $name, 'value' => $value];
    $nameLower = strtolower($name);
    
    if (strpos($nameLower, 'sec-ch-ua') === 0) {
        $categories['client_hints_ua']['headers'][] = $header;
    } elseif (in_array($nameLower, ['device-memory', 'dpr', 'viewport-width', 'viewport-height', 'width', 'sec-ch-prefers-color-scheme', 'sec-ch-prefers-reduced-motion', 'sec-ch-prefers-reduced-transparency'])) {
        $categories['client_hints_device']['headers'][] = $header;
    } elseif (in_array($nameLower, ['downlink', 'ect', 'rtt', 'save-data'])) {
        $categories['client_hints_network']['headers'][] = $header;
    } elseif (strpos($nameLower, 'sec-fetch') === 0) {
        $categories['fetch_metadata']['headers'][] = $header;
    } elseif (in_array($nameLower, ['sec-gpc', 'dnt', 'upgrade-insecure-requests', 'origin'])) {
        $categories['security']['headers'][] = $header;
    } elseif (in_array($nameLower, ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'host', 'connection', 'referer', 'cookie', 'cache-control', 'pragma', 'content-type', 'content-length'])) {
        $categories['standard']['headers'][] = $header;
    } else {
        $categories['other']['headers'][] = $header;
    }
}

// Prepare JSON data
$jsonData = [
    'timestamp' => date('c'),
    'serverInfo' => [
        'php_version' => PHP_VERSION,
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'Unknown',
        'https' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
    ],
    'headers' => [
        'raw' => $rawHeaders,
        'categorized' => []
    ],
    'analysis' => []
];

// Add categorized headers to JSON
foreach ($categories as $key => $category) {
    if (!empty($category['headers'])) {
        $jsonData['headers']['categorized'][$key] = [];
        foreach ($category['headers'] as $header) {
            $jsonData['headers']['categorized'][$key][$header['name']] = $header['value'];
        }
    }
}

// Parse and analyze key headers
if (isset($rawHeaders['User-Agent'])) {
    $ua = $rawHeaders['User-Agent'];
    $jsonData['analysis']['user_agent'] = [
        'raw' => $ua,
        'is_mobile' => (bool)preg_match('/Mobile|Android|iPhone|iPad/i', $ua),
        'is_android' => (bool)preg_match('/Android/i', $ua),
        'is_chrome' => (bool)preg_match('/Chrome/i', $ua)
    ];
    
    // Extract Chrome version
    if (preg_match('/Chrome\/(\d+\.\d+\.\d+\.\d+)/', $ua, $matches)) {
        $jsonData['analysis']['user_agent']['chrome_version'] = $matches[1];
    }
    
    // Extract Android version
    if (preg_match('/Android\s+([\d.]+)/', $ua, $matches)) {
        $jsonData['analysis']['user_agent']['android_version'] = $matches[1];
    }
}

// Parse Sec-CH-UA if present
if (isset($rawHeaders['Sec-CH-UA']) || isset($rawHeaders['sec-ch-ua'])) {
    $secChUa = $rawHeaders['Sec-CH-UA'] ?? $rawHeaders['sec-ch-ua'];
    $jsonData['analysis']['sec_ch_ua'] = [
        'raw' => $secChUa,
        'parsed' => []
    ];
    
    // Parse the brands
    preg_match_all('/"([^"]+)";v="([^"]+)"/', $secChUa, $matches, PREG_SET_ORDER);
    foreach ($matches as $match) {
        $jsonData['analysis']['sec_ch_ua']['parsed'][] = [
            'brand' => $match[1],
            'version' => $match[2]
        ];
    }
}

$jsonOutput = json_encode($jsonData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>HTTP Headers Diagnostic</title>
    <style>
        :root {
            --bg: #0f172a;
            --card: #1e293b;
            --border: #334155;
            --text: #e2e8f0;
            --text-dim: #94a3b8;
            --accent: #3b82f6;
            --accent-dim: #1d4ed8;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            padding: 12px;
            font-size: 14px;
            line-height: 1.5;
            min-height: 100vh;
        }
        
        .header {
            text-align: center;
            padding: 16px 0;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--border);
        }
        
        .header h1 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .header .timestamp {
            font-size: 12px;
            color: var(--text-dim);
        }
        
        .btn-group {
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }
        
        .btn {
            flex: 1;
            min-width: 120px;
            padding: 12px 16px;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: var(--accent);
            color: white;
        }
        
        .btn-primary:active {
            background: var(--accent-dim);
            transform: scale(0.98);
        }
        
        .btn-secondary {
            background: var(--card);
            color: var(--text);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:active {
            background: var(--border);
        }
        
        .toast {
            position: fixed;
            bottom: 80px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: var(--success);
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 500;
            opacity: 0;
            transition: all 0.3s;
            z-index: 1000;
        }
        
        .toast.show {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }
        
        .category {
            background: var(--card);
            border-radius: 12px;
            margin-bottom: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        
        .category-header {
            padding: 12px 16px;
            background: rgba(255,255,255,0.03);
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .category-title {
            font-weight: 600;
            font-size: 15px;
        }
        
        .category-count {
            background: var(--accent);
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .category-empty {
            color: var(--text-dim);
            font-style: italic;
            font-size: 12px;
        }
        
        .header-item {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
        }
        
        .header-item:last-child {
            border-bottom: none;
        }
        
        .header-name {
            font-weight: 500;
            color: var(--accent);
            font-size: 13px;
            margin-bottom: 4px;
            word-break: break-all;
        }
        
        .header-value {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 12px;
            color: var(--text);
            word-break: break-all;
            background: rgba(0,0,0,0.2);
            padding: 8px;
            border-radius: 6px;
            white-space: pre-wrap;
        }
        
        .section-title {
            font-size: 12px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin: 20px 0 12px 0;
            padding-left: 4px;
        }
        
        .info-box {
            background: var(--card);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 16px;
            border: 1px solid var(--border);
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid var(--border);
        }
        
        .info-row:last-child {
            border-bottom: none;
        }
        
        .info-label {
            color: var(--text-dim);
            font-size: 13px;
        }
        
        .info-value {
            color: var(--text);
            font-weight: 500;
            font-size: 13px;
            text-align: right;
            max-width: 60%;
            word-break: break-all;
        }
        
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
        }
        
        .badge-success {
            background: rgba(34, 197, 94, 0.2);
            color: var(--success);
        }
        
        .badge-warning {
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning);
        }
        
        .badge-error {
            background: rgba(239, 68, 68, 0.2);
            color: var(--error);
        }
        
        .note {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 8px;
            padding: 12px;
            font-size: 12px;
            color: var(--text-dim);
            margin-bottom: 16px;
        }
        
        .note strong {
            color: var(--accent);
        }
        
        .expected-headers {
            background: var(--card);
            border-radius: 12px;
            padding: 16px;
            margin-top: 16px;
            border: 1px solid var(--border);
        }
        
        .expected-headers h3 {
            font-size: 14px;
            margin-bottom: 12px;
            color: var(--text);
        }
        
        .expected-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        
        .expected-item {
            font-size: 11px;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: monospace;
        }
        
        .expected-present {
            background: rgba(34, 197, 94, 0.15);
            color: var(--success);
            border: 1px solid rgba(34, 197, 94, 0.3);
        }
        
        .expected-missing {
            background: rgba(239, 68, 68, 0.15);
            color: var(--error);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        @media (max-width: 400px) {
            body {
                padding: 8px;
            }
            
            .header h1 {
                font-size: 18px;
            }
            
            .btn {
                padding: 10px 12px;
                font-size: 13px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📡 HTTP Headers Diagnostic</h1>
        <div class="timestamp"><?= date('Y-m-d H:i:s T') ?></div>
    </div>
    
    <div class="btn-group">
        <button class="btn btn-primary" onclick="copyJSON()">
            📋 Copy JSON
        </button>
        <button class="btn btn-secondary" onclick="location.reload()">
            🔄 Refresh
        </button>
    </div>
    
    <div class="note">
        <strong>Note:</strong> High-entropy Client Hints (Model, Platform-Version, etc.) require Accept-CH header from server. 
        <strong>Reload the page</strong> to see all hints after the browser receives Accept-CH response.
    </div>

    <?php
    // Server Info Section
    echo '<div class="section-title">Server & Connection Info</div>';
    echo '<div class="info-box">';
    echo '<div class="info-row"><span class="info-label">Protocol</span><span class="info-value">' . htmlspecialchars($_SERVER['SERVER_PROTOCOL'] ?? 'Unknown') . '</span></div>';
    echo '<div class="info-row"><span class="info-label">HTTPS</span><span class="info-value">';
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        echo '<span class="badge badge-success">Yes</span>';
    } else {
        echo '<span class="badge badge-warning">No</span>';
    }
    echo '</span></div>';
    echo '<div class="info-row"><span class="info-label">Client IP</span><span class="info-value">' . htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'Unknown') . '</span></div>';
    echo '<div class="info-row"><span class="info-label">Request Method</span><span class="info-value">' . htmlspecialchars($_SERVER['REQUEST_METHOD'] ?? 'Unknown') . '</span></div>';
    echo '</div>';
    ?>

    <div class="section-title">Request Headers by Category</div>
    
    <?php foreach ($categories as $key => $category): ?>
        <div class="category">
            <div class="category-header">
                <span class="category-title"><?= htmlspecialchars($category['title']) ?></span>
                <?php if (!empty($category['headers'])): ?>
                    <span class="category-count"><?= count($category['headers']) ?></span>
                <?php else: ?>
                    <span class="category-empty">Not received</span>
                <?php endif; ?>
            </div>
            <?php foreach ($category['headers'] as $header): ?>
                <div class="header-item">
                    <div class="header-name"><?= htmlspecialchars($header['name']) ?></div>
                    <div class="header-value"><?= htmlspecialchars($header['value']) ?></div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endforeach; ?>

    <?php
    // Expected headers check
    $expectedHeaders = [
        // Low entropy (always sent)
        'Sec-CH-UA' => 'Low entropy, always sent',
        'Sec-CH-UA-Mobile' => 'Low entropy, always sent',
        'Sec-CH-UA-Platform' => 'Low entropy, always sent',
        // High entropy (requires Accept-CH)
        'Sec-CH-UA-Arch' => 'High entropy',
        'Sec-CH-UA-Bitness' => 'High entropy',
        'Sec-CH-UA-Full-Version-List' => 'High entropy',
        'Sec-CH-UA-Model' => 'High entropy',
        'Sec-CH-UA-Platform-Version' => 'High entropy',
        // Fetch Metadata
        'Sec-Fetch-Dest' => 'Fetch metadata',
        'Sec-Fetch-Mode' => 'Fetch metadata',
        'Sec-Fetch-Site' => 'Fetch metadata',
        'Sec-Fetch-User' => 'Fetch metadata (user-activated only)',
        // Standard
        'User-Agent' => 'Standard',
        'Accept' => 'Standard',
        'Accept-Language' => 'Standard',
        'Accept-Encoding' => 'Standard',
    ];
    
    $presentHeaders = array_change_key_case($rawHeaders, CASE_LOWER);
    ?>
    
    <div class="expected-headers">
        <h3>Expected Headers Check</h3>
        <div class="expected-list">
            <?php foreach ($expectedHeaders as $header => $type): ?>
                <?php 
                $isPresent = isset($presentHeaders[strtolower($header)]);
                $class = $isPresent ? 'expected-present' : 'expected-missing';
                $icon = $isPresent ? '✓' : '✗';
                ?>
                <span class="expected-item <?= $class ?>"><?= $icon ?> <?= htmlspecialchars($header) ?></span>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="toast" id="toast">Copied to clipboard!</div>
    
    <script>
        const headerData = <?= $jsonOutput ?>;
        
        function copyJSON() {
            const jsonStr = JSON.stringify(headerData, null, 2);
            
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(jsonStr).then(() => {
                    showToast('Copied to clipboard!');
                }).catch(err => {
                    fallbackCopy(jsonStr);
                });
            } else {
                fallbackCopy(jsonStr);
            }
        }
        
        function fallbackCopy(text) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            textarea.select();
            
            try {
                document.execCommand('copy');
                showToast('Copied to clipboard!');
            } catch (err) {
                showToast('Copy failed - check console');
                console.log('JSON Data:', text);
            }
            
            document.body.removeChild(textarea);
        }
        
        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.classList.add('show');
            
            setTimeout(() => {
                toast.classList.remove('show');
            }, 2000);
        }
        
        // Log to console for debugging
        console.log('HTTP Headers Data:', headerData);
    </script>
</body>
</html>
