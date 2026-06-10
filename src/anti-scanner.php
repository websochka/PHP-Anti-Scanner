<?php
/**
 * PHP Anti-Scanner
 *
 * Автоматически блокирует IP-адреса, которые обращаются к подозрительным URL.
 * Подходит для подключения в начале 404.php, особенно на WordPress-сайтах.
 */

declare(strict_types=1);

$jsonUrl = 'https://shell.seotools.workers.dev';
$localFile = __DIR__ . '/suspicious-paths.json';
$cacheLifetime = 24 * 60 * 60;
$htaccessFile = rtrim((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''), '/') . '/.htaccess';

function anti_scanner_get_client_ip(): string
{
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP']
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? '';

    if (strpos($ip, ',') !== false) {
        $ip = trim(explode(',', $ip)[0]);
    }

    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

function anti_scanner_load_paths(string $jsonUrl, string $localFile, int $cacheLifetime): array
{
    $needUpdate = !file_exists($localFile) || (time() - (int) filemtime($localFile) > $cacheLifetime);

    if ($needUpdate) {
        $jsonData = @file_get_contents($jsonUrl);

        if (is_string($jsonData) && $jsonData !== '') {
            @file_put_contents($localFile, $jsonData, LOCK_EX);
        }
    }

    if (!file_exists($localFile)) {
        return [];
    }

    $jsonData = file_get_contents($localFile);
    $paths = json_decode((string) $jsonData, true);

    return is_array($paths) ? $paths : [];
}

function anti_scanner_get_request_path(): string
{
    $requestUri = (string) ($_SERVER['REQUEST_URI'] ?? '');
    $path = parse_url($requestUri, PHP_URL_PATH);

    return is_string($path) ? $path : $requestUri;
}

function anti_scanner_htaccess_block_exists(string $content): bool
{
    return strpos($content, '# BEGIN PHP Anti-Scanner') !== false
        && strpos($content, '# END PHP Anti-Scanner') !== false;
}

function anti_scanner_extract_blocked_ips(string $content): array
{
    preg_match_all('/Deny from\s+([0-9a-fA-F:\.]+)/', $content, $matches);
    return array_unique($matches[1] ?? []);
}

function anti_scanner_build_block(array $ips): string
{
    $lines = [
        '# BEGIN PHP Anti-Scanner',
        '<IfModule mod_authz_core.c>',
        '    <RequireAll>',
        '        Require all granted',
    ];

    foreach ($ips as $ip) {
        $lines[] = '        Require not ip ' . $ip;
    }

    $lines[] = '    </RequireAll>';
    $lines[] = '</IfModule>';
    $lines[] = '<IfModule !mod_authz_core.c>';
    $lines[] = '    Order allow,deny';
    $lines[] = '    Allow from all';

    foreach ($ips as $ip) {
        $lines[] = '    Deny from ' . $ip;
    }

    $lines[] = '</IfModule>';
    $lines[] = '# END PHP Anti-Scanner';

    return implode(PHP_EOL, $lines) . PHP_EOL;
}

function anti_scanner_block_ip(string $htaccessFile, string $ip): bool
{
    if ($ip === '') {
        return false;
    }

    $content = file_exists($htaccessFile) ? (string) file_get_contents($htaccessFile) : '';
    $blockedIps = anti_scanner_extract_blocked_ips($content);

    if (in_array($ip, $blockedIps, true)) {
        return true;
    }

    $blockedIps[] = $ip;
    $block = anti_scanner_build_block($blockedIps);

    if (anti_scanner_htaccess_block_exists($content)) {
        $content = preg_replace(
            '/# BEGIN PHP Anti-Scanner.*?# END PHP Anti-Scanner\s*/s',
            $block,
            $content
        );
    } else {
        $content = rtrim($content) . PHP_EOL . PHP_EOL . $block;
    }

    return file_put_contents($htaccessFile, $content, LOCK_EX) !== false;
}

$suspiciousPaths = anti_scanner_load_paths($jsonUrl, $localFile, $cacheLifetime);
$requestPath = anti_scanner_get_request_path();

if (in_array($requestPath, $suspiciousPaths, true)) {
    anti_scanner_block_ip($htaccessFile, anti_scanner_get_client_ip());

    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Access forbidden. Your IP has been blocked.';
    exit;
}
