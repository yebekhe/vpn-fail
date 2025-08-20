<?php
// Set a default timezone to avoid potential warnings
date_default_timezone_set('UTC');
// It's better to configure this in php.ini, but for a single script, this is fine.
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Validates if a string is a valid IP address (IPv4 or IPv6).
 */
function is_ip(string $string): bool
{
    return filter_var($string, FILTER_VALIDATE_IP) !== false;
}

/**
 * Parses a key-value string into an associative array.
 */
function parse_key_value_string(string $input): array
{
    $data = [];
    $lines = preg_split('/\\R/', $input, -1, PREG_SPLIT_NO_EMPTY);

    foreach ($lines as $line) {
        $parts = explode('=', $line, 2);
        if (count($parts) === 2) {
            $key = trim($parts[0]);
            $value = trim($parts[1]);
            if ($key !== '' && $value !== '') {
                $data[$key] = $value;
            }
        }
    }
    return $data;
}

/**
 * Gets geolocation information for an IP or hostname.
 */
function ip_info(string $ipOrHost): ?stdClass
{
    $ip = $ipOrHost;
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        $ip_records = @dns_get_record($ip, DNS_A);
        if (empty($ip_records)) {
            return null;
        }
        $ip = $ip_records[array_rand($ip_records)]["ip"];
    }

    if (is_cloudflare_ip($ip)) {
        return (object)["country" => "CF"];
    }
    
    $endpoints = [
        ['https://ipapi.co/{ip}/json/', 'country_code'],
        ['https://ipwho.is/{ip}', 'country_code'],
        ['http://www.geoplugin.net/json.gp?ip={ip}', 'geoplugin_countryCode'],
    ];

    $options = [
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n",
            'timeout' => 3,
            'ignore_errors' => true,
        ],
    ];
    $context = stream_context_create($options);

    foreach ($endpoints as [$url_template, $country_key]) {
        $url = str_replace('{ip}', urlencode($ip), $url_template);
        $response = @file_get_contents($url, false, $context);

        if ($response !== false) {
            $data = json_decode($response);
            if (json_last_error() === JSON_ERROR_NONE && isset($data->{$country_key})) {
                return (object)["country" => $data->{$country_key} ?? 'XX'];
            }
        }
    }

    return (object)["country" => "XX"];
}

/**
 * Checks if a given IP address belongs to Cloudflare.
 */
function is_cloudflare_ip(string $ip, string $cacheFile = 'cloudflare_ips.json', int $cacheDuration = 86400): bool
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return false;
    }

    $ipRanges = [];

    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheDuration) {
        $ipRanges = json_decode(file_get_contents($cacheFile), true);
    } else {
        $ipv4 = @file_get_contents('https://www.cloudflare.com/ips-v4');
        $ipv6 = @file_get_contents('https://www.cloudflare.com/ips-v6');

        if ($ipv4 && $ipv6) {
            $ipv4Ranges = explode("\n", trim($ipv4));
            $ipv6Ranges = explode("\n", trim($ipv6));
            $ipRanges = array_merge($ipv4Ranges, $ipv6Ranges);
            file_put_contents($cacheFile, json_encode($ipRanges));
        } else if (file_exists($cacheFile)) {
            $ipRanges = json_decode(file_get_contents($cacheFile), true);
        }
    }

    if (empty($ipRanges)) {
        return false;
    }

    foreach ($ipRanges as $range) {
        if (ip_in_cidr($ip, $range)) {
            return true;
        }
    }

    return false;
}

/**
 * Helper function to check if an IP is within a CIDR range.
 */
function ip_in_cidr(string $ip, string $cidr): bool
{
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    
    list($net, $mask) = explode('/', $cidr);

    $ip_net = inet_pton($ip);
    $net_net = inet_pton($net);
    
    if ($ip_net === false || $net_net === false) {
        return false;
    }

    $ip_len = strlen($ip_net);
    $net_len = strlen($net_net);

    if ($ip_len !== $net_len) {
        return false;
    }
    
    $mask_bin = str_repeat('1', $mask) . str_repeat('0', ($ip_len * 8) - $mask);
    $mask_net = '';
    foreach (str_split($mask_bin, 8) as $byte) {
        $mask_net .= chr(bindec($byte));
    }

    return ($ip_net & $mask_net) === ($net_net & $mask_net);
}

/**
 * Checks if the input string contains invalid characters.
 */
function is_valid(string $input): bool
{
    return !(str_contains($input, '…') || str_contains($input, '...'));
}

/**
 * Determines if a proxy configuration is encrypted.
 */
function isEncrypted(string $input): bool
{
    $configType = detect_type($input);

    switch ($configType) {
        case 'vmess':
            $decodedConfig = configParse($input);
            return ($decodedConfig['tls'] ?? '') !== '' && ($decodedConfig['scy'] ?? 'none') !== 'none';

        case 'vless':
        case 'trojan':
            return str_contains($input, 'security=tls') || str_contains($input, 'security=reality');
        
        case 'ss':
        case 'tuic':
        case 'hy2':
            return true;

        default:
            return false;
    }
}

/**
 * Converts a 2-letter country code to a regional flag emoji.
 */
function getFlags(string $country_code): string
{
    $country_code = strtoupper(trim($country_code));
    if (strlen($country_code) !== 2 || !ctype_alpha($country_code) || $country_code === "XX") {
        return '🏳️';
    }

    $regional_offset = 127397;
    $char1 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[0])) . ';', 'UTF-8', 'HTML-ENTITIES');
    $char2 = mb_convert_encoding('&#' . ($regional_offset + ord($country_code[1])) . ';', 'UTF-8', 'HTML-ENTITIES');
    
    return $char1 . $char2;
}

/**
 * Detects the proxy protocol type from a configuration link.
 */
function detect_type(string $input): ?string
{
    if (str_starts_with($input, 'vmess://')) return 'vmess';
    if (str_starts_with($input, 'vless://')) return 'vless';
    if (str_starts_with($input, 'trojan://')) return 'trojan';
    if (str_starts_with($input, 'ss://')) return 'ss';
    if (str_starts_with($input, 'tuic://')) return 'tuic';
    if (str_starts_with($input, 'hy2://') || str_starts_with($input, 'hysteria2://')) return 'hy2';
    if (str_starts_with($input, 'hysteria://')) return 'hysteria';
    
    return null;
}

/**
 * Extracts all valid proxy links from a given text.
 */
function extractLinksByType(string $text): array
{
    $valid_types = ['vmess', 'vless', 'trojan', 'ss', 'tuic', 'hy2', 'hysteria'];
    $type_pattern = implode('|', $valid_types);
    $pattern = "/(?:{$type_pattern}):\\/\\/[^\\s\"']*(?=\\s|<|>|$)/i";
    
    preg_match_all($pattern, $text, $matches);
    
    return $matches[0] ?? [];
}

/**
 * Parses a configuration link into an associative array.
 */
function configParse(string $input): ?array
{
    $configType = detect_type($input);

    switch ($configType) {
        case 'vmess':
            $base64_data = substr($input, 8);
            return json_decode(base64_decode($base64_data), true);

        case 'vless':
        case 'trojan':
        case 'tuic':
        case 'hy2':
            $parsedUrl = parse_url($input);
            if ($parsedUrl === false) return null;
            
            $params = [];
            if (isset($parsedUrl['query'])) {
                parse_str($parsedUrl['query'], $params);
            }
            
            $output = [
                'protocol' => $configType,
                'username' => $parsedUrl['user'] ?? '',
                'hostname' => $parsedUrl['host'] ?? '',
                'port' => $parsedUrl['port'] ?? '',
                'params' => $params,
                'hash' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : 'PSG' . getRandomName(),
            ];

            if ($configType === 'tuic') {
                $output['pass'] = $parsedUrl['pass'] ?? '';
            }
            return $output;

        case 'ss':
            $parsedUrl = parse_url($input);
            if ($parsedUrl === false) return null;

            $userInfo = rawurldecode($parsedUrl['user'] ?? '');
            if (isBase64($userInfo)) {
                $userInfo = base64_decode($userInfo);
            }

            if (!str_contains($userInfo, ':')) return null;
            list($method, $password) = explode(':', $userInfo, 2);

            return [
                'encryption_method' => $method,
                'password' => $password,
                'server_address' => $parsedUrl['host'] ?? '',
                'server_port' => $parsedUrl['port'] ?? '',
                'name' => isset($parsedUrl['fragment']) ? rawurldecode($parsedUrl['fragment']) : 'PSG' . getRandomName(),
            ];
            
        default:
            return null;
    }
}

/**
 * Rebuilds a configuration link from a parsed array.
 */
function reparseConfig(array $configArray, string $configType): ?string
{
    switch ($configType) {
        case 'vmess':
            $encoded_data = rtrim(strtr(base64_encode(json_encode($configArray)), '+/', '-_'), '=');
            return "vmess://" . $encoded_data;
        
        case 'vless':
        case 'trojan':
        case 'tuic':
        case 'hy2':
            $url = $configType . "://";
            if (!empty($configArray['username'])) {
                $url .= $configArray['username'];
                if (!empty($configArray['pass'])) {
                    $url .= ':' . $configArray['pass'];
                }
                $url .= '@';
            }
            $url .= $configArray['hostname'];
            if (!empty($configArray['port'])) {
                $url .= ':' . $configArray['port'];
            }
            if (!empty($configArray['params'])) {
                $url .= '?' . http_build_query($configArray['params']);
            }
            if (!empty($configArray['hash'])) {
                $url .= '#' . rawurlencode($configArray['hash']);
            }
            return $url;

        case 'ss':
            $user_info = base64_encode($configArray['encryption_method'] . ':' . $configArray['password']);
            $url = "ss://{$user_info}@{$configArray['server_address']}:{$configArray['server_port']}";
            if (!empty($configArray['name'])) {
                $url .= '#' . rawurlencode($configArray['name']);
            }
            return $url;

        default:
            return null;
    }
}

/**
 * Checks if a VLESS config uses the 'reality' security protocol.
 */
function is_reality(string $input): bool
{
    return str_starts_with($input, 'vless://') && str_contains($input, 'security=reality');
}

/**
 * Checks if a string is Base64 encoded.
 */
function isBase64(string $input): bool
{
    return base64_decode($input, true) !== false;
}

/**
 * Generates a cryptographically secure random name.
 */
function getRandomName(int $length = 10): string
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyz';
    $max = strlen($alphabet) - 1;
    $name = '';
    for ($i = 0; $i < $length; $i++) {
        $name .= $alphabet[random_int(0, $max)];
    }
    return $name;
}

/**
 * Recursively deletes a folder and its contents.
 */
function deleteFolder(string $folder): bool
{
    if (!is_dir($folder)) {
        return false;
    }

    $iterator = new RecursiveDirectoryIterator($folder, RecursiveDirectoryIterator::SKIP_DOTS);
    $files = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::CHILD_FIRST);

    foreach ($files as $file) {
        if ($file->isDir()) {
            rmdir($file->getRealPath());
        } else {
            unlink($file->getRealPath());
        }
    }

    return rmdir($folder);
}

/**
 * Gets the current time in the Asia/Tehran timezone.
 */
function tehran_time(string $format = 'Y-m-d H:i:s'): string
{
    try {
        $date = new DateTime('now', new DateTimeZone('Asia/Tehran'));
        return $date->format($format);
    } catch (Exception $e) {
        return date($format);
    }
}

/**
 * Generates a Hiddify-compatible subscription header.
 */
function hiddifyHeader(string $subscriptionName): string
{
    $base64Name = base64_encode($subscriptionName);
    return <<<HEADER
#profile-title: base64:{$base64Name}
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531
#support-url: https://t.me/yebekhe
#profile-web-page-url: https://github.com/itsyebekhe/PSG

HEADER;
}

/**
 * INTERNAL FUNCTION: Fetches a single batch of URLs in parallel.
 */
function _internal_fetch_batch(array $urls): array
{
    $multi_handle = curl_multi_init();
    $handles = [];
    $results = [];

    if (empty($urls)) {
        return [];
    }

    foreach ($urls as $key => $url) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);
        $handles[$key] = $ch;
        curl_multi_add_handle($multi_handle, $ch);
    }

    $running = null;
    do {
        curl_multi_exec($multi_handle, $running);
        if ($running) {
            curl_multi_select($multi_handle);
        }
    } while ($running > 0);

    foreach ($handles as $key => $ch) {
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content = curl_multi_getcontent($ch);
        
        if (curl_errno($ch) === 0 && $http_code === 200 && !empty($content)) {
            $results[$key] = $content;
        }
        
        curl_multi_remove_handle($multi_handle, $ch);
        curl_close($ch);
    }

    curl_multi_close($multi_handle);
    return $results;
}

/**
 * PUBLIC FUNCTION: Fetches multiple URLs in parallel with a retry mechanism.
 */
function fetch_multiple_urls_parallel(array $urls, int $max_retries = 3, int $delay = 2): array
{
    $all_fetched_content = [];
    $urls_to_retry = $urls;

    for ($attempt = 1; $attempt <= $max_retries; $attempt++) {
        if (empty($urls_to_retry)) {
            break;
        }

        echo "\n  - Fetch attempt #{$attempt} for " . count($urls_to_retry) . " URLs...";
        
        $fetched_this_round = _internal_fetch_batch($urls_to_retry);
        $all_fetched_content = array_merge($all_fetched_content, $fetched_this_round);
        $urls_to_retry = array_diff_key($urls_to_retry, $fetched_this_round);

        if (!empty($urls_to_retry) && $attempt < $max_retries) {
            echo PHP_EOL . "  [!] " . count($urls_to_retry) . " URLs failed. Retrying in {$delay} seconds..." . PHP_EOL;
            sleep($delay);
        }
    }
    
    if (!empty($urls_to_retry)) {
        echo PHP_EOL . "  [!!] CRITICAL WARNING: The following URLs failed after all attempts:" . PHP_EOL;
        foreach (array_keys($urls_to_retry) as $failed_key) {
            echo "      - {$failed_key}" . PHP_EOL;
        }
    }

    return $all_fetched_content;
}

/**
 * Prints a clean, overwriting progress bar to the console.
 */
function print_progress(int $current, int $total, string $message = ''): void
{
    if ($total == 0) return;
    $percentage = ($current / $total) * 100;
    $bar_length = 50;
    $filled_length = (int)($bar_length * $current / $total);
    $bar = str_repeat('=', $filled_length) . str_repeat(' ', $bar_length - $filled_length);
    printf("\r%s [%s] %d%% (%d/%d)", $message, $bar, $percentage, $current, $total);
}

/**
 * Validates if a string is a valid Version 4 UUID.
 */
function is_valid_uuid(?string $uuid): bool
{
    if ($uuid === null) {
        return false;
    }
    
    $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
    return (bool) preg_match($pattern, $uuid);
}

/**
 * Fetches multiple pages of a Telegram channel.
 */
function fetch_channel_data_paginated(string $channelName, int $maxPages): string
{
    $combinedHtml = '';
    $nextUrl = "https://t.me/s/{$channelName}";
    $fetchedPages = 0;

    while ($fetchedPages < $maxPages && $nextUrl) {
        echo "\rFetching page " . ($fetchedPages + 1) . "/{$maxPages} for channel '{$channelName}'... ";
        
        $response = @file_get_contents($nextUrl, false, stream_context_create([
            'http' => [
                'timeout' => 15,
                'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            ]
        ]));

        if ($response === false || empty($response)) {
            $nextUrl = null;
            continue;
        }

        $combinedHtml .= $response;

        preg_match_all('/data-post="[^"]+\/(\d+)"/', $response, $matches);
        
        if (!empty($matches[1])) {
            $oldestMessageId = min($matches[1]);
            $nextUrl = "https://t.me/s/{$channelName}?before={$oldestMessageId}";
        } else {
            $nextUrl = null;
        }
        $fetchedPages++;
    }

    return $combinedHtml;
}

// ============================================================================
// CONFIG WRAPPER CLASS
// ============================================================================

class ConfigWrapper
{
    private ?array $decoded;
    private string $type;

    public function __construct(string $config_string)
    {
        $this->type = detect_type($config_string) ?? 'unknown';
        $this->decoded = configParse($config_string);
    }

    public function isValid(): bool
    {
        return $this->decoded !== null;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getTag(): string
    {
        $field = match($this->type) {
            'vmess' => 'ps',
            'ss' => 'name',
            default => 'hash',
        };
        return urldecode($this->decoded[$field] ?? 'Unknown Tag');
    }

    public function getServer(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['add'],
            'ss' => $this->decoded['server_address'],
            default => $this->decoded['hostname'],
        };
    }

    public function getPort(): int
    {
        $port = match($this->type) {
            'ss' => $this->decoded['server_port'],
            default => $this->decoded['port'],
        };
        return (int)$port;
    }

    public function getUuid(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['id'],
            'vless', 'trojan' => $this->decoded['username'],
            'tuic' => $this->decoded['username'],
            default => '',
        };
    }

    public function getPassword(): string
    {
        return match($this->type) {
            'trojan' => $this->decoded['username'],
            'ss' => $this->decoded['password'],
            'tuic' => $this->decoded['pass'],
            'hy2' => $this->decoded['username'],
            default => '',
        };
    }

    public function getSni(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['sni'] ?? $this->getServer(),
            default => $this->decoded['params']['sni'] ?? $this->getServer(),
        };
    }

    public function getTransportType(): ?string
    {
        return match($this->type) {
            'vmess' => $this->decoded['net'],
            default => $this->decoded['params']['type'] ?? null,
        };
    }
    
    public function getPath(): string
    {
        $path = match($this->type) {
            'vmess' => $this->decoded['path'] ?? '/',
            default => $this->decoded['params']['path'] ?? '/',
        };
        return '/' . ltrim($path, '/');
    }

    public function getServiceName(): string
    {
        return match($this->type) {
            'vmess' => $this->decoded['path'] ?? '',
            default => $this->decoded['params']['serviceName'] ?? '',
        };
    }

    public function get(string $key, $default = null)
    {
        return $this->decoded[$key] ?? $default;
    }
    
    public function getParam(string $key, $default = null)
    {
        return $this->decoded['params'][$key] ?? $default;
    }
}

// ============================================================================
// PROXY SCRAPER CLASS
// ============================================================================

/**
 * A class to scrape, process, and store proxy configurations.
 */
class ProxyScraper
{
    private const BASE_URL = "https://vpn.fail/free-proxy/type/v2ray";
    private const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
    private const MAX_AGE_SECONDS = 86400; // Increased to 24 hours
    private const CACHE_FILE = 'proxy_cache.json';
    private const CACHE_EXPIRY = 3600; // 1 hour
    private const OUTPUT_DIR = 'output'; // Output directory for categorized files
    
    private array $countryCodes = [];
    private ?DOMDocument $dom = null;
    private array $config = [];
    private int $proxyCounter = 1;
    
    /**
     * Constructor: Loads necessary data like country codes.
     */
    public function __construct(string $countryCodesFile = 'countries.lock', array $config = [])
    {
        $this->config = array_merge([
            'max_age_seconds' => self::MAX_AGE_SECONDS,
            'cache_file' => self::CACHE_FILE,
            'cache_expiry' => self::CACHE_EXPIRY,
            'curl_timeout' => 30, // Increased from 15
            'connect_timeout' => 10, // New parameter
            'max_concurrent_requests' => 20, // Increased from 10
            'max_articles' => 100, // New parameter to limit articles
            'name_format' => '{flag} {country}-{type}-{id}',
            'output_format' => 'categorized',
        ], $config);
        
        $this->loadCountryCodes($countryCodesFile);
        $this->dom = new DOMDocument();
        
        // Create output directory if it doesn't exist
        if (!is_dir(self::OUTPUT_DIR)) {
            mkdir(self::OUTPUT_DIR, 0755, true);
        }
    }
    
    /**
     * Loads the country code mapping from a JSON file.
     * @throws Exception if the file is unreadable or contains invalid JSON.
     */
    private function loadCountryCodes(string $filename): void
    {
        if (!is_readable($filename)) {
            throw new Exception("Country codes file not found or is not readable: {$filename}");
        }
        
        $json = file_get_contents($filename);
        if ($json === false) {
            throw new Exception("Failed to read country codes file: {$filename}");
        }
        
        $this->countryCodes = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Failed to decode country codes JSON: " . json_last_error_msg());
        }
    }
    
    /**
     * Fetches content from a single URL with caching.
     * @throws Exception on cURL error.
     */
    private function fetchUrl(string $url, bool $useCache = true): string
    {
        $cacheKey = md5($url);
        $cacheFile = $this->config['cache_file'];
        
        // Check cache if enabled
        if ($useCache && is_readable($cacheFile)) {
            $cacheData = json_decode(file_get_contents($cacheFile), true);
            if (isset($cacheData[$cacheKey]) && 
                (time() - $cacheData[$cacheKey]['timestamp']) < $this->config['cache_expiry']) {
                return $cacheData[$cacheKey]['content'];
            }
        }
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => $this->config['curl_timeout'],
            CURLOPT_CONNECTTIMEOUT => $this->config['connect_timeout'],
        ]);
        
        $content = curl_exec($ch);
        
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new Exception("cURL Error for {$url}: {$error}");
        }
        
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 400) {
            throw new Exception("HTTP Error {$httpCode} for {$url}");
        }
        
        // Save to cache if enabled
        if ($useCache) {
            $cacheData = is_readable($cacheFile) ? json_decode(file_get_contents($cacheFile), true) : [];
            $cacheData[$cacheKey] = [
                'content' => $content,
                'timestamp' => time()
            ];
            file_put_contents($cacheFile, json_encode($cacheData));
        }
        
        return $content;
    }
    
    /**
     * Retrieves the ISO 3166-1 alpha-2 code for a given country name.
     */
    private function getCountryCode(string $countryName): string
    {
        $normalizedName = ucwords(strtolower($countryName));
        return $this->countryCodes[$normalizedName] ?? 'XX';
    }
    
    /**
     * The main method to execute the scraping process.
     */
    public function run(): void
    {
        try {
            // 1. Fetch the main page
            $mainHtml = $this->fetchUrl(self::BASE_URL);
            
            // 2. Extract initial article data
            $articles = $this->extractInitialArticleData($mainHtml);
            
            if (empty($articles)) {
                echo "No recent articles found.\n";
                return;
            }
            
            // 3. Fetch details from each article's page concurrently
            $results = $this->fetchArticleDetailsConcurrently($articles);
            
            // 4. Process and save the final results
            $this->saveResults($results);
            
            echo "Scraping completed successfully. Processed " . count($results) . " proxies.\n";
        } catch (Exception $e) {
            header("Content-Type: application/json;", true, 500);
            echo json_encode(['error' => $e->getMessage(), 'timestamp' => time()]);
            exit(1);
        }
    }
    
    /**
     * Parses the main HTML to find recent articles.
     */
    private function extractInitialArticleData(string $html): array
    {
        if (empty($html)) return [];
        
        libxml_use_internal_errors(true);
        $this->dom->loadHTML($html);
        libxml_clear_errors();
        
        $xpath = new DOMXPath($this->dom);
        $articleNodes = $xpath->query('//article');
        $articles = [];
        $currentTime = time();
        $maxArticles = $this->config['max_articles'];
        $processedArticles = 0;
        
        foreach ($articleNodes as $node) {
            if ($processedArticles >= $maxArticles) {
                break;
            }
            
            $timeSpan = $xpath->query('.//div[contains(@class, "col-sm-3 text-right")]//span', $node)->item(0);
            $timeValue = $timeSpan ? (int)trim($timeSpan->textContent) : 0;
            
            if (($currentTime - $timeValue) > $this->config['max_age_seconds']) {
                break;
            }
            
            $linkNode = $xpath->query('.//div//a', $node)->item(0);
            $countryNode = $xpath->query('.//div[contains(@class, "col-sm-2 text-center") and .//a[contains(@href, "/country/")]]', $node)->item(0);
            
            if ($linkNode) {
                $articles[] = [
                    'url' => $linkNode->getAttribute('href'),
                    'country_text' => $countryNode ? trim($countryNode->textContent) : "XX",
                    'time_value' => $timeValue,
                ];
                $processedArticles++;
            }
        }
        
        return $articles;
    }
    
    /**
     * Fetches details for multiple articles concurrently using curl_multi with batching.
     */
    private function fetchArticleDetailsConcurrently(array $articles): array
    {
        if (empty($articles)) return [];
        
        $results = [];
        $maxConcurrent = $this->config['max_concurrent_requests'];
        $batches = array_chunk($articles, $maxConcurrent);
        
        foreach ($batches as $batch) {
            $batchResults = $this->processBatch($batch);
            $results = array_merge($results, $batchResults);
        }
        
        return $results;
    }
    
    /**
     * Processes a batch of articles concurrently.
     */
    private function processBatch(array $batch): array
    {
        $multiHandle = curl_multi_init();
        $curlHandles = [];
        $results = [];
        
        // Initialize curl handles for each URL in the batch
        foreach ($batch as $index => $article) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $article['url'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_USERAGENT => self::USER_AGENT,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT => $this->config['curl_timeout'],
                CURLOPT_CONNECTTIMEOUT => $this->config['connect_timeout'],
            ]);
            curl_multi_add_handle($multiHandle, $ch);
            $curlHandles[$index] = $ch;
        }
        
        // Execute the handles with improved performance
        $active = null;
        do {
            $status = curl_multi_exec($multiHandle, $active);
            
            if ($active > 0) {
                curl_multi_select($multiHandle, 1.0);
            }
        } while ($active > 0 && $status == CURLM_OK);
        
        // Get content and clean up
        foreach ($curlHandles as $index => $ch) {
            $html = curl_multi_getcontent($ch);
            $error = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            
            if ($error || $httpCode >= 400) {
                error_log("cURL Error for {$batch[$index]['url']}: " . ($error ?: "HTTP {$httpCode}"));
                $results[] = [
                    'first_href' => $batch[$index]['url'],
                    'country_text' => $batch[$index]['country_text'],
                    'time_value' => $batch[$index]['time_value'],
                    'input_value' => null,
                    'country_from_pre' => null,
                    'error' => $error ?: "HTTP {$httpCode}"
                ];
            } else {
                $articleData = $this->parseArticleDetailPage($html);
                $results[] = [
                    'first_href' => $batch[$index]['url'],
                    'country_text' => $batch[$index]['country_text'],
                    'time_value' => $batch[$index]['time_value'],
                    'input_value' => $articleData['input_value'],
                    'country_from_pre' => $articleData['country_code'] ?? $this->getCountryCode($batch[$index]['country_text']),
                ];
            }
            
            curl_multi_remove_handle($multiHandle, $ch);
            curl_close($ch);
        }
        
        curl_multi_close($multiHandle);
        return $results;
    }
    
    /**
     * Parses the HTML of a single article's detail page.
     */
    private function parseArticleDetailPage(string $html): array
    {
        if (empty($html)) {
            return ['input_value' => null, 'country_code' => null];
        }
        
        libxml_use_internal_errors(true);
        $this->dom->loadHTML($html);
        libxml_clear_errors();
        
        $xpath = new DOMXPath($this->dom);
        $inputNode = $xpath->query('//input[@id="pp2"]')->item(0);
        $inputValue = $inputNode ? $inputNode->getAttribute('value') : null;
        
        $preNode = $xpath->query('//pre')->item(0);
        $countryCode = null;
        
        if ($preNode) {
            preg_match('/Country:\s*([A-Z]{2})/', $preNode->textContent, $matches);
            $countryCode = $matches[1] ?? null;
        }
        
        return ['input_value' => $inputValue, 'country_code' => $countryCode];
    }
    
    /**
     * Generates a standardized name for a proxy configuration.
     */
    private function generateProxyName(array $enrichedData): string
    {
        $format = $this->config['name_format'];
        
        // Prepare replacements
        $replacements = [
            '{flag}' => $enrichedData['flag'],
            '{country}' => $enrichedData['country_code'],
            '{type}' => strtoupper($enrichedData['type'] ?? 'unknown'),
            '{id}' => $this->proxyCounter++,
            '{random}' => getRandomName(4),
            '{server}' => $this->getShortServerName($enrichedData),
            '{port}' => $enrichedData['parsed']['port'] ?? '',
        ];
        
        // Apply replacements
        $name = str_replace(array_keys($replacements), array_values($replacements), $format);
        
        // Clean up the name
        return preg_replace('/[^\w\s\-\.\p{L}]/u', '', $name);
    }
    
    /**
     * Gets a shortened version of the server name for display.
     */
    private function getShortServerName(array $enrichedData): string
    {
        $server = '';
        
        if (isset($enrichedData['parsed'])) {
            if ($enrichedData['type'] === 'vmess') {
                $server = $enrichedData['parsed']['add'] ?? '';
            } elseif ($enrichedData['type'] === 'ss') {
                $server = $enrichedData['parsed']['server_address'] ?? '';
            } else {
                $server = $enrichedData['parsed']['hostname'] ?? '';
            }
        }
        
        // If it's an IP address, just return the last octet
        if (filter_var($server, FILTER_VALIDATE_IP)) {
            $parts = explode('.', $server);
            return end($parts);
        }
        
        // For domain names, return the first part before the first dot
        $parts = explode('.', $server);
        return $parts[0] ?? '';
    }
    
    /**
     * Enriches proxy data with additional information.
     */
    private function enrichProxyData(string $inputValue, ?string $countryFromPre): array
    {
        $enriched = [
            'input_value' => $inputValue,
            'country_from_pre' => $countryFromPre,
            'type' => null,
            'parsed' => null,
            'is_encrypted' => false,
            'country_code' => $countryFromPre ?? 'XX',
            'flag' => '🏳️',
            'is_cloudflare' => false,
            'valid' => false,
        ];

        // Detect the type
        $type = detect_type($inputValue);
        $enriched['type'] = $type;

        // Parse the configuration
        $parsed = configParse($inputValue);
        if ($parsed === null) {
            return $enriched; // Invalid configuration
        }

        $enriched['valid'] = true;
        $enriched['parsed'] = $parsed;

        // Check encryption
        $enriched['is_encrypted'] = isEncrypted($inputValue);

        // Get the server address (hostname or IP)
        $server = '';
        if ($type === 'vmess') {
            $server = $parsed['add'] ?? '';
        } elseif ($type === 'ss') {
            $server = $parsed['server_address'] ?? '';
        } else {
            $server = $parsed['hostname'] ?? '';
        }

        // If we have a server and no country from pre, try to get country from server
        if ($server && empty($countryFromPre)) {
            // Check if server is an IP
            if (is_ip($server)) {
                // Check if it's Cloudflare
                $enriched['is_cloudflare'] = is_cloudflare_ip($server);
                if ($enriched['is_cloudflare']) {
                    $enriched['country_code'] = 'CF';
                } else {
                    // Get geolocation
                    $geo = ip_info($server);
                    $enriched['country_code'] = $geo->country ?? 'XX';
                }
            } else {
                // It's a hostname, resolve and get geo
                $geo = ip_info($server);
                $enriched['country_code'] = $geo->country ?? 'XX';
                // Also check if the resolved IP is Cloudflare
                if ($enriched['country_code'] === 'CF') {
                    $enriched['is_cloudflare'] = true;
                }
            }
        }

        // Get the flag emoji
        $enriched['flag'] = getFlags($enriched['country_code']);

        return $enriched;
    }
    
    /**
     * Saves the final results to multiple categorized files.
     */
    private function saveResults(array $results): void
    {
        // Enrich data with additional information
        $enrichedResults = [];
        $renamedConfigs = [];
        
        // Categorized storage
        $byType = [];
        $byCountry = [];
        $byTypeAndCountry = [];
        
        foreach ($results as $result) {
            if (!empty($result['input_value'])) {
                $enrichedData = $this->enrichProxyData($result['input_value'], $result['country_from_pre']);
                
                // Only rename valid configurations
                if ($enrichedData['valid']) {
                    $newName = $this->generateProxyName($enrichedData);
                    $type = $enrichedData['type'];
                    $country = $enrichedData['country_code'];
                    $parsedConfig = $enrichedData['parsed'];
                    
                    // Update the name in the parsed configuration
                    switch ($type) {
                        case 'vmess':
                            $parsedConfig['ps'] = $newName;
                            break;
                        case 'ss':
                            $parsedConfig['name'] = $newName;
                            break;
                        default: // vless, trojan, tuic, hy2
                            $parsedConfig['hash'] = $newName;
                            break;
                    }
                    
                    // Rebuild the configuration string with the new name
                    $newConfigString = reparseConfig($parsedConfig, $type);
                    
                    // Update the enriched data
                    $enrichedData['input_value'] = $newConfigString;
                    $enrichedData['parsed'] = $parsedConfig;
                    $enrichedData['new_name'] = $newName;
                    
                    // Add to renamed configs for subscription
                    $renamedConfigs[] = $newConfigString;
                    
                    // Categorize
                    $byType[$type][] = $enrichedData;
                    $byCountry[$country][] = $enrichedData;
                    $byTypeAndCountry[$type][$country][] = $enrichedData;
                }
                
                $enrichedResults[] = array_merge($result, ['enriched_data' => $enrichedData]);
            }
        }
        
        // Save the detailed JSON output (original format)
        $jsonOutput = json_encode($enrichedResults, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        if (file_put_contents("api.json", $jsonOutput) === false) {
            throw new Exception("Failed to write to api.json");
        }
        
        // Generate and save the Base64 subscription link with renamed configs
        if (!empty($renamedConfigs)) {
            $output = implode("\n", $renamedConfigs);
            if (file_put_contents("sub-link.txt", base64_encode($output)) === false) {
                throw new Exception("Failed to write to sub-link.txt");
            }
        }
        
        // Save categorized files if configured to do so
        if ($this->config['output_format'] === 'categorized') {
            $this->saveCategorizedFiles($byType, $byCountry, $byTypeAndCountry);
        }
    }
    
    /**
     * Saves categorized files to the output directory.
     */
    private function saveCategorizedFiles(array $byType, array $byCountry, array $byTypeAndCountry): void
    {
        // Save by type
        foreach ($byType as $type => $proxies) {
            $typeDir = self::OUTPUT_DIR . "/by-type/{$type}";
            if (!is_dir($typeDir)) {
                mkdir($typeDir, 0755, true);
            }
            
            $configStrings = array_column($proxies, 'input_value');
            $fileContent = implode("\n", $configStrings);
            
            $filename = "{$typeDir}/{$type}.txt";
            if (file_put_contents($filename, $fileContent) === false) {
                throw new Exception("Failed to write to {$filename}");
            }
            
            // Also save as JSON
            $jsonContent = json_encode($proxies, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            $jsonFilename = "{$typeDir}/{$type}.json";
            if (file_put_contents($jsonFilename, $jsonContent) === false) {
                throw new Exception("Failed to write to {$jsonFilename}");
            }
        }
        
        // Save by country
        foreach ($byCountry as $country => $proxies) {
            $countryDir = self::OUTPUT_DIR . "/by-country/{$country}";
            if (!is_dir($countryDir)) {
                mkdir($countryDir, 0755, true);
            }
            
            $configStrings = array_column($proxies, 'input_value');
            $fileContent = implode("\n", $configStrings);
            
            $filename = "{$countryDir}/{$country}.txt";
            if (file_put_contents($filename, $fileContent) === false) {
                throw new Exception("Failed to write to {$filename}");
            }
            
            // Also save as JSON
            $jsonContent = json_encode($proxies, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            $jsonFilename = "{$countryDir}/{$country}.json";
            if (file_put_contents($jsonFilename, $jsonContent) === false) {
                throw new Exception("Failed to write to {$jsonFilename}");
            }
        }
        
        // Save by type and country
        foreach ($byTypeAndCountry as $type => $countries) {
            foreach ($countries as $country => $proxies) {
                $combinedDir = self::OUTPUT_DIR . "/by-type-country/{$type}";
                if (!is_dir($combinedDir)) {
                    mkdir($combinedDir, 0755, true);
                }
                
                $configStrings = array_column($proxies, 'input_value');
                $fileContent = implode("\n", $configStrings);
                
                $filename = "{$combinedDir}/{$country}.txt";
                if (file_put_contents($filename, $fileContent) === false) {
                    throw new Exception("Failed to write to {$filename}");
                }
                
                // Also save as JSON
                $jsonContent = json_encode($proxies, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
                $jsonFilename = "{$combinedDir}/{$country}.json";
                if (file_put_contents($jsonFilename, $jsonContent) === false) {
                    throw new Exception("Failed to write to {$jsonFilename}");
                }
            }
        }
        
        // Create a summary file
        $summary = [
            'total_proxies' => count($byType),
            'by_type' => array_map('count', $byType),
            'by_country' => array_map('count', $byCountry),
            'by_type_and_country' => array_map(function($countries) {
                return array_map('count', $countries);
            }, $byTypeAndCountry),
            'generated_at' => date('c'),
        ];
        
        $summaryJson = json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        if (file_put_contents(self::OUTPUT_DIR . "/summary.json", $summaryJson) === false) {
            throw new Exception("Failed to write to summary.json");
        }
    }
}

// --- Main Execution ---
header("Content-Type: application/json;");

// Configuration to increase fetched configs
$config = [
    'name_format' => '{flag} {country}-{type}-{id}',
    'output_format' => 'categorized',
    
    // Increase these values to fetch more configs:
    'max_age_seconds' => 86400, // 24 hours instead of 30 minutes
    'max_concurrent_requests' => 20, // More concurrent requests
    'curl_timeout' => 30, // Longer timeout per request
    'connect_timeout' => 10, // Longer connection timeout
    'max_articles' => 100, // Maximum number of articles to process
];

$scraper = new ProxyScraper('countries.lock', $config);
$scraper->run();