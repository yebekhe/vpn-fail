<?php
// Set a default timezone to avoid potential warnings
date_default_timezone_set('UTC');
// It's better to configure this in php.ini, but for a single script, this is fine.
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/**
 * A class to scrape, process, and store proxy configurations.
 */
class ProxyScraper
{
    private const BASE_URL = "https://vpn.fail/free-proxy/type/v2ray";
    private const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
    private const MAX_AGE_SECONDS = 1800; // 30 minutes
    private const CACHE_FILE = 'proxy_cache.json';
    private const CACHE_EXPIRY = 3600; // 1 hour
    
    private array $countryCodes = [];
    private ?DOMDocument $dom = null;
    private array $config = [];
    
    /**
     * Constructor: Loads necessary data like country codes.
     */
    public function __construct(string $countryCodesFile = 'countries.lock', array $config = [])
    {
        $this->config = array_merge([
            'max_age_seconds' => self::MAX_AGE_SECONDS,
            'cache_file' => self::CACHE_FILE,
            'cache_expiry' => self::CACHE_EXPIRY,
            'curl_timeout' => 15,
            'max_concurrent_requests' => 10,
        ], $config);
        
        $this->loadCountryCodes($countryCodesFile);
        $this->dom = new DOMDocument();
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
            CURLOPT_CONNECTTIMEOUT => 5,
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
        // Normalize the input name to match the keys in the JSON file.
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
            // Set a 500 header for server errors and output a clean JSON error message.
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
        
        foreach ($articleNodes as $node) {
            $timeSpan = $xpath->query('.//div[contains(@class, "col-sm-3 text-right")]//span', $node)->item(0);
            $timeValue = $timeSpan ? (int)trim($timeSpan->textContent) : 0;
            
            // Stop processing if articles are older than the defined maximum age
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
                CURLOPT_CONNECTTIMEOUT => 5,
            ]);
            curl_multi_add_handle($multiHandle, $ch);
            $curlHandles[$index] = $ch;
        }
        
        // Execute the handles with improved performance
        $active = null;
        do {
            $status = curl_multi_exec($multiHandle, $active);
            
            // Wait for activity if there are handles still running
            if ($active > 0) {
                curl_multi_select($multiHandle, 1.0); // Wait up to 1 second
            }
        } while ($active > 0 && $status == CURLM_OK);
        
        // Get content and clean up
        foreach ($curlHandles as $index => $ch) {
            $html = curl_multi_getcontent($ch);
            $error = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            
            if ($error || $httpCode >= 400) {
                // Log error but continue processing other results
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
     * Saves the final results to JSON and Base64 encoded files.
     */
    private function saveResults(array $results): void
    {
        // Save the detailed JSON output
        $jsonOutput = json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        if (file_put_contents("api.json", $jsonOutput) === false) {
            throw new Exception("Failed to write to api.json");
        }
        
        // Generate and save the Base64 subscription link
        $output = "";
        foreach ($results as $config) {
            if (!empty($config['input_value'])) {
                $output .= $config['input_value'] . "\n";
            }
        }
        
        if (!empty($output)) {
            if (file_put_contents("sub-link.txt", base64_encode($output)) === false) {
                throw new Exception("Failed to write to sub-link.txt");
            }
        }
    }
}

// --- Main Execution ---
header("Content-Type: application/json;");

// Configuration can be passed to override defaults
$config = [
    // 'max_age_seconds' => 1800,
    // 'cache_expiry' => 3600,
    // 'max_concurrent_requests' => 10,
];

$scraper = new ProxyScraper('countries.lock', $config);
$scraper->run();