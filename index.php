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

    private array $countryCodes = [];

    /**
     * Constructor: Loads necessary data like country codes.
     */
    public function __construct(string $countryCodesFile = 'countries.lock')
    {
        $this->loadCountryCodes($countryCodesFile);
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
        $this->countryCodes = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Failed to decode country codes JSON: " . json_last_error_msg());
        }
    }

    /**
     * Fetches content from a single URL.
     * @throws Exception on cURL error.
     */
    private function fetchUrl(string $url): string
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_USERAGENT => self::USER_AGENT,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 15,
        ]);

        $content = curl_exec($ch);

        if (curl_errno($ch)) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new Exception("cURL Error for {$url}: {$error}");
        }

        curl_close($ch);
        return $content;
    }

    /**
     * Retrieves the ISO 3166-1 alpha-2 code for a given country name.
     */
    private function getCountryCode(string $countryName): string
    {
        // Normalize the input name to match the keys in the JSON file.
        $normalizedName = ucwords(strtolower($countryName));
        return $this->countryCodes[$normalizedName] ?? 'XX'; // Use null coalescing for a cleaner default.
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

            // 3. Fetch details from each article's page concurrently
            $results = $this->fetchArticleDetailsConcurrently($articles);

            // 4. Process and save the final results
            $this->saveResults($results);

            echo "Scraping completed successfully.\n";

        } catch (Exception $e) {
            // Set a 500 header for server errors and output a clean JSON error message.
            header("Content-Type: application/json;", true, 500);
            echo json_encode(['error' => $e->getMessage()]);
            exit;
        }
    }

    /**
     * Parses the main HTML to find recent articles.
     */
    private function extractInitialArticleData(string $html): array
    {
        if (empty($html)) return [];

        $dom = new DOMDocument();
        // Use internal error handling instead of the @ operator to suppress warnings
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();

        $xpath = new DOMXPath($dom);
        $articleNodes = $xpath->query('//article');
        $articles = [];
        $currentTime = time();

        foreach ($articleNodes as $node) {
            $timeSpan = $xpath->query('.//div[contains(@class, "col-sm-3 text-right")]//span', $node)->item(0);
            $timeValue = $timeSpan ? (int)trim($timeSpan->textContent) : 0;

            // Stop processing if articles are older than the defined maximum age
            if (($currentTime - $timeValue) > self::MAX_AGE_SECONDS) {
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
     * Fetches details for multiple articles concurrently using curl_multi.
     */
    private function fetchArticleDetailsConcurrently(array $articles): array
    {
        if (empty($articles)) return [];

        $multiHandle = curl_multi_init();
        $curlHandles = [];
        $results = [];

        foreach ($articles as $index => $article) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $article['url'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_USERAGENT => self::USER_AGENT,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT => 15,
            ]);
            curl_multi_add_handle($multiHandle, $ch);
            // Store the handle with its original index to map results back correctly
            $curlHandles[$index] = $ch;
        }

        // Execute the handles
        $running = null;
        do {
            curl_multi_exec($multiHandle, $running);
            curl_multi_select($multiHandle);
        } while ($running > 0);

        // Get content and clean up
        foreach ($curlHandles as $index => $ch) {
            $html = curl_multi_getcontent($ch);
            $articleData = $this->parseArticleDetailPage($html);
            
            $results[] = [
                'first_href' => $articles[$index]['url'],
                'country_text' => $articles[$index]['country_text'],
                'time_value' => $articles[$index]['time_value'],
                'input_value' => $articleData['input_value'],
                'country_from_pre' => $articleData['country_code'] ?? $this->getCountryCode($articles[$index]['country_text']),
            ];
            
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

        $dom = new DOMDocument();
        libxml_use_internal_errors(true);
        $dom->loadHTML($html);
        libxml_clear_errors();
        
        $xpath = new DOMXPath($dom);

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

        if (!empty($output) && file_put_contents("sub-link.txt", base64_encode($output)) === false) {
            throw new Exception("Failed to write to sub-link.txt");
        }
    }
}

// --- Main Execution ---
header("Content-Type: application/json;");
$scraper = new ProxyScraper('countries.lock');
$scraper->run();