# Documentation

## API Basic Information

- This `Spot Trading` document lists the REST interface's baseurl as `https://t(:spot_http_url)`.
- This `Spot Trading` document lists the REST interface's backup baseurl as `https://t(:spot_http_url_bak)`.
- This `Contract Trading` document lists the REST interface's baseurl as `https://t(:futures_http_url)`.
- This `Contract Trading` document lists the REST interface's backup baseurl as `https://t(:futures_http_url_bak)`.
- All interfaces will return a JSON, object, or array.
- If the response contains an array, the array elements are arranged in reverse chronological order, with earlier data appearing first.
- All times and timestamps are in Unix time, with units in **milliseconds**.

## Document Input Parameter Specifications

Input parameter names marked with a red <font color="red">\*</font> indicate that the parameter is mandatory; otherwise, it is optional.

The interface is case-sensitive to input parameter characters, and this will be explicitly stated in the interface.
For example, if the interface requires an uppercase trading pair name, you must input `BTCUSDT`; inputting `btcusdt` is not allowed.

The document specifies the types of input parameters, and you must input according to the specified type.
For example, the `integer` type can only accept numeric inputs;`3` is correct, but `"3"` is not allowed.

## General Interface Information

- All requests are based on the Https protocol, and the `Content-Type` in the request header must be set to:`'application/json'`.
- For `GET` method interfaces, parameters must be sent in the `query string`.
- For`POST` method interfaces, parameters must be sent in the `request body` .
- The order of parameters does not matter.

## Whether the Interface Requires Signature Verification

Interface types are divided into: public, market, trade, and account.

- Public and market-type interfaces can be accessed without an API-KEY or signature.
- Trade and account security interfaces require API-KEY and signature verification before access.
- The signature content is related to the parameters; if the parameters are input incorrectly, an error or empty value will be returned.
- Interfaces requiring signature verification must include `X-CH-SIGN`,`X-CH-APIKEY`, and `X-CH-TS` in the Header for verification.
- `X-CH-TS` (timestamp) is Unix time, in **milliseconds**.
- `X-CH-APIKEY` is the user's `apiKey`.
- `X-CH-SIGN` is the signature encryption key, which is the secretKey.The signature rules and examples can be referenced as follows: [Signature Rules](#InterfacesRequiringSignature), Signature Example(#ExampleWithRequestParameters).
- (The `apiKey`and `secretKey` in the document are virtual values; the actual content needs to be obtained by the user through the API management on the front-end page.)

| Interface Type | Authentication Type |
| :------------- | :------------------ |
| Public         | NONE                |
| Market         | NONE                |
| Trade          | TRADE               |
| Account        | USER_DATA           |

### Interface Authentication Types

- Each interface has its own authentication type, which determines what kind of authentication should be performed when accessing it.
- If an API-KEY is required, it should be passed in the HTTP header as the `X-CH-APIKEY` field.
- API-KEY and API-Secret are case-sensitive.
- You can modify the permissions of the API-KEY in the user center on the web page, such as reading account information, sending trade instructions, and sending withdrawal instructions.

| Authentication Type | Description                                           | Header                                |
| :------------------ | :---------------------------------------------------- | :------------------------------------ |
| NONE                | Interfaces that do not require authentication         |                                       |
| TRADE               | Interfaces that require a valid API-KEY and signature | `X-CH-SIGN`，`X-CH-APIKEY`，`X-CH-TS` |
| USER_DATA           | Interfaces that require a valid API-KEY and signature | `X-CH-SIGN`，`X-CH-APIKEY`，`X-CH-TS` |
| USER_STREAM         | Interfaces that require a valid API-KEY               | `X-CH-APIKEY`，`X-CH-TS`              |
| MARKET_DATA         | Interfaces that require a valid API-KEY               | `X-CH-APIKEY`，`X-CH-TS`              |

<a name="Interfaces that require signatures"></a>

### Interfaces Requiring Signature (TRADE and USER_DATA)

- When calling `TRADE` or `USER_DATA` interfaces, the signature parameter should be passed in the HTTP header as the `X-CH-SIGN` .
- `X-CH-SIGN` uses the `HMAC SHA256` encryption algorithm, with the API-Secret corresponding to the API-KEY as the key for`HMAC SHA256`.
- The `X-CH-SIGN` request header uses the （+string concatenation） of timestamp + method + requestPath + body as the object.
- The timestamp value is the same as the `X-CH-TS` request header, the method is the request method in uppercase:`GET`/`POST`.
- requestPath is the request interface path, for example:`sapi/v1/order?symbol=ethusdt&orderID=111000111`.
- `body` is the string of the request body (post only), and if it is a `GET` request, `body` can be omitted.
- The signature is case-insensitive.

### Interface Examples

Below are examples of interfaces, showing the interface format, access links, and parameter descriptions.

#### GET Example: Get Server Time

`GET https://t(:spot_http_url)/sapi/v1/time`

GET without request parameters

> Request Example

```http
GET https://t(:spot_http_url)/sapi/v1/time

// Headers
Content-Type:application/json
```

```shell
curl -X GET "https://t(:spot_http_url)/sapi/v1/time"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create URL using URI
      URI uri = new URI("https://t(:spot_http_url)/sapi/v1/time");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:spot_http_url)/sapi/v1/time"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response:", err)
		return
	}

	// Print response
	fmt.Println("Server returned:", string(body))
}
```

```python
import requests

url = "https://t(:spot_http_url)/sapi/v1/time"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
<?
$url = "https://t(:spot_http_url)/sapi/v1/time";

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if API requires)

// Execute request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:spot_http_url)/sapi/v1/time';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

> Response Example

```json
{
  "timezone": "UTC",
  "server_time": 1705039779880
}
```

**Response Parameters**

| Parameter Name | Type   | Example         | Description      |
| :------------- | :----- | :-------------- | :--------------- |
| timezone       | string | `UTC`           | Server timezone  |
| server_time    | long   | `1705039779880` | Server timestamp |

<a name="Example with request parameters"></a>

#### GET Example: Order Query

`GET https://t(:spot_http_url)/sapi/v1/order`

GET with request parameters

**Request Headers**

| Parameter Name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

**Request Parameters**

| Parameter Name                     | Type   | Description                                  |
| :--------------------------------- | :----- | :------------------------------------------- |
| orderId<font color="red">\*</font> | string | Order ID                                     |
| symbol<font color="red">\*</font>  | string | `Lowercase`trading pair name, e.g.,`ethusdt` |

**API Data**

| Key         | Value           |
| :---------- | :-------------- |
| `apiKey`    | your API-KEY    |
| `secretKey` | your API-SECRET |

The following is an example of calling the interface to place an order using echo, openssl, and curl tools in a Linux bash environment.<font color="red">(The above `apikey` and `secretKey` are for demonstration only; please replace them with your real `apiKey` and `secretKey`)</font>

> Request Example

```http
GET https://t(:spot_http_url)/sapi/v1/order?orderId=12&symbol=ethusdt

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/order"
QUERY_STRING="?orderId=12&symbol=ethusdt"

# Calculate the full request path
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate current millisecond timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET request has no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debug information**
echo "==== Request Information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (string to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/order";
            String queryString = "?orderId=12&symbol=ethusdt";

            // Calculate the full request path
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate current millisecond timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET request has no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debug information**
            System.out.println("==== Request Information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (string to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Send request and get response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/order"
	queryString := "?orderId=12&symbol=ethusdt"

	// Calculate the full request path
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate current millisecond timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET request has no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debug information**
	fmt.Println("==== Request Information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (string to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Calculate HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create a request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Settings Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API Related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/order"
QUERY_STRING = "?orderId=12&symbol=ethusdt"

# Calculate the complete request path
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET Request without body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print the response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/order";
$QUERY_STRING = "?orderId=12&symbol=ethusdt";

// Calculate the complete request path
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET Request without body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print the response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/order";
const QUERY_STRING = "?orderId=12&symbol=ethusdt";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debug information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

> HMAC-SHA256 Signature example

```http
// Switch to Node.js to view 『JavaScript code (categorized under HTTP)』
```

```shell
# Generate Signature (X-CH-SIGN) - GET Requests Have No Body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
```

```java
// HMAC-SHA256 Signature Calculation
public static String hmacSha256(String data, String secret) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    mac.init(secretKeySpec);
    byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

    StringBuilder hexString = new StringBuilder();
    for (byte b : hash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) {
            hexString.append('0');
        }
        hexString.append(hex);
    }
    return hexString.toString();
}
```

```go
// Calculate HMAC-SHA256 Signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
# Generate Signature (X-CH-SIGN) - GET Requests Have No Body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()
```

```php
// Generate Signature (X-CH-SIGN) - GET request has no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);
```

```javascript--node
// Generate Signature (X-CH-SIGN) - GET request has no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");
```

```javascript--node
// JavaScript code (categorized under HTTP)

let secretKey = pm.environment.get("SecretKey");  // Retrieve API key from environment variables
let timestampString = String(Date.now()); // Generate timestamp (accurate to milliseconds)
let method = pm.request.method; // Get request method (GET, POST, etc.)

let fullUrl = pm.request.url.toString();
let requestPath = "/"+fullUrl.split("/").slice(3).join("/"); // Get the part after `example.com`

// The X-CH-SIGN request header is composed of the string:timestamp + method + requestPath + body (where + represents string concatenation)
// The `body` is the string representation of the request payload (POST only). If it is a GET request, the `body` can be omitted.
let signPayload = timestampString + method.toUpperCase() + requestPath;
if (method.toUpperCase() === "POST") {
    let body = pm.request.body ? pm.request.body.raw : null; // Get the request body (if present)
    if (body) {
        try {
            const parsedBody = JSON.parse(body); // Attempt to parse JSON
            let bodyString = JSON.stringify(parsedBody);
            signPayload += bodyString
        } catch (e) {
            signPayload += body; // If not JSON, directly append the raw body
        }
    } else {
        console.log("POST method failed to process body data");
    }
}

//The signature uses the HMAC-SHA256 algorithm, with the API-Secret corresponding to the API-KEY as the HMAC-SHA256 key.
const crypto = require('crypto-js'); // Load the CryptoJS library.
// Calculate the signature
let signature = crypto.HmacSHA256(signPayload, secretKey).toString(crypto.enc.Hex);

// Set Headers
pm.variables.set('xChTs', timestampString);
pm.variables.set('xChSign', signature);
```

> Return example

```json
{}
```

#### POST Example: Create a Test Order

`POST https://t(:spot_http_url)/sapi/v1/order/test`

**Request Headers**

| Parameter Name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

**Request parameters**

| Parameter name | Example |
| :------------- | :------ |
| symbol         | BTCUSDT |
| side           | BUY     |
| type           | LIMIT   |
| volume         | 1       |
| price          | 9300    |

**API Data**

| Key         | Value           |
| :---------- | :-------------- |
| `apiKey`    | your API-KEY    |
| `secretKey` | your API-SECRET |

The following is an example of placing an order by calling an API in a Linux Bash environment using `echo`, `openssl`, and `curl` tools.<font color="red">(The `apikey` and `secretKey` above are for demonstration purposes only. Please replace them with your actual `apiKey` and `secretKey`.) </font>

> Request Example

```http
POST https://t(:spot_http_url)/sapi/v1/order/test

// Headers Set up
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
URL="https://t(:spot_http_url)"
REQUEST_PATH="/sapi/v1/order/test"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="POST"

# Define the request body (JSON format)
BODY_JSON='{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}'

# Generate signature (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debug information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# Send request
curl -X POST "$API_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json" \
    -d "$BODY_JSON"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.io.OutputStream;
import java.time.Instant;
import java.util.Base64;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API Relevant information
            String url = "https://t(:spot_http_url)";
            String requestPath = "/sapi/v1/order/test";
            String apiUrl = url + requestPath;
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Get the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "POST";

            // Define the request body (JSON format)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"price\":\"9300\",\"volume\":\"1\",\"side\":\"BUY\",\"type\":\"LIMIT\"}";

            // Generate signature (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debug information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // Send request
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 Signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP POST request
    public static void sendPostRequest(String apiUrl, String apiKey, String timestamp, String signature, String bodyJson) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);
            conn.setDoOutput(true);

            // Send request body
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API Relevant information
    url := "https://t(:spot_http_url)"
    requestPath := "/sapi/v1/order/test"
	apiURL := url + requestPath
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "POST"

	// Define the request body (JSON format)
	bodyJSON := `{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}`

	// Generate Signature (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debug information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// Send request
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 Signature calculation
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP POST request
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests
import json

# API-related information
URL = "https://t(:spot_http_url)"
REQUEST_PATH = "/sapi/v1/order/test"
API_URL = URL + REQUEST_PATH
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "POST"

# Define the request body (JSON format)
body_json = {
    "symbol": "BTCUSDT",
    "price": "9300",
    "volume": "1",
    "side": "BUY",
    "type": "LIMIT"
}
body_str = json.dumps(body_json, separators=(',', ':'))  # Ensure the JSON string format is correct

# Generate signature (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **Print debug information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# Send request
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API Relevant information
$url = "https://t(:spot_http_url)";
$request_path = "/sapi/v1/order/test";
$api_url = $url . $request_path;
$api_key = "your API-KEY";
$api_secret = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$method = "POST";

// Define the request body (JSON format)
$body_json = json_encode([
    "symbol" => "BTCUSDT",
    "price" => "9300",
    "volume" => "1",
    "side" => "BUY",
    "type" => "LIMIT"
], JSON_UNESCAPED_SLASHES); // Ensure the JSON format is correct

// Generate signature (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **Print debug information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// Send request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a POST request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// Execute the request and retrieve the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print the response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const URL = "https://t(:spot_http_url)";
const REQUEST_PATH = "/sapi/v1/order/test";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "POST";

// Define the request body (in JSON format)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  price: "9300",
  volume: "1",
  side: "BUY",
  type: "LIMIT",
});

// Generate signature (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **Print debug information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// Send request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": signature,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .post(API_URL, bodyJson, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });

```

> body

```json
{
  "symbol": "BTCUSDT",
  "price": "9300",
  "volume": "1",
  "side": "BUY",
  "type": "LIMIT"
}
```

> HMAC-SHA256 Signature example

```http
// Switch to Node.js to view 『JavaScript code (categorized under HTTP)』
```

```shell
# Generate X-CH-SIGN signature command
echo -n "1739520816000POST/sapi/v1/order/test{\"symbol\":\"BTCUSDT\",\"price\":\"9300\",\"volume\":\"1\",\"side\":\"BUY\",\"type\":\"LIMIT\"}" | openssl dgst -sha256 -hmac "709f1e13068f5e51123252d1e6851117"

# Generate X-CH-SIGN signature data
(stdin)= e496db94ec168f23d836d7c7be7223135e6fe6d9593e9c985a9e4017ed78a3f3
```

```java
// HMAC-SHA256 Signature calculation
public static String hmacSha256(String data, String secret) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    mac.init(secretKeySpec);
    byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    StringBuilder hexString = new StringBuilder();
    for (byte b : hash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) {
            hexString.append('0');
        }
        hexString.append(hex);
    }
    return hexString.toString();
}
```

```go
// HMAC-SHA256 Signature calculation
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
# Generate signature (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()
```

```php
// Generate signature (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);
```

```javascript--node
// Generate signature (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");
```

```javascript--node
// JavaScript Code (categorized under HTTP)

let secretKey = pm.environment.get("SecretKey");  // Get API key from environment variables
let timestampString = String(Date.now()); // Generate a timestamp (precise to milliseconds)
let method = pm.request.method; // Get the request method (GET, POST, etc.)

let fullUrl = pm.request.url.toString();
let requestPath = "/"+fullUrl.split("/").slice(3).join("/"); // Get the part after `example.com`

// The `X-CH-SIGN` header is formed by concatenating the string `timestamp + method + requestPath + body` (where `+` indicates string concatenation)
// The `body` is the request body string (for POST requests only). If it's a GET request, the body can be omitted.
let signPayload = timestampString + method.toUpperCase() + requestPath;
if (method.toUpperCase() === "POST") {
    let body = pm.request.body ? pm.request.body.raw : null; // Get the request body (if available)
    if (body) {
        try {
            const parsedBody = JSON.parse(body); // Try to parse JSON
            let bodyString = JSON.stringify(parsedBody);
            signPayload += bodyString
        } catch (e) {
            signPayload += body; // If it's not JSON, directly append the raw body
        }
    } else {
        console.log("Failed to process body data for POST method");
    }
}

// The signature uses the HMAC SHA256 algorithm, with the API-Secret corresponding to the API-KEY as the key for HMAC SHA256.
const crypto = require('crypto-js'); // Load the CryptoJS library
// Calculate the signature
let signature = crypto.HmacSHA256(signPayload, secretKey).toString(crypto.enc.Hex);

// Set up Headers
pm.variables.set('xChTs', timestampString);
pm.variables.set('xChSign', signature);
```

> Return example

```json
{}
```

## HTTP status code types

- The `HTTP 4XX` error codes are used to indicate errors in the request content, behavior, or format.
- The `HTTP 429` error code indicates a warning for exceeding the access rate limit, meaning the IP will be blocked soon.
- `HTTP 418` indicates that after receiving a `429` error, the client continued to make requests, resulting in being blocked.
- The `HTTP 5XX` error codes indicate internal server errors; this means the problem is on the server side. When handling this error, **never** treat it as a failed task because the execution status is unknown—it could be either successful or failed.
- `HTTP 504` indicates that the API server has submitted a request to the business core but has not received a response. It is important to note that the `504` code does not represent a failed request, but rather an unknown status. It is likely that the request has been executed, but it may also have failed, requiring further confirmation.
- Any API may return an ERROR. The error response `payload` is as follows:

> Return example

```json
{
  "code": -1121,
  "msg": "Invalid symbol."
}
```

For more details, refer to [Response Code Types](#response-code-types)

## Access restriction

- Each API will have a rate limit description below it.
- Violating the rate limit will result in receiving an `HTTP 429` error, which is a warning.
- When receiving an `HTTP 429` warning, the caller should reduce the access frequency or stop accessing the service.

## Time synchronization security

- The signature interfaces require the timestamp to be passed in the HTTP header with the `X-CH-TS` field. Its value should be the Unix timestamp (in milliseconds) at the time the request is sent, e.g., `1528394129373`.
- When the server receives a request, it will check the timestamp in the request. If the timestamp is older than `5000` milliseconds, the request will be considered invalid. This time window value can be customized by sending the optional parameter `recvWindow`.
- Additionally, if the server calculates that the client’s timestamp is more than one second ahead of the server’s time, the request will also be rejected.

> Java Logical Pseudocode：

```
if (timestamp < (serverTime + 1000) && (serverTime - timestamp) <= recvWindow) {
  // process request
} else {
  // reject request
}
```

<aside class="notice">Regarding Transaction Timeliness: The internet connection is not 100% reliable and cannot be fully depended on. Therefore, the latency from your local system to the exchange server will have fluctuations. This is the purpose of setting the <code>recvWindow</code>. If you are engaged in high-frequency trading and have higher requirements for transaction timeliness, you can adjust <code>recvWindow</code> flexibly to meet your needs. It is not recommended to use a <code>recvWindow</code> greater than 5 seconds.</aside>

<a name="Return Code Type"></a>

# Return Code Type

Description and Causes of Exception Codes and Error Codes

<aside class="warning">The following return content is for basic parameter validation. If the return code is not included in the return code types listed below, it indicates an error outside the business layer, and you need to contact technical personnel for resolution.</aside>

## 10XX - General Server and Network Errors

### Code:-1000 UNKNOWN

| Code | Tag     | msg                                                    | Cause                                                  |
| :--- | :------ | :----------------------------------------------------- | :----------------------------------------------------- |
| 1000 | UNKNOWN | An unknown error occurred while processing the request | An unknown error occurred while processing the request |

### Code:-1001 DISCONNECTED

| Code | Tag          | msg                                                              | Cause                                          |
| :--- | :----------- | :--------------------------------------------------------------- | :--------------------------------------------- |
| 1001 | DISCONNECTED | Internal error; unable to process your request. Please try again | Internal error; unable to process your request |

### Code:-1002 UNAUTHORIZED

| Code | Tag          | msg                                                                                                                                              | Cause                                       |
| :--- | :----------- | :----------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------ |
| 1002 | UNAUTHORIZED | You do not have permission to execute this request. The request requires an API Key. We recommend attaching `X-CH-APIKEY` in all request headers | The request header is missing `X-CH-APIKEY` |

### Code:-1003 TOO_MANY_REQUESTS

| Code | Tag               | msg                                               | Cause                                             |
| :--- | :---------------- | :------------------------------------------------ | :------------------------------------------------ |
| 1003 | TOO_MANY_REQUESTS | The request is too frequent and exceeds the limit | The request is too frequent and exceeds the limit |

### Code:-1004 NO_THIS_COMPANY

| Code | Tag             | msg                                                                     | Cause                                                                   |
| :--- | :-------------- | :---------------------------------------------------------------------- | :---------------------------------------------------------------------- |
| 1004 | NO_THIS_COMPANY | You do not have permission to execute this request. User does not exist | You do not have permission to execute this request. User does not exist |

### Code:-1006 UNEXPECTED_RESP

| Code | Tag             | msg                                                                                         | Cause                                                                                       |
| :--- | :-------------- | :------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------ |
| 1006 | UNEXPECTED_RESP | The received message does not conform to the preset format, and the order status is unknown | The received message does not conform to the preset format, and the order status is unknown |

### Code:-1007 TIMEOUT

| Code | Tag     | msg                                                                                           | Cause           |
| :--- | :------ | :-------------------------------------------------------------------------------------------- | :-------------- |
| 1007 | TIMEOUT | Timeout waiting for backend server response. Sending status unknown; execution status unknown | Request timeout |

### Code:-1014 UNKNOWN_ORDER_COMPOSITION

| Code | Tag                       | msg                           | Cause                                                                              |
| :--- | :------------------------ | :---------------------------- | :--------------------------------------------------------------------------------- |
| 1014 | UNKNOWN_ORDER_COMPOSITION | Unsupported order combination | The order combination does not exist or an incorrect order combination was entered |

### Code:-1015 TOO_MANY_ORDERS

| Code | Tag             | msg                                                      | Cause                                        |
| :--- | :-------------- | :------------------------------------------------------- | :------------------------------------------- |
| 1015 | TOO_MANY_ORDERS | Too many orders. Please reduce the number of your orders | The order quantity exceeds the maximum limit |

### Code:-1016 SERVICE_SHUTTING_DOWN

| Code | Tag                   | msg            | Cause                                                  |
| :--- | :-------------------- | :------------- | :----------------------------------------------------- |
| 1016 | SERVICE_SHUTTING_DOWN | Server offline | The server is offline and the interface is unavailable |

### Code:-1017 NO_CONTENT_TYPE

| Code | Tag             | msg                                                                                               | Cause                                        |
| :--- | :-------------- | :------------------------------------------------------------------------------------------------ | :------------------------------------------- |
| 1017 | NO_CONTENT_TYPE | We recommend attaching `Content-Type` in all request headers and setting it to `application/json` | The request header is missing `Content-Type` |

### Code:-1020 UNSUPPORTED_OPERATION

| Code | Tag                   | msg                             | Cause                                                                                                        |
| :--- | :-------------------- | :------------------------------ | :----------------------------------------------------------------------------------------------------------- |
| 1020 | UNSUPPORTED_OPERATION | This operation is not supported | An incorrect request operation was made. You need to coordinate with the technical team to resolve the issue |

### Code:-1021 INVALID_TIMESTAMP

| Code | Tag               | msg                                             | Cause                                                                                                                                                                  |
| :--- | :---------------- | :---------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1021 | INVALID_TIMESTAMP | Invalid timestamp, the time offset is too large | The timestamp offset is too large. The server determines that the client’s time is more than 1 second ahead of the server’s time based on the timestamp in the request |

### Code:-1022 INVALID_SIGNATURE

| Code | Tag               | msg               | Cause                         |
| :--- | :---------------- | :---------------- | :---------------------------- |
| 1022 | INVALID_SIGNATURE | Invalid signature | Signature verification failed |

### Code:-1023 UNAUTHORIZED

| Code | Tag          | msg                                                                                                                                           | Cause                                   |
| :--- | :----------- | :-------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------- |
| 1023 | UNAUTHORIZED | You do not have permission to execute this request. The request requires a timestamp. We recommend attaching `X-CH-TS` in all request headers | The request header is missing `X-CH-TS` |

### Code:-1024 UNAUTHORIZED

| Code | Tag          | msg                                                                                                                                        | Cause                                     |
| :--- | :----------- | :----------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------- |
| 1024 | UNAUTHORIZED | You do not have permission to execute this request. The request requires a sign. We recommend attaching `X-CH-SIGN` in all request headers | The request header is missing `X-CH-SIGN` |

## 11XX - Issue in the request content

### Code:-1100 ILLEGAL_CHARS

| Code | Tag           | msg                          | Cause                        |
| :--- | :------------ | :--------------------------- | :--------------------------- |
| 1100 | ILLEGAL_CHARS | Issue in the request content | Issue in the request content |

### Code:-1101 TOO_MANY_PARAMETERS

| Code | Tag                 | msg                      | Cause                                                                               |
| :--- | :------------------ | :----------------------- | :---------------------------------------------------------------------------------- |
| 1101 | TOO_MANY_PARAMETERS | Too many parameters sent | The parameter content is too large or duplicate parameter values have been detected |

### Code:-1102 MANDATORY_PARAM_EMPTY_OR_MALFORMED

| Code | Tag                                | msg                                                                        | Cause                                                                                          |
| :--- | :--------------------------------- | :------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------- |
| 1102 | MANDATORY_PARAM_EMPTY_OR_MALFORMED | Mandatory parameter {0} was not sent, is empty, or has an incorrect format | The parameter is empty; a required parameter was not provided or has an incorrect input format |

### Code:-1103 UNKNOWN_PARAM

| Code | Tag           | msg                           | Cause                                                                                                  |
| :--- | :------------ | :---------------------------- | :----------------------------------------------------------------------------------------------------- |
| 1103 | UNKNOWN_PARAM | An unknown parameter was sent | The parameter content or format in the request is incorrect. Please check if the fields contain spaces |

### Code:-1104 UNREAD_PARAMETERS

| Code | Tag               | msg                               | Cause                                                                             |
| :--- | :---------------- | :-------------------------------- | :-------------------------------------------------------------------------------- |
| 1104 | UNREAD_PARAMETERS | Not all sent parameters were read | Not all sent parameters were read; the parameter '%s' was read, but '%s' was sent |

### Code:-1105 PARAM_EMPTY

| Code | Tag         | msg                    | Cause                         |
| :--- | :---------- | :--------------------- | :---------------------------- |
| 1105 | PARAM_EMPTY | Parameter {0} is empty | A required parameter is empty |

### Code:-1106 PARAM_NOT_REQUIRED

| Code | Tag                | msg                                     | Cause                                       |
| :--- | :----------------- | :-------------------------------------- | :------------------------------------------ |
| 1106 | PARAM_NOT_REQUIRED | This parameter does not need to be sent | The parameter '%s' does not need to be sent |

### Code:-1111 BAD_PRECISION

| Code | Tag           | msg                                                            | Cause                                                          |
| :--- | :------------ | :------------------------------------------------------------- | :------------------------------------------------------------- |
| 1111 | BAD_PRECISION | The precision exceeds the maximum value defined for this asset | The precision exceeds the maximum value defined for this asset |

### Code:-1112 NO_DEPTH

| Code | Tag      | msg                                           | Cause                                   |
| :--- | :------- | :-------------------------------------------- | :-------------------------------------- |
| 1112 | NO_DEPTH | There are no open orders for the trading pair | The order to be canceled does not exist |

### Code:-1116 INVALID_ORDER_TYPE

| Code | Tag                | msg                | Cause              |
| :--- | :----------------- | :----------------- | :----------------- |
| 1116 | INVALID_ORDER_TYPE | Invalid order type | Invalid order type |

### Code:-1117 INVALID_SIDE

| Code | Tag          | msg                        | Cause                      |
| :--- | :----------- | :------------------------- | :------------------------- |
| 1117 | INVALID_SIDE | Invalid buy/sell direction | Invalid buy/sell direction |

### Code:-1121 BAD_SYMBOL

| Code | Tag        | msg              | Cause                                        |
| :--- | :--------- | :--------------- | :------------------------------------------- |
| 1121 | BAD_SYMBOL | Invalid contract | Incorrect trading pair name or contract name |

### Code:-1136 ORDER_QUANTITY_TOO_SMALL

| Code | Tag                      | msg                                               | Cause                                             |
| :--- | :----------------------- | :------------------------------------------------ | :------------------------------------------------ |
| 1136 | ORDER_QUANTITY_TOO_SMALL | The order quantity is less than the minimum value | The order quantity is less than the minimum value |

### Code:-1138 ORDER_PRICE_WAVE_EXCEED

| Code | Tag                     | msg                                       | Cause                                     |
| :--- | :---------------------- | :---------------------------------------- | :---------------------------------------- |
| 1138 | ORDER_PRICE_WAVE_EXCEED | The order price exceeds the allowed range | The order price exceeds the allowed range |

### Code:-1139 ORDER_NOT_SUPPORT_MARKET

| Code | Tag                      | msg                                              | Cause                                            |
| :--- | :----------------------- | :----------------------------------------------- | :----------------------------------------------- |
| 1139 | ORDER_NOT_SUPPORT_MARKET | This trading pair does not support market orders | This trading pair does not support market orders |

### Code:-1145 ORDER_NOT_SUPPORT_CANCELLATION

| Code | Tag                            | msg                                          | Cause                        |
| :--- | :----------------------------- | :------------------------------------------- | :--------------------------- |
| 1145 | ORDER_NOT_SUPPORT_CANCELLATION | The order status does not allow cancellation | The order cannot be canceled |

### Code:-1147 PRICE_VOLUME_PRESION_ERROR

| Code | Tag                        | msg                                                   | Cause                                                 |
| :--- | :------------------------- | :---------------------------------------------------- | :---------------------------------------------------- |
| 1147 | PRICE_VOLUME_PRESION_ERROR | Price or quantity precision exceeds the maximum limit | The order price or quantity exceeds the maximum limit |

## 2XXX - Other related return codes

### Code:-2013 NO_SUCH_ORDER

| Code | Tag           | msg                      | Cause                    |
| :--- | :------------ | :----------------------- | :----------------------- |
| 2013 | NO_SUCH_ORDER | The order does not exist | The order does not exist |

### Code:-2015 REJECTED_API_KEY

| Code | Tag              | msg                                          | Cause                               |
| :--- | :--------------- | :------------------------------------------- | :---------------------------------- |
| 2015 | REJECTED_API_KEY | Invalid API key, IP, or operation permission | Signature or IP verification failed |

### Code:-2016 EXCHANGE_LOCK

| Code | Tag           | msg               | Cause                        |
| :--- | :------------ | :---------------- | :--------------------------- |
| 2016 | EXCHANGE_LOCK | Trading is frozen | The user's trading is frozen |

### Code:-2017 BALANCE_NOT_ENOUGH

| Code | Tag                | msg                  | Cause                                          |
| :--- | :----------------- | :------------------- | :--------------------------------------------- |
| 2017 | BALANCE_NOT_ENOUGH | Insufficient balance | The user’s account has an insufficient balance |

### Code:-2100 PARAM_ERROR

| Code | Tag         | msg             | Cause                 |
| :--- | :---------- | :-------------- | :-------------------- |
| 2100 | PARAM_ERROR | Parameter issue | Parameter input error |

### Code:-2200 ORDER_CREATE_FAILS

| Code | Tag                | msg        | Cause            |
| :--- | :----------------- | :--------- | :--------------- |
| 2200 | ORDER_CREATE_FAILS | Illegal IP | Not a trusted IP |

### Code:35

| Code | Tag | msg                           | Cause                                |
| :--- | :-- | :---------------------------- | :----------------------------------- |
| 35   |     | Order placement is prohibited | The user's trading may be restricted |

# Enumeration type

## Trading pair

| Value   | Description                                                                                                |
| :------ | :--------------------------------------------------------------------------------------------------------- |
| `base`  | Refers to the trading asset of a trading pair, specifically the asset name that appears in the front part  |
| `quote` | Refers to the pricing asset of a trading pair, specifically the asset name that appears in the latter part |

## Order status

| Value                        | Description               |
| :--------------------------- | :------------------------ |
| `New Order`                  | Create a new order        |
| `Partially Filled`           | Partially filled          |
| `Filled`                     | Fully filled              |
| `Cancelled`                  | Canceled                  |
| `To be Cancelled`            | Canceling                 |
| `Partially Filled/Cancelled` | Partially filled/Canceled |
| `REJECTED`                   | Order rejected            |

## Order type

| Value    | Description  |
| :------- | :----------- |
| `LIMIT`  | Limit order  |
| `MARKET` | Market order |

## Order direction

| Value  | Description |
| :----- | :---------- |
| `BUY`  | Buy order   |
| `SELL` | Sell order  |

## K-line interval

| Value   | Description | Example                                   |
| :------ | :---------- | :---------------------------------------- |
| `min`   | Minute      | `1min`, `5min`, `15min`, `30min`, `60min` |
| `h`     | Hour        | `1h`, `4h`                                |
| `day`   | Day         | `1day`                                    |
| `week`  | Week        | `1week`                                   |
| `month` | Month       |                                           |

# Spot trading

## Public

### Security type: None

<aside class='notice'>Public-type interfaces can be accessed freely without an API key or signature </aside>

### Test connection

`GET https://t(:spot_http_url)/sapi/v1/ping`

Test the connectivity of the REST API

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/ping

// Headers Setting
Content-Type:application/json
```

```shell
curl -X GET "https://t(:spot_http_url)/sapi/v1/ping"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:spot_http_url)/sapi/v1/ping");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read the response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:spot_http_url)/sapi/v1/ping"

	// Send a GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print the response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:spot_http_url)/sapi/v1/ping"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
<?
$url = "https://t(:spot_http_url)/sapi/v1/ping";

// Initialization cURL
$ch = curl_init();

// Settings cURL Option
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:spot_http_url)/sapi/v1/ping';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

> Return example

```json
{}
```

### Server time

`GET https://t(:spot_http_url)/sapi/v1/time`

Get server time

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/time

// Headers Setting
Content-Type:application/json
```

```shell
curl -X GET "https://t(:spot_http_url)/sapi/v1/time"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:spot_http_url)/sapi/v1/time");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Create a URL using URI.
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:spot_http_url)/sapi/v1/time"

	// Send a GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print the response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:spot_http_url)/sapi/v1/time"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
<?
$url = "https://t(:spot_http_url)/sapi/v1/time";

// Initialization cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:spot_http_url)/sapi/v1/time';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

> Return example

```json
{
  "timezone": "China Standard Time",
  "serverTime": 1705039779880
}
```

**Return parameters**

| parameter name | Type   | Example               | Description      |
| :------------- | :----- | :-------------------- | :--------------- |
| timezone       | string | `China Standard Time` | Server time zone |
| serverTime     | long   | `1705039779880`       | Server timestamp |

<a name="spot-trading-public-currency-pair-list"></a>

### Currency Pair List

`GET https://t(:spot_http_url)/sapi/v1/symbols`

Retrieve the set of currency pairs supported by the market

> Request Example

```http
GET https://t(:spot_http_url)/sapi/v1/symbols

// Headers  setting
Content-Type:application/json
```

```shell
curl -X GET "https://t(:spot_http_url)/sapi/v1/symbols"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Use URI to create URL
      URI uri = new URI("https://t(:spot_http_url)/sapi/v1/symbols");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:spot_http_url)/sapi/v1/symbols"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read response:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:spot_http_url)/sapi/v1/symbols"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request is successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
<?
$url = "https://t(:spot_http_url)/sapi/v1/symbols";

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:spot_http_url)/sapi/v1/symbols';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

> Return example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "symbols": [
      {
        "symbol": "BTCUSDT",
        "baseAsset": "BTC",
        "quoteAsset": "USDT",
        "pricePrecision": 2,
        "quantityPrecision": 5,
        "limitMoneyMin": "1",
        "limitVolumeMin": "0.00001",
        "limitVolumeMax": "100",
        "limitMoneyMax": "1000000"
      },
      {
        "symbol": "LTCUSDT",
        "baseAsset": "LTC",
        "quoteAsset": "USDT",
        "pricePrecision": 2,
        "quantityPrecision": 3,
        "limitMoneyMin": "5",
        "limitVolumeMin": "0.001",
        "limitVolumeMax": "11509.049",
        "limitMoneyMax": "9000000"
      },
      {
        "symbol": "FILUSDT",
        "baseAsset": "FIL",
        "quoteAsset": "USDT",
        "pricePrecision": 3,
        "quantityPrecision": 2,
        "limitMoneyMin": "5",
        "limitVolumeMin": "0.89",
        "limitVolumeMax": "890000",
        "limitMoneyMax": "2000000"
      },
      {
        "symbol": "DOTUSDT",
        "baseAsset": "DOT",
        "quoteAsset": "USDT",
        "pricePrecision": 3,
        "quantityPrecision": 3,
        "limitMoneyMin": "5",
        "limitVolumeMin": "0.56",
        "limitVolumeMax": "560000",
        "limitMoneyMax": "2000000"
      },
      {
        "symbol": "XLMUSDT",
        "baseAsset": "XLM",
        "quoteAsset": "USDT",
        "pricePrecision": 4,
        "quantityPrecision": 1,
        "limitMoneyMin": "5",
        "limitVolumeMin": "12",
        "limitVolumeMax": "12000000",
        "limitMoneyMax": "2000000"
      }
    ]
  }
}
```

**Return parameter**

| Parameter name    | Type       | Example   | Description                             |
| :---------------- | :--------- | :-------- | :-------------------------------------- |
| symbol            | string     | `btcusdt` | `Lowercase`currency pair name           |
| baseAsset         | string     | `BTC`     | `Base currency`                         |
| quoteAsset        | string     | `USDT`    | `Quote currency`                        |
| pricePrecision    | integer    | `6`       | Price precision                         |
| quantityPrecision | integer    | `3`       | Quantity precision                      |
| limitMoneyMin     | BigDecimal | `0.0001`  | Minimum order amount limit for orders   |
| limitVolumeMin    | BigDecimal | `0.0001`  | Minimum order quantity limit for orders |
| limitVolumeMax    | BigDecimal | `0.0001`  | Maximum order quantity limit for orders |
| limitMoneyMax     | BigDecimal | `0.0001`  | Maximum order amount limit for orders   |

## Market data

### Security type: None

<aside class='notice'>The interfaces below the market data do not require an API key or signature for free access.</aside>

### Order book

`GET https://t(:spot_http_url)/sapi/v1/depth`

Get market order book depth information

**Request parameters**

| Parameter name                    | Type    | Description                                          |
| :-------------------------------- | :------ | :--------------------------------------------------- |
| symbol<font color="red">\*</font> | string  | `Uppercase`currency pair name, for example:`BTCUSDT` |
| limit                             | integer | Default: 100; Maximum: 100                           |

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/depth?symbol=BTCUSDT&limit=100

// Headers setting
Content-Type: application/json
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/depth"
QUERY_STRING="?symbol=BTCUSDT&limit=100"

# Calculate the complete request path
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# Define request method
METHOD="GET"

# **Print debug information**
echo "==== Request information ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL"
\ -H "Content-Type: application/json"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/depth";
            String queryString = "?symbol=BTCUSDT&limit=100";

            // Calculate the full request path
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // Request method
            String method = "GET";

            // **Print debug information**
            System.out.println("==== Request information ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");

            // Send request and get response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/depth"
	queryString := "?symbol=BTCUSDT&limit=100"

	// Calculate the full request path
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// Request method
	method := "GET"

	// **Print debug information**
	fmt.Println("==== Request information ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, method)
}

// Send HTTP GET request
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/depth"
QUERY_STRING = "?symbol=BTCUSDT&limit=100"

# Calculate the complete request path
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **Print debug information**
print("==== Request information ====")
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/depth";
$QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// Calculate the complete request path
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **Print debug information**
echo "==== Request information ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
];

//Send GET request using cURL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute request and get response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/depth";
const QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// Calculate the full request path
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **Print debug information**
console.log("==== Request information ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });

```

> Return example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "time": 1764180842868,
    "bids": [
      [90058.6, 7.7918],
      [90058.59, 7.09332]
    ],
    "asks": [
      [90058.7, 4.35464],
      [90058.72, 3.95142]
    ]
  }
}
```

**Return parameter**

| Parameter name | Type  | Example                   | Description                                                                                                                                                       |
| :------------- | :---- | :------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| time           | long  | `1595563624731`           | Current timestamp                                                                                                                                                 |
| bids           | array | `[[3.9,43.1],[4.0,19.2]]` | Order book bid information, the array length is 2, index 1 is the price, type is float; index 2 is the quantity corresponding to the current price, type is float |
| asks           | array | `[[4.0,12.0],[5.1,28.0]]` | Order book ask information, the array length is 2, index 1 is the price, type is float; index 2 is the quantity corresponding to the current price, type is float |

The information corresponding to bids and asks represents all the prices in the order book and the quantities corresponding to those prices, arranged from the best price (highest bid and lowest ask) downwards

### Market Ticker

`GET https://t(:spot_http_url)/sapi/v1/ticker`

Get 24-hour price change data

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/ticker?symbol=BTCUSDT

// Set Headers
Content-Type: application/json
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/ticker"
QUERY_STRING="?symbol=BTCUSDT"

# Calculate the complete request path
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# Define request method
METHOD="GET"

# **Print debug information**
echo "==== Request information ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "Content-Type: application/json"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/ticker";
            String queryString = "?symbol=BTCUSDT";

            // Calculate the complete request path
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // Request method
            String method = "GET";

            // **Print debug information**
            System.out.println("==== Request information ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");

            // Send request and get response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/ticker"
	queryString := "?symbol=BTCUSDT"

	// Calculate the complete request path
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// Request method
	method := "GET"

	// **Print debug information**
	fmt.Println("==== Request information ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, method)
}

// Send HTTP GET request
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/ticker"
QUERY_STRING = "?symbol=BTCUSDT"

# Calculate the full request path
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **Print debug information**
print("==== Request information ====")
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/ticker";
$QUERY_STRING = "?symbol=BTCUSDT";

// Calculate the complete request path
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **Print debug information**
echo "==== Request information ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
];

// Send GET request using cURL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute request and get response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/ticker";
const QUERY_STRING = "?symbol=BTCUSDT";

// Calculate the full request path
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **Print debug information**
console.log("==== Request information ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name                    | Type   | Description                                          |
| :-------------------------------- | :----- | :--------------------------------------------------- |
| symbol<font color="red">\*</font> | string | Uppercase currency pair name, for example: `BTCUSDT` |

> Return example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "amount": 1357550713.60334,
    "high": 90267.9,
    "vol": 15520.54679,
    "last": 90253.5,
    "low": 86180.1,
    "buy": 90217.6,
    "sell": 90217.7,
    "rose": "+0.0295494912",
    "time": 1764180900000
  }
}
```

**Return parameter**

| Parameter name | Type   | Example         | Description                                                                                                   |
| :------------- | :----- | :-------------- | :------------------------------------------------------------------------------------------------------------ |
| time           | long   | `1595563624731` | Current timestamp                                                                                             |
| high           | float  | `9900.51`       | Highest price                                                                                                 |
| low            | float  | `9100.34`       | Lowest price                                                                                                  |
| last           | float  | `9211.60`       | Latest trade price                                                                                            |
| vol            | float  | `4691.0`        | Trading volume                                                                                                |
| amount         | float  | `22400.0`       | Transaction Amount                                                                                            |
| buy            | float  | `9210.0`        | Bid price                                                                                                     |
| sell           | float  | `9213.0`        | Ask price                                                                                                     |
| rose           | string | `+0.05`         | Price change percentage,`+`indicates an increase,`-`indicates a decrease, and `+0.05`indicates a`5%` increase |

### Market Ticker-V2

`GET https://t(:spot_http_url)/v2/public/ticker`

Get 24-hour price change data

> Request example

```http
GET https://t(:spot_http_url)/v2/public/ticker

// Set Headers
Content-Type: application/json
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/v2/public/ticker"

# Calculate the complete request path
REQUEST_PATH="${REQUEST_URL}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# Define request method
METHOD="GET"

# **Print debug information**
echo "==== Request information ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "Content-Type: application/json"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/v2/public/ticker";

            // Calculate the complete request path
            String requestPath = requestUrl;
            String fullUrl = apiUrl + requestPath;

            // Request method
            String method = "GET";

            // **Print debug information**
            System.out.println("==== Request information ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");

            // Send request and get response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/v2/public/ticker"

	// Calculate the complete request path
	requestPath := requestURL
	fullURL := apiURL + requestPath

	// Request method
	method := "GET"

	// **Print debug information**
	fmt.Println("==== Request information ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, method)
}

// Send HTTP GET request
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/v2/public/ticker"

# Calculate the full request path
REQUEST_PATH = REQUEST_URL
FULL_URL = API_URL + REQUEST_PATH

# **Print debug information**
print("==== Request information ====")
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/v2/public/ticker";

// Calculate the complete request path
$REQUEST_PATH = $REQUEST_URL;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **Print debug information**
echo "==== Request information ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
];

// Send GET request using cURL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute request and get response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/v2/public/ticker";

// Calculate the full request path
const REQUEST_PATH = REQUEST_URL;
const FULL_URL = API_URL + REQUEST_PATH;

// **Print debug information**
console.log("==== Request information ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

> Response example

```json
{
  "code": "0",
  "msg": "Succeed",
  "data": {
    "MNT_USDT": {
      "base_id": "MNT",
      "quote_volume": 3049025.662482,
      "quote_id": "USDT",
      "base_volume": 4123162.07,
      "isFrozen": 1,
      "last_price": 0.7491
    },
    "PEPE_USDT": {
      "base_id": "PEPE",
      "quote_volume": 19215044.55550406,
      "quote_id": "USDT",
      "base_volume": 2733395751472,
      "isFrozen": 1,
      "last_price": 0.00000731
    }
  },
  "message": null,
  "succ": true
}
```

**Response parameters**

| Parameter name | Type    | Example          | Description              |
| :------------- | :------ | :--------------- | :----------------------- |
| code           | string  | `0`              | Return Code              |
| msg            | string  | `Succeed`        | Return information       |
| message        | string  | `null`           | error message            |
| succ           | boolean | true             | Operation ID             |
| data           | object  |                  |                          |
| base_id        | string  | `MNT`            | Trading Currency         |
| quote_id       | string  | `USDT`           | Denominated currency     |
| base_volume    | float   | `4123162.07`     | Trading Volume           |
| quote_volume   | float   | `3049025.662482` | Transaction Amount       |
| last_price     | float   | `0.7491`         | Latest transaction price |
| isFrozen       | number  | `1`              | Freeze flag              |

<a name="Spot Trading - Market - Latest Trades"></a>

### Recent transactions

`GET https://t(:spot_http_url)/sapi/v1/trades`

Get recent transaction data

> Request Example

```http
GET https://t(:spot_http_url)/sapi/v1/trades?symbol=BTCUSDT&limit=10

// Headers Setup
Content-Type: application/json
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/trades"
QUERY_STRING="?symbol=BTCUSDT&limit=10"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# Define the request method
METHOD="GET"

# **Print debugging information**
echo "==== Request information ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "Content-Type: application/json"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/trades";
            String queryString = "?symbol=BTCUSDT&limit=10";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // Request method
            String method = "GET";

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Sending a GET request
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");

            // Send request and get response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/trades"
	queryString := "?symbol=BTCUSDT&limit=10"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// Request method
	method := "GET"

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, method)
}

// Send HTTP GET request
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/trades"
QUERY_STRING = "?symbol=BTCUSDT&limit=10"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **Print debugging information**
print("==== Request information ====")
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/trades";
$QUERY_STRING = "?symbol=BTCUSDT&limit=10";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **Print debugging information**
echo "==== Request information ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/trades";
const QUERY_STRING = "?symbol=BTCUSDT&limit=10";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **Print debugging information**
console.log("==== Request information ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name                    | Type   | Description                                                 |
| :-------------------------------- | :----- | :---------------------------------------------------------- |
| symbol<font color="red">\*</font> | string | `Capitalize` the currency pair name, for example: `BTCUSDT` |
| limit                             | string | Default: 100; Maximum: 1000                                 |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": [
    {
      "side": "BUY",
      "price": 90310.4,
      "qty": 0.06466,
      "time": 1764181079236
    },
    {
      "side": "BUY",
      "price": 90305.6,
      "qty": 0.51622,
      "time": 1764181078271
    }
  ]
}
```

**Response parameters**

| Parameter name | Type   | Example                | Description            |
| :------------- | :----- | :--------------------- | :--------------------- |
| price          | float  | `131.0000000000000000` | Trading price          |
| time           | long   | `1704788645416`        | Current timestamp      |
| qty            | float  | `0.1000000000000000`   | Quantity (contracts)   |
| side           | string | `buy/sell`             | Active order direction |

### K-line/Candlestick data

`GET https://t(:spot_http_url)/sapi/v1/klines`

Get K-line data

> Request Example

```http
GET https://t(:spot_http_url)/sapi/v1/klines?symbol=BTCUSDT&interval=1min&limit=5

// request headers
Content-Type: application/json
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/klines"
QUERY_STRING="?symbol=BTCUSDT&interval=1min&limit=5"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# Define the request method
METHOD="GET"

# **Print debugging information**
echo "==== Request information ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send HTTP GET request
curl -X GET "$FULL_URL" \
    -H "Content-Type: application/json"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/klines";
            String queryString = "?symbol=BTCUSDT&interval=1min&limit=5";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // Request method
            String method = "GET";

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");

            // Send request and get response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/klines"
	queryString := "?symbol=BTCUSDT&interval=1min&limit=5"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// Request method
	method := "GET"

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, method)
}

// Send HTTP GET request
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/klines"
QUERY_STRING = "?symbol=BTCUSDT&interval=1min&limit=5"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **Print debugging information**
print("==== Request information ====")
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/klines";
$QUERY_STRING = "?symbol=BTCUSDT&interval=1min&limit=5";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **Print debugging information**
echo "==== Request information ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send HTTP GET request
$headers = [
    "Content-Type: application/json",
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/klines";
const QUERY_STRING = "?symbol=BTCUSDT&interval=1min&limit=5";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **Print debugging information**
console.log("==== Request information ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name                      | Type    | Description                                                                                                                                                      |
| :---------------------------------- | :------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| symbol<font color="red">\*</font>   | string  | `Uppercase` trading pair name, e.g., `BTCUSDT`                                                                                                                   |
| interval<font color="red">\*</font> | string  | K-line chart interval, acceptable values:`1min`,`5min`,`15min`,`30min`,`60min`,`1day`,`1week`,`1month` (min = minutes, day = days, week = weeks, month = months) |
| limit                               | integer | Default: 100; Maximum: 300                                                                                                                                       |

> Return example

```json
{
  "code": 0,
  "msg": "Success",
  "data": [
    {
      "high": 87754.2,
      "vol": 13.29173,
      "low": 87694.4,
      "idx": 1764175260000,
      "close": 87719.7,
      "open": 87739.7
    },
    {
      "high": 87723.1,
      "vol": 8.95014,
      "low": 87687.3,
      "idx": 1764175320000,
      "close": 87723.1,
      "open": 87719.7
    }
  ]
}
```

**Response parameters**

| Parameter name | Type  | Example         | Description     |
| :------------- | :---- | :-------------- | :-------------- |
| idx            | long  | `1538728740000` | Start timestamp |
| open           | float | `6129.41`       | Opening price   |
| close          | float | `6225.63`       | Closing price   |
| high           | float | `6228.77`       | Highest price   |
| low            | float | `6220.13`       | Lowest price    |
| vol            | float | `2456.11`       | Trading volume  |

## Trade

### Security type: TRADE

<aside class='notice'>All trading-related endpoints below require signature and API-key authentication.</aside>

### Create a new order

`POST https://t(:spot_http_url)/sapi/v1/order`

**Rate limit: 100 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:spot_http_url)/sapi/v1/order

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
URL="https://t(:spot_http_url)"
REQUEST_PATH="/sapi/v1/order"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="POST"

# Define request body (JSON format)
BODY_JSON='{"symbol":"BTCUSDT","volume":0.00001,"side":"BUY","type":"LIMIT","price":97081.19,"newClientOrderId":"111000000111"}'

# Generate signature (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# Send request
curl -X POST "$API_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json" \
    -d "$BODY_JSON"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.io.OutputStream;
import java.time.Instant;
import java.util.Base64;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String url = "https://t(:spot_http_url)";
            String requestPath = "/sapi/v1/order";
            String apiUrl = url + requestPath;
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Get the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method and path
            String method = "POST";

            // Define the request body (JSON format)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"volume\":\"0.00001\",\"side\":\"BUY\",\"type\":\"LIMIT\",\"price\":\"97081.19\",\"newClientOrderId\":\"111000000111\"}";

            // Generate signature (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // Send request
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 Signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP POST request
    public static void sendPostRequest(String apiUrl, String apiKey, String timestamp, String signature, String bodyJson) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);
            conn.setDoOutput(true);

            // Send request body
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
    url := "https://t(:spot_http_url)"
    requestPath := "/sapi/v1/order"
	apiURL := url + requestPath
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method and path
	method := "POST"

	// Define the request body (JSON format)
	bodyJSON := `{"symbol":"BTCUSDT","volume":"0.00001","side":"BUY","type":"LIMIT","price":"97081.19","newClientOrderId":"111000000111"}`

	// Generate signature (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// Send request
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 Signature calculation
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP POST request
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests
import json

# API-related information
URL = "https://t(:spot_http_url)"
REQUEST_PATH = "/sapi/v1/order"
API_URL = URL + REQUEST_PATH
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method and path
METHOD = "POST"


# Define the request body (JSON format)
body_json = {
    "symbol": "BTCUSDT",
    "volume": "0.00001",
    "side": "BUY",
    "type": "LIMIT",
    "price": "97081.19",
    "newClientOrderId": "111000000111",
}
body_str = json.dumps(body_json, separators=(',', ':'))  # Ensure the JSON string is correctly formatted

# Generate signature (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# Send request
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$url = "https://t(:spot_http_url)";
$request_path = "/sapi/v1/order";
$api_url = $url . $request_path;
$api_key = "your API-KEY";
$api_secret = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$method = "POST";

// Define request body (JSON format)
$body_json = json_encode([
    "symbol" => "BTCUSDT",
    "price" => "9300",
    "volume" => "1",
    "side" => "BUY",
    "type" => "LIMIT"
], JSON_UNESCAPED_SLASHES); // Ensure the JSON format is correct

// Generate signature (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// Send request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a POST request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const URL = "https://t(:spot_http_url)";
const REQUEST_PATH = "/sapi/v1/order";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "POST";

// Define request body (JSON format)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  price: "9300",
  volume: "1",
  side: "BUY",
  type: "LIMIT",
});

// Generate signature (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// Send request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": signature,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .post(API_URL, bodyJson, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });

```

> body

```json
{
  "symbol": "BTCUSDT",
  "volume": 1.0,
  "side": "BUY",
  "type": "LIMIT",
  "price": 65000.0,
  "newClientOrderId": "111000000111"
}
```

**Request parameters**

| Parameter name                    | Type   | Description                                                                                                                                   |
| :-------------------------------- | :----- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| symbol<font color="red">\*</font> | string | `Uppercase` trading pair name, e.g.,`BTCUSDT`(refer to Trading Pair List for`symbol`)                                                         |
| volume<font color="red">\*</font> | number | Order quantity, with precision restrictions configured by the administrator (refer to[Trading Pair List]for `limitVolumeMin` )                |
| side<font color="red">\*</font>   | string | Order direction，`BUY/SELL`                                                                                                                   |
| type<font color="red">\*</font>   | string | Order type，`LIMIT/MARKET`                                                                                                                    |
| price                             | number | Order price, required for`LIMIT`orders, with precision restrictions configured by the administrator (refer to[Recent Transactions]for`price`) |
| newClientOrderId                  | string | Client order ID                                                                                                                               |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "orderId": "781594618796015616",
    "clientOrderId": "",
    "symbol": "ENAUSDT",
    "transactTime": 1764183478446,
    "price": 0.1,
    "origQty": 50,
    "executedQty": 0,
    "type": "LIMIT",
    "side": "BUY",
    "status": "INIT"
  }
}
```

**Response parameters**

| Parameter name | Type    | Example              | Description                                                                                                                     |
| :------------- | :------ | :------------------- | :------------------------------------------------------------------------------------------------------------------------------ |
| orderId        | long    | `781594618796015616` | Order ID (system-generated)                                                                                                     |
| clientOrderId  | string  | `213443`             | Order ID (user-generated)                                                                                                       |
| symbol         | string  | `BTCUSDT`            | `Uppercase` trading pair name                                                                                                   |
| transactTime   | integer | `1704959985403`      | Order creation timestamp                                                                                                        |
| price          | float   | `47651.29`           | Order price                                                                                                                     |
| origQty        | float   | `0.01`               | Order quantity                                                                                                                  |
| executedQty    | float   | `0`                  | Filled order quantity                                                                                                           |
| type           | string  | `LIMIT`              | Order type. Possible values:`LIMIT`(Limit Order) and`MARKET`(Market Order)                                                      |
| side           | string  | `BUY`                | Order direction. Possible values:`BUY`(Long) and`SELL`(Short).                                                                  |
| status         | string  | `NEW`                | Order status. Possible values:`New Order`(New order, no fills),`Partially Filled`(Partially filled),`Filled`(Completely filled) |

### Create a new order-V2

`POST https://t(:spot_http_url)/sapi/v2/order`

**Rate limit: 100 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:spot_http_url)/sapi/v2/order

body
{"symbol":"BTCUSDT","volume":"1.00","side":"BUY","type":"LIMIT","price":"65000.00","newClientOrderId":"111000000111"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/sapi/v2/order"

# Request body (in JSON format)
body='{"symbol":"BTCUSDT","volume":"1.00","side":"BUY","type":"LIMIT","price":"65000.00","newClientOrderId":"111000000111"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send POST request
response=$(curl -s -X POST "https://t(:spot_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:spot_http_url)";
    private static final String REQUEST_PATH = "/sapi/v2/order";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{\"symbol\":\"BTCUSDT\",\"volume\":\"1.00\",\"side\":\"BUY\",\"type\":\"LIMIT\",\"price\":\"65000.00\",\"newClientOrderId\":\"111000000111\"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

          // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

          // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data The string to be signed
     * @param secret The secret key
     * @return HMAC SHA256 signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API-KEY"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:spot_http_url)"
	RequestPath = "/sapi/v2/order"
)

func main() {
	// Get millisecond timestamp
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"symbol":"BTCUSDT","volume":"1.00","side":"BUY","type":"LIMIT","price":"65000.00","newClientOrderId":"111000000111"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send POST request.
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:spot_http_url)"
REQUEST_PATH = "/sapi/v2/order"

# Request method and request body
method = "POST"
body = {"symbol":"BTCUSDT","volume":"1.00","side":"BUY","type":"LIMIT","price":"65000.00","newClientOrderId":"111000000111"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body into a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API-KEY";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:spot_http_url)";
$requestPath = "/sapi/v2/order";

// Request method and request body
$method = "POST";
$body = json_encode([
    "symbol"=> "BTCUSDT",
    "volume"=> 1.00,
    "side"=> "BUY",
    "type"=> "LIMIT",
    "price"=> 65000.00,
    "newClientOrderId"=> "111000000111"
], JSON_UNESCAPED_SLASHES);

//Get millisecond timestamp
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Use only in the development environment; SSL verification should be enabled in the production environment

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API-KEY";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:spot_http_url)";
const REQUEST_PATH = "/sapi/v2/order";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    "symbol": "BTCUSDT",
    "volume": 1.00,
    "side": "BUY",
    "type": "LIMIT",
    "price": 65000.00,
    "newClientOrderId": "111000000111"
});

// Get millisecond timestamp
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                    | Type   | Description                                                                                                                                   |
| :-------------------------------- | :----- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| symbol<font color="red">\*</font> | string | `Uppercase` trading pair name, e.g.,`BTCUSDT`(refer to Trading Pair List for`symbol`)                                                         |
| volume<font color="red">\*</font> | number | Order quantity, with precision restrictions configured by the administrator (refer to[Trading Pair List]for `limitVolumeMin` )                |
| side<font color="red">\*</font>   | string | Order direction，`BUY/SELL`                                                                                                                   |
| type<font color="red">\*</font>   | string | Order type，`LIMIT/MARKET`                                                                                                                    |
| price                             | number | Order price, required for`LIMIT`orders, with precision restrictions configured by the administrator (refer to[Recent Transactions]for`price`) |
| newClientOrderId                  | string | Client order ID                                                                                                                               |

> Response example

```json
{
  "symbol": "ETHUSDT",
  "side": "BUY",
  "executedQty": 0,
  "orderId": ["2012274607240433332"],
  "price": 47651.29,
  "origQty": 0.01,
  "clientOrderId": "213443",
  "transactTime": 1704959985403,
  "type": "MARKET",
  "status": "NEW"
}
```

**Response parameters**

| Parameter name | Type    | Example               | Description                                                                                                                     |
| :------------- | :------ | :-------------------- | :------------------------------------------------------------------------------------------------------------------------------ |
| orderId        | long    | `2012274607240433332` | Order ID (system-generated)                                                                                                     |
| clientOrderId  | string  | `213443`              | Order ID (user-generated)                                                                                                       |
| symbol         | string  | `BTCUSDT`             | `Uppercase` trading pair name                                                                                                   |
| transactTime   | integer | `1704959985403`       | Order creation timestamp                                                                                                        |
| price          | float   | `47651.29`            | Order price                                                                                                                     |
| origQty        | float   | `0.01`                | Order quantity                                                                                                                  |
| executedQty    | float   | `0`                   | Filled order quantity                                                                                                           |
| type           | string  | `LIMIT`               | Order type. Possible values:`LIMIT`(Limit Order) and`MARKET`(Market Order)                                                      |
| side           | string  | `BUY`                 | Order direction. Possible values:`BUY`(Long) and`SELL`(Short).                                                                  |
| status         | string  | `NEW`                 | Order status. Possible values:`New Order`(New order, no fills),`Partially Filled`(Partially filled),`Filled`(Completely filled) |

### Create a test order

`POST https://t(:spot_http_url)/sapi/v1/order/test`

Create and validate a new order, but it will not be sent to the matching engine

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:spot_http_url)/sapi/v1/order/test

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
URL="https://t(:spot_http_url)"
REQUEST_PATH="/sapi/v1/order/test"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="POST"

# Define the request body (JSON format)
BODY_JSON='{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}'

# Generate signature (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# Send request
curl -X POST "$API_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json" \
    -d "$BODY_JSON"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.io.OutputStream;
import java.time.Instant;
import java.util.Base64;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String url = "https://t(:spot_http_url)";
            String requestPath = "/sapi/v1/order/test";
            String apiUrl = url + requestPath;
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Get the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "POST";

            // Define the request body (JSON format)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"price\":\"9300\",\"volume\":\"1\",\"side\":\"BUY\",\"type\":\"LIMIT\"}";

            // Generate signature (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // Send request
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 Signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP POST request
    public static void sendPostRequest(String apiUrl, String apiKey, String timestamp, String signature, String bodyJson) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);
            conn.setDoOutput(true);

            // Send request body
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
    url := "https://t(:spot_http_url)"
    requestPath := "/sapi/v1/order/test"
	apiURL := url + requestPath
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "POST"

	// Define the request body (JSON format)
	bodyJSON := `{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}`

	// Generate signature (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// Send request
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 Signature calculation
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP POST request
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests
import json

# API-related information
URL = "https://t(:spot_http_url)"
REQUEST_PATH = "/sapi/v1/order/test"
API_URL = URL + REQUEST_PATH
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "POST"

# Define the request body (JSON format)
body_json = {
    "symbol": "BTCUSDT",
    "price": "9300",
    "volume": "1",
    "side": "BUY",
    "type": "LIMIT"
}
body_str = json.dumps(body_json, separators=(',', ':'))  # Ensure the JSON string format is correct

# Generate signature (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# Send request
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$url = "https://t(:spot_http_url)";
$request_path = "/sapi/v1/order/test";
$api_url = $url . $request_path;
$api_key = "your API-KEY";
$api_secret = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$method = "POST";

// Define the request body (JSON format)
$body_json = json_encode([
    "symbol" => "BTCUSDT",
    "price" => "9300",
    "volume" => "1",
    "side" => "BUY",
    "type" => "LIMIT"
], JSON_UNESCAPED_SLASHES); // Ensure the JSON format is correct

// Generate signature (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// Send request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a POST request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const URL = "https://t(:spot_http_url)";
const REQUEST_PATH = "/sapi/v1/order/test";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "POST";

// Define the request body (JSON format)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  price: "9300",
  volume: "1",
  side: "BUY",
  type: "LIMIT",
});

// Generate signature (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// Send request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": signature,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .post(API_URL, bodyJson, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });

```

> body

```json
{
  "symbol": "BTCUSDT",
  "price": "9300",
  "volume": "1",
  "side": "BUY",
  "type": "LIMIT"
}
```

**Request parameters**

| Parameter name                    | Type   | Description                                                                                                                               |
| :-------------------------------- | :----- | :---------------------------------------------------------------------------------------------------------------------------------------- |
| symbol<font color="red">\*</font> | string | `Uppercase`trading pair name, such as`BTCUSDT`(refer to Trading Pair List for`symbol`)                                                    |
| volume<font color="red">\*</font> | number | Order quantity, with precision limits configured by the administrator (refer to Trading Pair List for`limitVolumeMin`)                    |
| side<font color="red">\*</font>   | string | Order direction,`BUY/SELL`                                                                                                                |
| type<font color="red">\*</font>   | string | Order type, `LIMIT/MARKET`                                                                                                                |
| price                             | number | Order price, required for`LIMIT`orders. It has precision limits configured by the administrator (refer to[Recent Transactions]for`price`) |
| newClientOrderId                  | string | Client order identifier                                                                                                                   |

> Response example

```json
{}
```

<!--

### Batch order placement

`POST https://t(:spot_http_url)/sapi/v1/batchOrders`

**Rate limit rule: 50 requests per 2 seconds, with a maximum of 10 orders per batch**

**Request headers**

| Parameter name                         | Type    | Description |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature   |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> Request example

```http
POST https://t(:spot_http_url)/sapi/v1/batchOrders

body
{
    "symbol": "ETHUSDT",
    "orders": [
        {
            "price": 2100.00,
            "volume": 1.00,
            "side": "BUY",
            "batchType": "LIMIT"
        },
        {
            "price": 2200.00,
            "volume": 2.00,
            "side": "SELL",
            "batchType": "LIMIT"
        }
    ]
}
```

**Request parameters**

| Parameter name    | Type   | Example         | Description    |
| :---------| :------| :--------------| :--------|
| symbol    | string | `ETHUSDT`      | Trading pair name |
| price     | float  | `2100.00`      | Price     |
| volume    | float  | `1.00`         | Quantity     |
| side      | string | `BUY/SELL`     | Direction     |
| batchType | string | `LIMIT/MARKET` | Type     |

> Response example

```json
{
    "ids": [
        165964665990709251,
        165964665990709252,
        165964665990709253
    ]
}
```

**Response parameters**

| Parameter name | Type  | Example | Description       |
| :------| :-----| :----| :----------|
| ids    | array |      | Order ID array |

-->

### Order query

`GET https://t(:spot_http_url)/sapi/v1/order`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/order?orderId=2618039663715064005&symbol=btcusdt

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/order"
QUERY_STRING="?orderId=2618039663715064005&symbol=btcusdt"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/order";
            String queryString = "?orderId=2618039663715064005&symbol=btcusdt";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET requests have no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 Signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP POST request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Send the request and get the response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/order"
	queryString := "?orderId=2618039663715064005&symbol=btcusdt"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET requests have no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Compute HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/order"
QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/order";
$QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/order";
const QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload String to be signed):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name                     | Type   | Description                                    |
| :--------------------------------- | :----- | :--------------------------------------------- |
| orderId<font color="red">\*</font> | string | Order ID (system-generated)                    |
| symbol<font color="red">\*</font>  | string | `Lowercase`trading pair name, such as`ethusdt` |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "orderId": "781601003987136512",
    "clientOrderId": "",
    "symbol": "enausdt",
    "price": 0.1,
    "origQty": 50,
    "executedQty": 0,
    "avgPrice": 0,
    "type": "LIMIT",
    "transactTime": 1764185000794,
    "side": "BUY",
    "status": "NEW"
  }
}
```

**Response parameters**

| Parameter name | Type   | Example              | Description                                                                                                                    |
| :------------- | :----- | :------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| orderId        | long   | `150695552109032492` | Order ID (system-generated)                                                                                                    |
| clientOrderId  | string | `213443`             | Order ID (user-generated)                                                                                                      |
| symbol         | string | `ethusdt`            | `Lowercase`trading pair name                                                                                                   |
| price          | float  | `4765.29`            | Order price                                                                                                                    |
| origQty        | float  | `1.01`               | Order quantity                                                                                                                 |
| executedQty    | float  | `0`                  | Filled order quantity                                                                                                          |
| avgPrice       | float  | `4754.24`            | The average price of the filled order                                                                                          |
| type           | string | `LIMIT`              | Order type. Possible values are:`LIMIT`(Limit Order) and`MARKET`(Market Order)                                                 |
| time           | long   | `1672274311107`      | Timestamp                                                                                                                      |
| side           | string | `BUY`                | Order direction. Possible values are:`BUY`(Buy/Long) and`SELL`(Sell/Short)                                                     |
| status         | string | `New Order`          | Order status. Possible values are:`New Order`(New order, no fills),`Partially Filled`(Partially filled),`Filled`(Fully filled) |

### Order Query-V2

`GET https://t(:spot_http_url)/sapi/v2/order`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
GET https://t(:spot_http_url)/sapi/v2/order?orderId=2618039663715064005&symbol=btcusdt

// request headers
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v2/order"
QUERY_STRING="?orderId=2618039663715064005&symbol=btcusdt"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v2/order";
            String queryString = "?orderId=2618039663715064005&symbol=btcusdt";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET requests have no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v2/order"
	queryString := "?orderId=2618039663715064005&symbol=btcusdt"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET requests have no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Compute HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v2/order"
QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v2/order";
$QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v2/order";
const QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name                     | Type   | Description                                    |
| :--------------------------------- | :----- | :--------------------------------------------- |
| orderId<font color="red">\*</font> | string | Order ID (system-generated)                    |
| symbol<font color="red">\*</font>  | string | `Lowercase`trading pair name, such as`ethusdt` |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "orderId": "781601003987136512",
    "clientOrderId": "",
    "symbol": "enausdt",
    "price": 0.1,
    "origQty": 50,
    "executedQty": 0,
    "avgPrice": 0,
    "type": "LIMIT",
    "transactTime": 1764185000794,
    "side": "BUY",
    "status": "NEW"
  }
}
```

**Response parameters**

| Parameter name | Type   | Example              | Description                                                                                                                    |
| :------------- | :----- | :------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| orderId        | long   | `150695552109032492` | Order ID (system-generated)                                                                                                    |
| clientOrderId  | string | `213443`             | Order ID (user-generated)                                                                                                      |
| symbol         | string | `ethusdt`            | `Lowercase`trading pair name                                                                                                   |
| price          | float  | `4765.29`            | Order price                                                                                                                    |
| origQty        | float  | `1.01`               | Order quantity                                                                                                                 |
| executedQty    | float  | `0`                  | Filled order quantity                                                                                                          |
| avgPrice       | float  | `4754.24`            | The average price of the filled order                                                                                          |
| type           | string | `LIMIT`              | Order type. Possible values are:`LIMIT`(Limit Order) and`MARKET`(Market Order)                                                 |
| transactTime   | long   | `1672274311107`      | Timestamp                                                                                                                      |
| side           | string | `BUY`                | Order direction. Possible values are:`BUY`(Buy/Long) and`SELL`(Sell/Short)                                                     |
| status         | string | `New Order`          | Order status. Possible values are:`New Order`(New order, no fills),`Partially Filled`(Partially filled),`Filled`(Fully filled) |

### Cancel order

`POST https://t(:spot_http_url)/sapi/v1/cancel`

**Rate limit rule: 100 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:spot_http_url)/sapi/v1/cancel

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739945835000
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 3c22ee3d2940df5e9dc5b7b862ba3d75e805e97a242f52f12fec9d16bc73e1c7
```

```shell
#!/bin/bash

# Set API-related information
URL="https://t(:spot_http_url)"
REQUEST_PATH="/sapi/v1/cancel"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="POST"

# Define the request body (JSON format)
BODY_JSON='{"symbol":"btcusdt","orderId":"2618039663715064005"}'

# Generate signature (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# Send request
curl -X POST "$API_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json" \
    -d "$BODY_JSON"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.io.OutputStream;
import java.time.Instant;
import java.util.Base64;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String url = "https://t(:spot_http_url)";
            String requestPath = "/sapi/v1/cancel";
            String apiUrl = url + requestPath;
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Get the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "POST";

            // Define the request body (JSON format)
            String bodyJson = "{\"symbol\":\"btcusdt\",\"orderId\":\"2618039663715064005\"";

            // Generate signature (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // Send request
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 Signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP POST request
    public static void sendPostRequest(String apiUrl, String apiKey, String timestamp, String signature, String bodyJson) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);
            conn.setDoOutput(true);

            // Send request body
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
    url := "https://t(:spot_http_url)"
    requestPath := "/sapi/v1/cancel"
	apiURL := url + requestPath
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "POST"

	// Define the request body (JSON format)
	bodyJSON := `{"symbol":"btcusdt","orderId":"2618039663715064005"}`

	// Generate signature (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// Send request
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 Signature calculation
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP POST request
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests
import json

# API-related information
URL = "https://t(:spot_http_url)"
REQUEST_PATH = "/sapi/v1/cancel"
API_URL = URL + REQUEST_PATH
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "POST"

# Define the request body (JSON format)
body_json = {
    "symbol": "btcusdt",
    "orderId": "2618039663715064005"
}
body_str = json.dumps(body_json, separators=(',', ':'))  # Ensure the JSON string format is correct

# Generate signature (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# Send request
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$url = "https://t(:spot_http_url)";
$request_path = "/sapi/v1/cancel";
$api_url = $url . $request_path;
$api_key = "your API-KEY";
$api_secret = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$method = "POST";

// Define the request body (JSON format)
$body_json = json_encode([
    "symbol" => "btcusdt",
    "orderId" => "2618039663715064005"
], JSON_UNESCAPED_SLASHES); // Ensure the JSON format is correct

// Generate signature (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **Print debugging information**
echo "==== Request information息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// Send request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a POST request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const URL = "https://t(:spot_http_url)";
const REQUEST_PATH = "/sapi/v1/cancel";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "POST";

// Define the request body (JSON format)
const bodyJson = JSON.stringify({
  symbol: "btcusdt",
  orderId: "2618039663715064005",
});

// Generate signature (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// Send request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": signature,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .post(API_URL, bodyJson, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });

```

> body

```json
{ "symbol": "btcusdt", "orderId": "2618039663715064005" }
```

**Request parameters**

| Parameter name                     | Type   | Description                                    |
| :--------------------------------- | :----- | :--------------------------------------------- |
| orderId<font color="red">\*</font> | string | Order ID (system-generated)                    |
| symbol<font color="red">\*</font>  | string | `Lowercase`trading pair name, such as`ethusdt` |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "orderId": "781594618796015616",
    "symbol": "enausdt",
    "status": "PENDING_CANCEL"
  }
}
```

**Response parameters**

| Parameter name | Type   | Example               | Description                   |
| :------------- | :----- | :-------------------- | :---------------------------- |
| orderId        | long   | `1938321163093079425` | Order ID (system-generated)   |
| symbol         | string | `ethusdt`             | Trading pair name             |
| status         | string | `PENDING_CANCEL`      | Order status:`PENDING_CANCEL` |

### Cancel order-V2

`POST https://t(:spot_http_url)/sapi/v2/cancel`

**Rate limit: 100 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:spot_http_url)/sapi/v2/cancel

body
{"symbol": "ethusdt","orderId": "111000111"}
```

```shell
#!/bin/bash

# API-related information
api_key="your API-KEY"
api_secret="your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/sapi/v2/cancel"

# Request body (in JSON format)
body='{"symbol": "ethusdt","orderId": "111000111"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send POST request
response=$(curl -s -X POST "https://t(:spot_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "your API-KEY";
    private static final String API_SECRET = "your API-SECRET";
    private static final String BASE_URL = "https://t(:spot_http_url)";
    private static final String REQUEST_PATH = "/sapi/v2/cancel";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{\"symbol\":\"ethusdt\",\"orderId\":\"111000111\"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "your API-KEY"
	APISecret  = "your API-SECRET"
	BaseURL    = "https://t(:spot_http_url)"
	RequestPath = "/sapi/v2/cancel"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"symbol": "ethusdt","orderId": "111000111"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"
BASE_URL = "https://t(:spot_http_url)"
REQUEST_PATH = "/sapi/v2/cancel"

# Request method and request body
method = "POST"
body = {"symbol": "ethusdt","orderId": "111000111"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "your API-KEY";
$apiSecret = "your API-SECRET";
$baseUrl = "https://t(:spot_http_url)";
$requestPath = "/sapi/v2/cancel";

// Request method and request body
$method = "POST";
$body = json_encode([
    "symbol"=> "ethusdt",
    "orderId"=> "111000111"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";
const BASE_URL = "https://t(:spot_http_url)";
const REQUEST_PATH = "/sapi/v2/cancel";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    "symbol": "ethusdt",
    "orderId": "111000111"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                     | Type   | Description                                    |
| :--------------------------------- | :----- | :--------------------------------------------- |
| orderId<font color="red">\*</font> | string | Order ID (system-generated)                    |
| symbol<font color="red">\*</font>  | string | `Lowercase`trading pair name, such as`ethusdt` |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "orderId": "781594618796015616",
    "symbol": "enausdt",
    "status": "PENDING_CANCEL"
  }
}
```

**Response parameters**

| Parameter name | Type   | Example               | Description                   |
| :------------- | :----- | :-------------------- | :---------------------------- |
| orderId        | long   | `1938321163093079425` | Order ID (system-generated)   |
| symbol         | string | `ethusdt`             | Trading pair name             |
| status         | string | `PENDING_CANCEL`      | Order status:`PENDING_CANCEL` |

### Bulk cancel orders

`POST https://t(:spot_http_url)/sapi/v1/batchCancel`

**Rate limit rule: 50 requests per 2 seconds, with a maximum of 10 orders per batch**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:spot_http_url)/sapi/v1/batchCancel

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739945835000
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 3c22ee3d2940df5e9dc5b7b862ba3d75e805e97a242f52f12fec9d16bc73e1c7
```

```shell
#!/bin/bash

# Set API-related information
URL="https://t(:spot_http_url)"
REQUEST_PATH="/sapi/v1/batchCancel"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="POST"

# Define the request body (JSON format)
BODY_JSON='{"symbol":"BTCUSDT","orderId":["111000111","111000112"]}'

# Generate signature (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# Send request
curl -X POST "$API_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json" \
    -d "$BODY_JSON"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.io.OutputStream;
import java.time.Instant;
import java.util.Base64;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String url = "https://t(:spot_http_url)";
            String requestPath = "/sapi/v1/batchCancel";
            String apiUrl = url + requestPath;
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Get the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "POST";

            // Define the request body (JSON format)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"orderId\":[\"111000111\",\"111000112\"]}";

            // Generate signature (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // Send request
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 Signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP POST request
    public static void sendPostRequest(String apiUrl, String apiKey, String timestamp, String signature, String bodyJson) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);
            conn.setDoOutput(true);

            // Send request body
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
    url := "https://t(:spot_http_url)"
    requestPath := "/sapi/v1/batchCancel"
	apiURL := url + requestPath
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "POST"

	// Define the request body (JSON format)
	bodyJSON := `{"symbol":"BTCUSDT","orderId":["111000111","111000112"]}`

	// Generate signature (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// Send request
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 Signature calculation
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP POST request
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(body))
}
```

```python
import time
import hmac
import hashlib
import requests
import json

# API-related information
URL = "https://t(:spot_http_url)"
REQUEST_PATH = "/sapi/v1/batchCancel"
API_URL = URL + REQUEST_PATH
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "POST"

# Define the request body (JSON format)
body_json = {
    "symbol": "BTCUSDT",
    "orderId": {
        111000111,
        111000112
    }
}
body_str = json.dumps(body_json, separators=(',', ':'))  # Ensure the JSON string format is correct

# Generate signature (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# Send request
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const URL = "https://t(:spot_http_url)";
const REQUEST_PATH = "/sapi/v1/batchCancel";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "POST";

// Define the request body (JSON format)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  orderId: ["111000111", "111000112"],
});

// Generate signature (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// Send request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": signature,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .post(API_URL, bodyJson, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });

```

> body

```json
{ "symbol": "BTCUSDT", "oderIds": [111000111, 111000112] }
```

**Request parameters**

| Parameter name                      | Type   | Description                                                                           |
| :---------------------------------- | :----- | :------------------------------------------------------------------------------------ |
| symbol<font color="red">\*</font>   | string | `Uppercase` trading pair name, such as `BTCUSDT`                                      |
| orderIds<font color="red">\*</font> | array  | Set of order IDs to be canceled, with ID values entered in numeric format `[123,456]` |

> Successful response data

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "success": [165964665990709251, 165964665990709252, 165964665990709253],
    "failed": [
      // 取消失败一般是因为订单不存在或订单状态已经到终态
      165964665990709250
    ]
  }
}
```

> Failed response data

```json
{} //Usually due to an incorrect order ID. Please check if the contents of `orderIds` are correct
```

### Current order

`GET https://t(:spot_http_url)/sapi/v1/openOrders`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/openOrders?symbol=btcusdt&limit=10

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/openOrders"
QUERY_STRING="?symbol=btcusdt&limit=10"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/openOrders";
            String queryString = "?symbol=btcusdt&limit=10";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET requests have no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (string to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Send the request and get the response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/openOrders"
	queryString := "?symbol=btcusdt&limit=10"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET requests have no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (string to be signed): ", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Compute HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/openOrders"
QUERY_STRING = "?symbol=btcusdt&limit=10"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/openOrders";
$QUERY_STRING = "?symbol=btcusdt&limit=10";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/openOrders";
const QUERY_STRING = "?symbol=btcusdt&limit=10";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (string to be signed): ", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name                    | Type    | Description                                      |
| :-------------------------------- | :------ | :----------------------------------------------- |
| symbol<font color="red">\*</font> | string  | `Lowercase` trading pair name, such as `ethusdt` |
| limit                             | integer | Maximum 1000                                     |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": [
    {
      "orderId": "781594618796015616",
      "symbol": "ENAUSDT",
      "price": 0.1,
      "origQty": 50,
      "executedQty": 0,
      "avgPrice": 0,
      "type": "LIMIT",
      "time": 1764183478446,
      "side": "BUY",
      "status": "NEW"
    },
    {
      "symbol": "ETHUSDT",
      "side": "BUY",
      "executedQty": "0",
      "orderId": 1938321163093078022,
      "price": "0",
      "origQty": "0.01",
      "avgPrice": "0",
      "time": 1701243281850,
      "type": "MARKET",
      "status": "NEW_"
    }
  ]
}
```

**Response parameters**

| Parameter name | Type   | Example              | Description                                                                                                                    |
| :------------- | :----- | :------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| orderId        | long   | `150695552109032492` | Order ID (system-generated)                                                                                                    |
| symbol         | string | `ETHUSDT`            | Trading pair name                                                                                                              |
| price          | float  | `4765.29`            | Order price                                                                                                                    |
| origQty        | float  | `1.01`               | Order quantity                                                                                                                 |
| executedQty    | float  | `1.01`               | Filled order quantity                                                                                                          |
| avgPrice       | float  | `4754.24`            | The average price of the filled order                                                                                          |
| type           | string | `LIMIT`              | Order type. Possible values are:`LIMIT`(Limit Order) and`MARKET`(Market Order)                                                 |
| time           | long   | `1701243281850`      | Timestamp                                                                                                                      |
| side           | string | `BUY`                | Order direction. Possible values are: BUY (Buy/Long) and SELL (Sell/Short)                                                     |
| status         | string | `New Order`          | Order status. Possible values are:`New Order`(New order, no fills),`Partially Filled`(Partially filled), Filled (Fully filled) |

### Current order-V2

`GET https://t(:spot_http_url)/sapi/v2/openOrders`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
GET https://t(:spot_http_url)/sapi/v2/openOrders?symbol=btcusdt&limit=10

// request headers
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v2/openOrders"
QUERY_STRING="?symbol=btcusdt&limit=10"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v2/openOrders";
            String queryString = "?symbol=btcusdt&limit=10";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET requests have no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v2/openOrders"
	queryString := "?symbol=btcusdt&limit=10"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET requests have no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Compute HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v2/openOrders"
QUERY_STRING = "?symbol=btcusdt&limit=10"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v2/openOrders";
$QUERY_STRING = "?symbol=btcusdt&limit=10";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v2/openOrders";
const QUERY_STRING = "?symbol=btcusdt&limit=10";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| 参数名                            | 类型    | 描述                            |
| :-------------------------------- | :------ | :------------------------------ |
| symbol<font color="red">\*</font> | string  | `小写`币对名称，例如：`ethusdt` |
| limit<font color="red">\*</font>  | integer | 最大 1000                       |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": [
    {
      "orderId": "781594618796015616",
      "symbol": "ENAUSDT",
      "price": 0.1,
      "origQty": 50,
      "executedQty": 0,
      "avgPrice": 0,
      "type": "LIMIT",
      "time": 1764183478446,
      "side": "BUY",
      "status": "NEW"
    },
    {
      "symbol": "ETHUSDT",
      "side": "BUY",
      "executedQty": "0",
      "orderId": 1938321163093078022,
      "price": "0",
      "origQty": "0.01",
      "avgPrice": "0",
      "time": 1701243281850,
      "type": "MARKET",
      "status": "NEW_"
    }
  ]
}
```

**Response parameters**

| Parameter name | Type   | Example              | Description                                                                                                                    |
| :------------- | :----- | :------------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| orderId        | long   | `150695552109032492` | Order ID (system-generated)                                                                                                    |
| symbol         | string | `ETHUSDT`            | Trading pair name                                                                                                              |
| price          | float  | `4765.29`            | Order price                                                                                                                    |
| origQty        | float  | `1.01`               | Order quantity                                                                                                                 |
| executedQty    | float  | `1.01`               | Filled order quantity                                                                                                          |
| avgPrice       | float  | `4754.24`            | The average price of the filled order                                                                                          |
| type           | string | `LIMIT`              | Order type. Possible values are:`LIMIT`(Limit Order) and`MARKET`(Market Order)                                                 |
| time           | long   | `1701243281850`      | Timestamp                                                                                                                      |
| side           | string | `BUY`                | Order direction. Possible values are: BUY (Buy/Long) and SELL (Sell/Short)                                                     |
| status         | string | `New Order`          | Order status. Possible values are:`New Order`(New order, no fills),`Partially Filled`(Partially filled), Filled (Fully filled) |

### Transaction records

`GET https://t(:spot_http_url)/sapi/v1/myTrades`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/myTrades?symbol=BTCUSDT&limit=100

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/myTrades"
QUERY_STRING="?symbol=BTCUSDT&limit=100"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/myTrades";
            String queryString = "?symbol=BTCUSDT&limit=100";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET requests have no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Send the request and get the response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/myTrades"
	queryString := "?symbol=BTCUSDT&limit=100"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET requests have no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Compute HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/myTrades"
QUERY_STRING = "?symbol=BTCUSDT&limit=100"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/myTrades";
$QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/myTrades";
const QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name                    | Type   | Description                                     |
| :-------------------------------- | :----- | :---------------------------------------------- |
| symbol<font color="red">\*</font> | string | `Uppercase` trading pair name, such as`BTCUSDT` |
| limit                             | string | Default: 100; Maximum: 1000                     |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": [
    {
      "symbol": "ENAUSDT",
      "id": 781602664387395584,
      "orderId": 781602663370088448,
      "price": 0.2812,
      "qty": 9.99,
      "time": 1764185396665,
      "isBuyer": false,
      "isMaker": false,
      "feeCoin": "USDT",
      "fee": 0.002809188,
      "userId": "10055930",
      "side": "SELL"
    },
    {
      "symbol": "ENAUSDT",
      "id": 781602630887489536,
      "orderId": 781602630773108736,
      "price": 0.2813,
      "qty": 10,
      "time": 1764185388678,
      "isBuyer": true,
      "isMaker": false,
      "feeCoin": "ENA",
      "fee": 0.01,
      "userId": "10055930",
      "side": "BUY"
    }
  ]
}
```

**Response parameters**

| Parameter name | Type    | Example               | Description                                                                            |
| :------------- | :------ | :-------------------- | :------------------------------------------------------------------------------------- |
| symbol         | string  | `ETHBTC`              | `Uppercase`currency name                                                               |
| id             | integer | `159`                 | Transaction ID                                                                         |
| bidId          | long    | `1954603951049381893` | Buyer order ID                                                                         |
| askId          | long    | `1856176838352995447` | Seller order ID                                                                        |
| price          | integer | `2334`                | Transaction price                                                                      |
| qty            | float   | `0.00004284`          | Transaction quantity                                                                   |
| time           | number  | `1701165091964`       | Transaction timestamp                                                                  |
| isBuyer        | boolean | `true`                | `true`=Buyer，`false`=Seller                                                           |
| isMaker        | boolean | `false`               | `true`=Maker，`false`=Taker                                                            |
| feeCoin        | string  | `ETH`                 | Transaction fee currency                                                               |
| fee            | number  | `0.00000000428`       | Transaction fee                                                                        |
| bidUserId      | integer | `10083`               | Buyer user UID                                                                         |
| askUserId      | integer | `10671`               | Seller user UID                                                                        |
| isSelf         | boolean | `false`               | Is it a self-trade?`true`= yes, it is a self-trade;`false`= no, it is not a self-trade |
| side           | string  | `BUY`                 | Active order direction:`BUY`/`SELL`                                                    |

## Account

### Security type: USER_DATA

<aside class="notice">The APIs under the account section require signature and API-key authentication.</aside>

### Account information (deprecated)

`GET https://t(:spot_http_url)/sapi/v1/account`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
GET https://t(:spot_http_url)/sapi/v1/account

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/account"
QUERY_STRING=""

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/account";
            String queryString = "";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET requests have no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Send the request and get the response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/account"
	queryString := ""

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET requests have no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Compute HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/v1/account"
QUERY_STRING = ""

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/account";
$QUERY_STRING = "";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET reques
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/account";
const QUERY_STRING = "";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

> Return example

```json
{
  "balances": [
    {
      "asset": "ABAT",
      "free": "10.00",
      "locked": "20.00"
    },
    {
      "asset": "DOT",
      "free": "10.00",
      "locked": "10.00"
    },
    {
      "asset": "TT",
      "free": "50.00",
      "locked": "50.00"
    }
  ]
}
```

**Response parameters**

| Parameter name | Type   | Description          |
| :------------- | :----- | :------------------- |
| balances       | array  | Account balance set. |
| asset          | string | Trading pair         |
| free           | string | Available balance    |
| locked         | string | Frozen balance       |

### Account information (recommended)

`GET https://t(:spot_http_url)/sapi/v1/account/balance`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
// Query all currencies
GET https://t(:spot_http_url)/sapi/v1/account/balance

// Query USDT, BTC, ETH
GET https://t(:spot_http_url)/sapi/v1/account/balance?symbols=USDT,BTC,ETH

// Headers Configuration
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: your API-KEY
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# Set API-related information
API_URL="https://t(:spot_http_url)"
REQUEST_URL="/sapi/v1/account/balance"
QUERY_STRING="?symbols=USDT,BTC,ETH"

# Calculate the complete request URL
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API authentication information
API_KEY="your API-KEY"
API_SECRET="your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp=$(date +%s | awk '{print $1 * 1000}')

# Define the request method
METHOD="GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **Print debugging information**
echo "==== Request information ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (String to be signed): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# Send GET request
curl -X GET "$FULL_URL" \
    -H "X-CH-SIGN: $SIGNATURE" \
    -H "X-CH-APIKEY: $API_KEY" \
    -H "X-CH-TS: $timestamp" \
    -H "Content-Type: application/json"

```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;

public class FameexApiRequest {
    public static void main(String[] args) {
        try {
            // API-related information
            String apiUrl = "https://t(:spot_http_url)";
            String requestUrl = "/sapi/v1/account/balance";
            String queryString = "?symbols=USDT,BTC,ETH";

            // Calculate the complete request URL
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API authentication information
            String apiKey = "your API-KEY";
            String apiSecret = "your API-SECRET";

            // Generate the current millisecond-level timestamp
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // Request method
            String method = "GET";

            // Generate signature (X-CH-SIGN) - GET requests have no body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **Print debugging information**
            System.out.println("==== Request information ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (String to be signed): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // Send GET request
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 signature calculation
    public static String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Send HTTP GET request
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // Set request headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // Send the request and get the response
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            Scanner scanner = new Scanner(conn.getInputStream(), StandardCharsets.UTF_8.name());
            while (scanner.hasNextLine()) {
                System.out.println(scanner.nextLine());
            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

func main() {
	// API-related information
	apiURL := "https://t(:spot_http_url)"
	requestURL := "/sapi/v1/account/balance"
	queryString := "?symbols=USDT,BTC,ETH"

	// Calculate the complete request URL
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API authentication information
	apiKey := "your API-KEY"
	apiSecret := "your API-SECRET"

	// Generate the current millisecond-level timestamp
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// Request method
	method := "GET"

	// Generate signature (X-CH-SIGN) - GET requests have no body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **Print debugging information**
	fmt.Println("==== Request information ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (String to be signed):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// Send GET request
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// Compute HMAC-SHA256 signature
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// Send HTTP GET request
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Code:", resp.StatusCode)
	fmt.Println("Response Body:", string(body))
}

```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_URL = "https://t(:spot_http_url)"
REQUEST_URL = "/sapi/account/balance"
QUERY_STRING = "?symbols=USDT,BTC,ETH"

# Calculate the complete request URL
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API authentication information
API_KEY = "your API-KEY"
API_SECRET = "your API-SECRET"

# Generate the current millisecond-level timestamp
timestamp = str(int(time.time() * 1000))

# Request method
METHOD = "GET"

# Generate signature (X-CH-SIGN) - GET requests have no body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **Print debugging information**
print("==== Request information ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (String to be signed):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# Send GET request
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# Print response
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API-related information
$API_URL = "https://t(:spot_http_url)";
$REQUEST_URL = "/sapi/v1/account/balance";
$QUERY_STRING = "?symbols=USDT,BTC,ETH";

// Calculate the complete request URL
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API authentication information
$API_KEY = "your API-KEY";
$API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Request method
$METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **Print debugging information**
echo "==== Request information ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (String to be signed): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// Send GET request
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// Use cURL to send a GET request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// Execute the request and get the response
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Print response
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API-related information
const API_URL = "https://t(:spot_http_url)";
const REQUEST_URL = "/sapi/v1/account/balance";
const QUERY_STRING = "?symbols=USDT,BTC,ETH";

// Calculate the complete request URL
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API authentication information
const API_KEY = "your API-KEY";
const API_SECRET = "your API-SECRET";

// Generate the current millisecond-level timestamp
const timestamp = Date.now().toString();

// Request method
const METHOD = "GET";

// Generate signature (X-CH-SIGN) - GET requests have no body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **Print debugging information**
console.log("==== Request information ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (String to be signed):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// Send GET request
const headers = {
  "Content-Type": "application/json",
  "X-CH-SIGN": SIGNATURE,
  "X-CH-APIKEY": API_KEY,
  "X-CH-TS": timestamp,
};

axios
  .get(FULL_URL, { headers })
  .then((response) => {
    console.log("Response Code:", response.status);
    console.log("Response Body:", response.data);
  })
  .catch((error) => {
    console.error("Error:", error.response ? error.response.data : error.message);
  });
```

**Request parameters**

| Parameter name | Type   | Description                                                                                                 |
| :------------- | :----- | :---------------------------------------------------------------------------------------------------------- |
| symbols        | string | Uppercase currency name, such as`BTC`. Supports querying multiple currencies, up to 20, separated by commas |

> Response example

```json
{
  "code": 0,
  "msg": "Success",
  "data": {
    "balances": [
      {
        "asset": "USDT",
        "free": "9.993378812",
        "locked": "0"
      },
      {
        "asset": "BTC",
        "free": "10.00",
        "locked": "20.00"
      },
      {
        "asset": "ETH",
        "free": "100.00",
        "locked": "70.00"
      }
    ]
  }
}
```

**Response parameters**

| Parameter name | Type   | Description       |
| :------------- | :----- | :---------------- |
| balances       | array  | Account balance   |
| asset          | string | Trading pair      |
| free           | string | Available balance |
| locked         | string | Frozen balance    |

# Contract trading

## Public

### Security type: None

<aside class="notice">The APIs under the public section can be freely accessed without an API key or signature.</aside>

### Test connection

`GET https://t(:futures_http_url)/fapi/v1/ping`

> Request example

```http
GET https://t(:futures_http_url)/fapi/v1/ping

// Headers Configuration
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_http_url)/fapi/v1/ping"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:futures_http_url)/fapi/v1/ping");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:futures_http_url)/fapi/v1/ping"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:futures_http_url)/fapi/v1/ping"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
$url = "https://t(:futures_http_url)/fapi/v1/ping";

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_http_url)/fapi/v1/ping';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

> Response example

```json
{}
```

**Response parameters**

{}

Test the connectivity of the REST API

### Get server time

`GET https://t(:futures_http_url)/fapi/v1/time`

> Request example

```http
GET https://t(:futures_http_url)/fapi/v1/time

// Headers Configuration
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_http_url)/fapi/v1/time"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:futures_http_url)/fapi/v1/time");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:futures_http_url)/fapi/v1/time"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:futures_http_url)/fapi/v1/time"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
$url = "https://t(:futures_http_url)/fapi/v1/time";

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_http_url)/fapi/v1/time';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

> Response example

```json
{
  "timezone": "China Standard Time",
  "serverTime": 1704962055664
}
```

**Response parameters**

| Parameter name | Type   | Example               | Description      |
| :------------- | :----- | :-------------------- | :--------------- |
| timezone       | string | `China Standard Time` | Server timezone  |
| serverTime     | long   | `1607702400000`       | Server timestamp |

### Contract list

`GET https://t(:futures_http_url)/fapi/v1/contracts`

> Request example

```http
GET https://t(:futures_http_url)/fapi/v1/contracts

// Headers Configuration
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_http_url)/fapi/v1/contracts"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:futures_http_url)/fapi/v1/contracts");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:futures_http_url)/fapi/v1/contracts"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:futures_http_url)/fapi/v1/contracts"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
$url = "https://t(:futures_http_url)/fapi/v1/contracts";

// 初始化 cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_http_url)/fapi/v1/contracts';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

> Response example

```json
[
  {
    "symbol": "E-ETC-USDT",
    "pricePrecision": 3,
    "side": 1,
    "maxMarketVolume": 200000,
    "multiplier": 1.0,
    "minOrderVolume": 1,
    "maxMarketMoney": 500000.0,
    "type": "E",
    "maxLimitVolume": 300000,
    "maxValidOrder": 10,
    "multiplierCoin": "ETC",
    "minOrderMoney": 1.0,
    "maxLimitMoney": 500000.0,
    "status": 1
  },
  {
    "symbol": "E-ATOM-USDT",
    "pricePrecision": 3,
    "side": 1,
    "maxMarketVolume": 100000,
    "multiplier": 1.0,
    "minOrderVolume": 1,
    "maxMarketMoney": 200000.0,
    "type": "E",
    "maxLimitVolume": 200000,
    "maxValidOrder": 10,
    "multiplierCoin": "ATOM",
    "minOrderMoney": 20.0,
    "maxLimitMoney": 2000000.0,
    "status": 1
  }
]
```

**Response parameters**

| Parameter name  | Type   | Example                   | Description                                                                                 |
| :-------------- | :----- | :------------------------ | :------------------------------------------------------------------------------------------ |
| symbol          | string | `E-BTC-USDT`              | `Uppercase`contract name                                                                    |
| pricePrecision  | number | `3`                       | Price precision                                                                             |
| status          | number | `1`                       | Contract status (0:`Not tradable`, 1:`Tradable`)                                            |
| type            | string | `E`                       | Contract type (E:`Perpetual contract`, S:`Simulated contract`, others are`Hybrid contract`) |
| side            | number | `1`                       | Contract direction (0:`Inverse`, 1:`Linear`)                                                |
| multiplier      | number | `1.0000000000000000`      | Contract nominal value                                                                      |
| minOrderVolume  | number | `1`                       | Minimum order quantity                                                                      |
| minOrderMoney   | number | `1.0000000000000000`      | Minimum order amount                                                                        |
| maxMarketVolume | number | `200000`                  | Maximum order quantity for market orders                                                    |
| maxMarketMoney  | number | `500000.0000000000000000` | Maximum order amount for market orders                                                      |
| maxLimitVolume  | number | `300000`                  | Maximum order quantity for limit orders                                                     |
| maxLimitMoney   | number | `500000.0000000000000000` | Maximum order amount for limit orders                                                       |
| maxValidOrder   | number | `10`                      | Maximum number of active orders allowed                                                     |

## Market data

### Security type: None

<aside class="notice">APIs under the market section can be freely accessed without an API key or signature</aside>

### Order book

`GET https://t(:futures_http_url)/fapi/v1/depth`

Market order book depth information

> Request example

```http
GET https://t(:futures_http_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100

// Headers Configuration
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_http_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:futures_http_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:futures_http_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:futures_http_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
$url = "https://t(:futures_http_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100";

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_http_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

**Request parameters**

| Parameter name                          | Type    | Description                                   |
| :-------------------------------------- | :------ | :-------------------------------------------- |
| contractName<font color="red">\*</font> | string  | `Uppercase`contract name, such as`E-BTC-USDT` |
| limit                                   | integer | Default: 100; Maximum: 100                    |

> Response example

```json
{
  "time": 1704962463000,
  "bids": [
    [
      3.9, //Price
      16.1 //Quantity
    ],
    [4.0, 29.3]
  ],
  "asks": [
    [
      4.000002, //Price
      12.0 //Quantity
    ],
    [5.1, 28.0]
  ]
}
```

**Response parameters**

| Parameter name | Type | Example                          | Description                                                                                                                                                             |
| :------------- | :--- | :------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| time           | long | `1595563624731`                  | Current timestamp                                                                                                                                                       |
| bids           | list | `[[3.9,16.1],[4.0,29.3]]`        | Order book bid information, where the first element is the price (type: float), and the second element is the quantity corresponding to the current price (type: float) |
| asks           | list | `[[4.00000200,12.0],[5.1,28.0]]` | Order book ask information, where the first element is the price (type: float), and the second element is the quantity corresponding to the current price (type: float) |

The information corresponding to bids and asks represents all the prices and their associated quantities in the order book, arranged from the best price downwards

### Market Ticker

`GET https://t(:futures_http_url)/fapi/v1/ticker`

24-hour price change data

> Request example

```http
GET https://t(:futures_http_url)/fapi/v1/ticker?contractName=E-BTC-USDT

// Headers Configuration
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_http_url)/fapi/v1/ticker?contractName=E-BTC-USDT"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:futures_http_url)/fapi/v1/ticker?contractName=E-BTC-USDT");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:futures_http_url)/fapi/v1/ticker?contractName=E-BTC-USDT"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:futures_http_url)/fapi/v1/ticker?contractName=E-BTC-USDT"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
$url = "https://t(:futures_http_url)/fapi/v1/ticker?contractName=E-BTC-USDT";

// Initialize cURL
$ch = curl_init();

// Skip SSL certificate verification (if required by the API)
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_http_url)/fapi/v1/ticker?contractName=E-BTC-USDT';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

**Request parameters**

| Parameter name                          | Type   | Description                                   |
| :-------------------------------------- | :----- | :-------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, such as`E-BTC-USDT` |

> Return example

```json
{
  "high": 56120.22,
  "vol": 51.21,
  "last": 55989.93,
  "low": 55982.24,
  "buy": 55988.1,
  "sell": 55990.1,
  "rose": "+0.05",
  "time": 1704966225000
}
```

**Response parameters**

| Parameter name | Type   | Example         | Description                                                                                             |
| :------------- | :----- | :-------------- | :------------------------------------------------------------------------------------------------------ |
| time           | long   | `1595563624731` | Timestamp                                                                                               |
| high           | float  | `56120.22`      | Highest price                                                                                           |
| low            | float  | `55982.24`      | Lowest price                                                                                            |
| last           | float  | `55989.93`      | Latest price                                                                                            |
| vol            | float  | `51.21`         | Trading volume                                                                                          |
| rose           | string | `+0.05`         | Price change percentage.`+`indicates an increase,`-`indicates a decrease, and`+0.05`means a`5%`increase |
| buy            | float  | `55988.10`      | Buy price (highest bid price)                                                                           |
| sell           | float  | `55990.10`      | Sell price (lowest ask price)                                                                           |

### Market Ticker-V2

`GET https://t(:futures_http_url)/swap-api/v2/tickers`

Get 24-hour price change data

> Request example

```http
GET https://t(:futures_http_url)/swap-api/v2/tickers

// request headers
Content-Type:application/json
```

> Return example

```json
[
  {
    "base_currency": "ETH",
    "open_interest_usd": "3158506.047",
    "quote_volume": "475254656162",
    "base_volume": "2135453.51",
    "open_interest": "1372.13",
    "index_price": "2302.705",
    "basis": "0.0003",
    "quote_currency": "USDT",
    "ticker_id": "ETH-USDT",
    "funding_rate": "0.0000632068687814",
    "high": "2318.84",
    "product_type": "Perpetual",
    "low": "2160.71",
    "ask": "2301.96",
    "next_funding_rate_timestam": 1741248000000,
    "bid": "2301.8",
    "last_price": "2301.9"
  }
]
```

**Return parameter**

| Name                       | Type   | Example              | Description              |
| :------------------------- | :----- | :------------------- | :----------------------- |
| ticker_id                  | string | `ETH-USDT`           | Trading Pairs            |
| product_type               | string | `Perpetual`          | Contract Type            |
| base_currency              | string | `ETH`                | Trading Currency         |
| quote_currency             | string | `USDT`               | Denominated currency     |
| last_price                 | float  | `2301.9`             | Latest transaction price |
| index_price                | float  | `2302.705`           | Index Price              |
| base_volume                | float  | `2135453.51`         | Trading Volume           |
| quote_volume               | string | `475254656162`       | Transaction Amount       |
| bid                        | float  | `2301.8`             | Buy one price            |
| ask                        | float  | `2301.96`            | Selling price            |
| high                       | float  | `2318.84`            | Highest Price            |
| low                        | float  | `2160.71`            | Lowest Price             |
| open_interest              | float  | `1372.13`            | Number of open positions |
| open_interest_usd          | float  | `3158506.047`        | Opening amount           |
| basis                      | float  | `0.0003`             | Basis                    |
| funding_rate               | float  | `0.0000632068687814` | Funding Rate             |
| next_funding_rate_timestam | float  | `1741248000000`      | Next funding rate time   |

### Get index/mark price

`GET` `https://t(:futures_http_url)/fapi/v1/index`

> Request example

```http
GET https://t(:futures_http_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100

// Headers Configuration
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_http_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:futures_http_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:futures_http_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:futures_http_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
$url = "https://t(:futures_http_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100";

// Initialize cURL
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_http_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

**Request parameters**

| Parameter name                          | Type   | Description                                   |
| :-------------------------------------- | :----- | :-------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, such as`E-BTC-USDT` |
| limit                                   | string | Default: 100; Maximum: 1000                   |

> Return example

```json
{
  "currentFundRate": -0.00375,
  "indexPrice": 27905.98,
  "tagPrice": 27824.4422146875,
  "nextFundRate": -0.00375
}
```

**Response parameters**

| Name            | Type  | Example                  | Description                                               |
| :-------------- | :---- | :----------------------- | :-------------------------------------------------------- |
| indexPrice      | float | `27905.9800000000000000` | Index price                                               |
| tagPrice        | float | `27824.4422146875000000` | Mark price                                                |
| nextFundRate    | float | `-0.0037500000000000`    | Funding rate price                                        |
| currentFundRate | float | `-0.0037500000000000`    | Previous funding rate (used for this period's settlement) |

### K-line / Candlestick chart data

`GET https://t(:futures_http_url)/fapi/v1/klines`

> Request example

```http
GET https://t(:futures_http_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000

// Headers Configuration
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_http_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000"
```

```java
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

public class Main {
  public static void main(String[] args) {
    try {
      // Create a URL using URI
      URI uri = new URI("https://t(:futures_http_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // Read response
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // Output result
      System.out.println("Response: " + response.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

```

```go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	url := "https://t(:futures_http_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000"

	// Send GET request
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read the response:", err)
		return
	}

	// Print response
	fmt.Println("Server response:", string(body))
}
```

```python
import requests

url = "https://t(:futures_http_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000"

try:
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("Request error:", e)
```

```php
$url = "https://t(:futures_http_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000";

// Initialize cURL.
$ch = curl_init();

// Set cURL options
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL certificate verification (if required by the API)

// Execute the request
$response = curl_exec($ch);

// Check for errors
if (curl_errno($ch)) {
    echo "cURL Error：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// Close cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_http_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000';

https.get(url, (res) => {
  let data = '';

  // A chunk of data has been received.
  res.on('data', (chunk) => {
    data += chunk;
  });

  // The whole response has been received.
  res.on('end', () => {
    console.log("Response:", data);
  });

}).on('error', (err) => {
  console.log('Request error:', err.message);
});
```

**Request parameters**

| Parameter name                          | Type    | Description                                                                                                                                                                                       |
| :-------------------------------------- | :------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| contractName<font color="red">\*</font> | string  | `Uppercase`contract name, such as`E-BTC-USDT`                                                                                                                                                     |
| interval<font color="red">\*</font>     | string  | The time intervals for K-line charts, recognizable parameter values are:`1min`,`5min`,`15min`,`30min`,`1h`,`1day`,`1week`,`1month`(min = minute, h = hour, day = day, week = week, month = month) |
| limit                                   | integer | 默认：100；最大：300                                                                                                                                                                              |
| startTime                               | long    | Start timestamp                                                                                                                                                                                   |
| endTime                                 | long    | End timestamp                                                                                                                                                                                     |

> Response example.

```json
[
  {
    "high": 6228.77,
    "vol": 111,
    "low": 6190.48,
    "idx": 15946403400000,
    "close": 6210.51,
    "open": 6195.8
  },
  {
    "high": 6228.77,
    "vol": 222,
    "low": 6228.77,
    "idx": 15876321600000,
    "close": 6228.77,
    "open": 6228.77
  },
  {
    "high": 6228.77,
    "vol": 333,
    "low": 6228.77,
    "idx": 15876321000000,
    "close": 6228.77,
    "open": 6228.77
  }
]
```

**Response parameters**

| Parameter name | Type  | Example          | Description     |
| :------------- | :---- | :--------------- | :-------------- |
| idx            | long  | `15946403400000` | Start timestamp |
| open           | float | `6195.80`        | Opening price   |
| close          | float | `6210.51`        | Closing price   |
| high           | float | `6228.77`        | Highest price   |
| low            | float | `6190.48`        | Lowest price    |
| vol            | float | `111`            | Volume traded   |

## Trading

### Security type: TRADE

<aside class="notice">The APIs under the trading section require signature and API-key authentication</aside>

### Create order

`POST https://t(:futures_http_url)/fapi/v1/order`

Create a single new order

**Request headers**

| Parameter name                         | Type   | Description  |
| :------------------------------------- | :----- | :----------- |
| X-CH-TS<font color="red">\*</font>     | string | Timestamp    |
| X-CH-APIKEY<font color="red">\*</font> | string | Your API key |
| X-CH-SIGN<font color="red">\*</font>   | string | Signature    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/order

body
{"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/order"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API key";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/order";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{\"contractName\":\"E-BTC-USDT\",\"price\":65000.00,\"volume\":1.00,\"type\":\"LIMIT\",\"side\":\"BUY\",\"open\":\"OPEN\",\"positionType\":1,\"clientOrderId\":\"111000111\",\"timeInForce\":\"IOC\"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data The string to be signed
     * @param secret The secret key
     * @return HMAC SHA256 signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API key"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/order"
)

func main() {
	// Get millisecond timestamp
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send POST request.
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API key"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/order"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body into a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API key";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/order";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "price" => 65000.00,
    "volume" => 1.00,
    "type" => "LIMIT",
    "side" => "BUY",
    "open" => "OPEN",
    "positionType" => 1,
    "clientOrderId" => "111000111",
    "timeInForce" => "IOC"
], JSON_UNESCAPED_SLASHES);

//Get millisecond timestamp
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Use only in the development environment; SSL verification should be enabled in the production environment

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API-KEY";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/order";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    price: 65000.00,
    volume: 1.00,
    type: "LIMIT",
    side: "BUY",
    open: "OPEN",
    positionType: 1,
    clientOrderId: "111000111",
    timeInForce: "IOC"
});

// Get millisecond timestamp
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                                                                                                      |
| :-------------------------------------- | :----- | :------------------------------------------------------------------------------------------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, such as`E-BTC-USDT`                                                                                    |
| price                                   | number | Order price. This field is mandatory for limit orders. It has precision restrictions set by the administrator                    |
| volume<font color="red">\*</font>       | number | Order quantity. It has precision restrictions set by the administrator. For market orders, this field represents the order value |
| type<font color="red">\*</font>         | string | Order type:`LIMIT`/`MARKET` (`LIMIT`: Limit order, `MARKET`: Market order)                                                       |
|                                         |        | Note: When `timeInForce` is provided, this field will be ignored.                                                                |
| side<font color="red">\*</font>         | string | Order direction:`BUY`/`SELL`                                                                                                     |
| open<font color="red">\*</font>         | string | Position direction:`OPEN`/`CLOSE`                                                                                                |
| positionType<font color="red">\*</font> | number | Position type: 1 (Cross Margin) / 2 (Isolated Margin)                                                                            |
| timeInForce                             | string | Optional values: `IOC`,`FOK`,`POST_ONLY`                                                                                         |
|                                         |        | (`IOC`: Cancel unfilled parts immediately,                                                                                       |
|                                         |        | `FOK`: Cancel if not fully filled immediately,                                                                                   |
|                                         |        | `POST_ONLY`: Cancel if not a passive order )                                                                                     |
|                                         |        | Note: If this field is set, it will override the `type` field and be used as the final order type.                               |
| clientOrderId                           | string | Client order identifier, a string with a length of fewer than 32 characters                                                      |

> Response example

```json
{
  "orderId": 256609229205684228
}
```

**Response parameters**

| Parameter name | Type   | Example              | Description |
| :------------- | :----- | :------------------- | :---------- |
| orderId        | string | `256609229205684228` | Order ID    |

### Create conditional order

`POST https://t(:futures_http_url)/fapi/v1/conditionOrder`

**Request headers**

| Parameter name                         | Type   | Example      |
| :------------------------------------- | :----- | :----------- |
| X-CH-TS<font color="red">\*</font>     | string | Timestamp    |
| X-CH-APIKEY<font color="red">\*</font> | string | Your API key |
| X-CH-SIGN<font color="red">\*</font>   | string | Signature    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/conditionOrder

body
{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/conditionOrder"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/conditionOrder";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API-KEY"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/conditionOrder"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/conditionOrder"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API key";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/conditionOrder";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "price" => 65000.00,
    "volume" => 1.00,
    "type" => "LIMIT",
    "side" => "BUY",
    "positionType" => 1,
    "open" => "OPEN",
    "triggerType" => "1",
    "triggerPrice" => "455"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API key";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/conditionOrder";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    price: "65000.00",
    volume: "1.00",
    type: "LIMIT",
    side: "BUY",
    positionType: "1",
    open: "OPEN",
    triggerType: "1",
    triggerPrice: "455"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Construct the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                                                                                    |
| :-------------------------------------- | :----- | :------------------------------------------------------------------------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, such as`E-BTC-USDT`                                                                  |
| price<font color="red">\*</font>        | number | Order price, with precision limits set by the administrator                                                    |
| volume<font color="red">\*</font>       | number | Order quantity. For market orders, this represents the value. It has precision limits set by the administrator |
| type<font color="red">\*</font>         | string | Order type:`LIMIT`/`MARKET`                                                                                    |
| side<font color="red">\*</font>         | string | Order direction:`BUY`/`SELL`                                                                                   |
| positionType<font color="red">\*</font> | number | Order direction: BUY / SELL; Position type: 1 (Cross Margin), 2 (Isolated Margin)                              |
| open<font color="red">\*</font>         | string | Position direction:`OPEN`/`CLOSE`                                                                              |
| triggerType<font color="red">\*</font>  | string | Condition type: 1 (Stop Loss), 2 (Take Profit), 3 (Buy on the rise), 4 (Sell on the dip)                       |
| triggerPrice<font color="red">\*</font> | string | Trigger price                                                                                                  |
| clientOrderId                           | string | Client order identifier, a string with a length of fewer than 32 characters                                    |

> Response example

```json
{
  "code": "0",
  "msg": "Success",
  "data": {
    "triggerIds": ["1322738336974712847"],
    "ids": [],
    "cancelIds": []
  },
  "succ": true
}
```

If this API returns unexpected results, please contact the technical team, and we will provide relevant assistance

### Cancel order

`POST https://t(:futures_http_url)/fapi/v1/cancel`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/cancel

body
{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/cancel"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API key";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/cancel";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, ensure to use compact format)
            String body = "{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}";
            System.out.println("Request body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API-KEY"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/cancel"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/cancel"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Construct the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API-KEY";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/cancel";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "orderId" => 2616833860188981826
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Construct the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Use only in the development environment; SSL verification should be enabled in the production environment

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API key";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/cancel";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    orderId: "2616833860188981826"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Construct the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                    |
| :-------------------------------------- | :----- | :--------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase` contract name, such as`E-BTC-USDT` |
| orderId<font color="red">\*</font>      | string | Order ID                                       |

> Return example

```json
{
  "orderId": "256609229205684228"
}
```

### Cancel conditional order

`POST https://t(:futures_http_url)/fapi/v1/cancel_trigger_order`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter nam                          | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/cancel_trigger_order

body
{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API key"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/cancel_trigger_order"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/cancel_trigger_order";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API key"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/cancel_trigger_order"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API key"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/cancel_trigger_order"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API key";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/cancel_trigger_order";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "orderId" => 2616833860188981826
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API key";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/cancel_trigger_order";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    orderId: "2616833860188981826"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request.
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                         |
| :-------------------------------------- | :----- | :-------------------------------------------------- |
| contractName<font color="red">\*</font> | string | `UPPERCASE` contract name, for example:`E-BTC-USDT` |
| orderId<font color="red">\*</font>      | string | Order ID                                            |
| clientOrderId                           | string | Client unique identifier, default: 0                |

> Response example

```json
{
  "orderId": "256609229205684228"
}
```

### Order details

`GET https://t(:futures_http_url)/fapi/v1/order`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type   | Description  |
| :------------------------------------- | :----- | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string | Your API key |
| X-CH-TS<font color="red">\*</font>     | string | Timestamp    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/order

body
{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API key"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/order"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Use cURL to send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = API-related information";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/order";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API key"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/order"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API key"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/order"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API key";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/order";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "orderId" => 2616833860188981826
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API key";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/order";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    orderId: "2616833860188981826"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Get timestamp in milliseconds
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                           | Type   | Description                                        |
| :--------------------------------------- | :----- | :------------------------------------------------- |
| contractName<font color="red">\*</font>  | string | `UPPERCASE`Contract Name, for example:`E-BTC-USDT` |
| orderId<font color="red">\*</font>       | string | Order ID                                           |
| clientOrderId<font color="red">\*</font> | string | Client unique identifier, default: 0               |

> Response example

```json
{
  "side": "BUY",
  "executedQty": 0,
  "orderId": 2006628907041292645,
  "price": 67000.0,
  "origQty": 2.0,
  "avgPrice": 0,
  "transactTime": 1704967622000,
  "action": "OPEN",
  "contractName": "E-BTC-USDT",
  "type": "LIMIT",
  "timeInForce": "1",
  "status": "NEW",
  "fills": []
}
```

**Response parameters**

| Parameter name | Type    | Example                  | Description                                                                                                                                                                   |
| :------------- | :------ | :----------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| orderId        | long    | `2006628907041292645`    | Order ID (system-generated)                                                                                                                                                   |
| contractName   | string  | `E-BTC-USDT`             | `UPPERCASE` Contract Name                                                                                                                                                     |
| price          | float   | `67000.0000000000000000` | Order price                                                                                                                                                                   |
| origQty        | float   | `2.0000000000000000`     | Order quantity                                                                                                                                                                |
| executedQty    | float   | `0`                      | Executed quantity                                                                                                                                                             |
| avgPrice       | float   | `0`                      | Average execution price                                                                                                                                                       |
| status         | string  | `NEW`                    | Order status. Possible values are:`NEW`(New order, no fills),`PARTIALLY_FILLED`(Partially filled),`FILLED`(Fully filled),`CANCELED`(Cancelled), and`REJECTED`(Order rejected) |
| side           | string  | `BUY`                    | Order direction. The possible values are:`BUY`(Buy long) and`SELL`(Sell short)                                                                                                |
| action         | string  | `OPEN`                   | `OPEN/CLOSE`                                                                                                                                                                  |
| transactTime   | long    | `1704967622000`          | Order creation time                                                                                                                                                           |
| type           | string  | `LIMIT`                  | Order type:`LIMIT / MARKET`                                                                                                                                                   |
| timeInForce    | integer | `1`                      | Conditional order validity types:1：`limit`，2：`market`，3：`IOC`，4：`FOK`，5： `POST\_ONLY`                                                                                |
| fills          | array   |                          | Transaction records                                                                                                                                                           |

### Current order

`GET https://t(:futures_http_url)/fapi/v1/openOrders`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type   | Description  |
| :------------------------------------- | :----- | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string | Your API key |
| X-CH-TS<font color="red">\*</font>     | string | Timestamp    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/openOrders

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API key"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/openOrders"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API key";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/openOrders";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API key"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/openOrders"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/openOrders"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "API-related information";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/openOrders";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API key";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/openOrders";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                 |
| :-------------------------------------- | :----- | :------------------------------------------ |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, e.g.,`E-BTC-USDT` |

> Response example

```json
[
  {
    "side": "BUY",
    "executedQty": 0.5,
    "orderId": 259396989397942275,
    "price": 72000.0,
    "origQty": 1.0,
    "avgPrice": 71990.0,
    "transactTime": 1607702400000,
    "action": "OPEN",
    "contractName": "E-BTC-USDT",
    "type": "LIMIT",
    "status": "NEW"
  }
]
```

Response parameters

| Parameter name | Type   | Example                  | Description                                                                                                                                                                      |
| :------------- | :----- | :----------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| orderId        | long   | `259396989397942275`     | Order ID (system-generated)                                                                                                                                                      |
| contractName   | string | `E-BTC-USDT`             | `Uppercase contract name`                                                                                                                                                        |
| price          | float  | `72000.0000000000000000` | Order price                                                                                                                                                                      |
| origQty        | float  | `1.0000000000000000`     | Order quantity                                                                                                                                                                   |
| executedQty    | float  | `0.5`                    | Filled order quantity                                                                                                                                                            |
| avgPrice       | float  | `71990.0`                | The average price of the filled order                                                                                                                                            |
| type           | string | `LIMIT`                  | Order type. Possible values are:`LIMIT`(limit order) and`MARKET`(market order)                                                                                                   |
| side           | string | `BUY`                    | Order direction. Possible values are:`BUY`(long position) and`SELL`(short position)                                                                                              |
| status         | string | `NEW`                    | Order status. Possible values are:`NEW`(new order, no fill),`PARTIALLY_FILLED`(partially filled),`FILLED`(completely filled),`CANCELED`(canceled), and`REJECTED`(order rejected) |
| action         | string | `OPEN`                   | `OPEN/CLOSE`                                                                                                                                                                     |
| transactTime   | long   | `1607702400000`          | Order creation timestamp                                                                                                                                                         |

### Historical Orders

`POST https://t(:futures_http_url)/fapi/v1/orderHistorical`

**Request headers**

| Parameter name                         | Type   | Description  |
| :------------------------------------- | :----- | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string | Your API key |
| X-CH-TS<font color="red">\*</font>     | string | Timestamp    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/orderHistorical

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/orderHistorical"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/orderHistorical";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API key"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/orderHistorical"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/orderHistorical"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API-KEY";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/orderHistorical";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API-KEY";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/orderHistorical";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                        |
| :-------------------------------------- | :----- | :------------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, for example:`E-BTC-USDT` |
| limit                                   | string | Pagination limit, default: 100; maximum: 1000      |
| fromId                                  | long   | Start retrieving from this record                  |

> Return example

```json
[
  {
    "side": "BUY",
    "clientId": "0",
    "ctimeMs": 1632903411000,
    "positionType": 2,
    "orderId": 777293886968070157,
    "avgPrice": 41000,
    "openOrClose": "OPEN",
    "leverageLevel": 26,
    "type": 4,
    "closeTakerFeeRate": 0.00065,
    "volume": 2,
    "openMakerFeeRate": 0.00025,
    "dealVolume": 1,
    "price": 41000,
    "closeMakerFeeRate": 0.00025,
    "contractId": 1,
    "ctime": "2021-09-29T16:16:51",
    "contractName": "E-BTC-USDT",
    "openTakerFeeRate": 0.00065,
    "dealMoney": 4.1,
    "status": 4
  }
]
```

If this API returns unexpected results, please contact the technical team, and we will provide you with relevant assistance

### Profit and Loss Record

`POST https://t(:futures_http_url)/fapi/v1/profitHistorical`

If this API returns an error, please contact the technical team, and we will provide you with relevant assistance

**Request headers**

| Parameter name                         | Type   | Description  |
| :------------------------------------- | :----- | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string | Your API-KEY |
| X-CH-TS<font color="red">\*</font>     | string | Timestamp    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/profitHistorical

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/profitHistorical"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/profitHistorical";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API key"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/profitHistorical"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/profitHistorical"


# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API-KEY";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/profitHistorical";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API-KEY";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/profitHistorical";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                   |
| :-------------------------------------- | :----- | :-------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, such as`E-BTC-USDT` |
| limit                                   | string | Pagination limit, default: 100; maximum: 1000 |
| fromId                                  | long   | Start retrieving from this record             |

> Response example

```json
[
  {
    "side": "SELL",
    "positionType": 2,
    "tradeFee": -5.23575,
    "realizedAmount": 0,
    "leverageLevel": 26,
    "openPrice": 44500,
    "settleProfit": 0,
    "mtime": 1632882739000,
    "shareAmount": 0,
    "openEndPrice": 44500,
    "closeProfit": -45,
    "volume": 900,
    "contractId": 1,
    "historyRealizedAmount": -50.23575,
    "ctime": 1632882691000,
    "id": 8764,
    "capitalFee": 0
  }
]
```

If this API returns unexpected results, please contact the technical team, and we will provide you with relevant assistance

### Transaction records

`GET https://t(:futures_http_url)/fapi/v1/myTrades`

**Rate limit rule: 20 requests per 2 seconds**

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API-KEY |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/myTrades

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/myTrades"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/myTrades";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API-KEY"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/myTrades"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/myTrades"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API key";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/myTrades";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API-KEY";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/myTrades";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type   | Description                                   |
| :-------------------------------------- | :----- | :-------------------------------------------- |
| contractName<font color="red">\*</font> | string | `Uppercase`contract name, such as`E-BTC-USDT` |
| limit                                   | string | Pagination limit, default: 100; maximum: 1000 |
| fromId                                  | long   | Start retrieving from this tradeId            |

> Return example

```json
[
  {
    "amount": 0.3,
    "side": "BUY",
    "fee": 0.001,
    "isMaker": true,
    "isBuyer": true,
    "bidId": 1874564572563538130,
    "bidUserId": 10034,
    "price": 10.0,
    "qty": 3,
    "askId": 1954072405852309104,
    "contractName": "E-ETH-USDT",
    "time": 1701419186000,
    "tradeId": 1528,
    "askUserId": 10378
  },
  {
    "amount": 1.0,
    "side": "BUY",
    "fee": 0.00025,
    "isMaker": true,
    "isBuyer": true,
    "bidId": 1874564572563538059,
    "bidUserId": 10034,
    "price": 10.0,
    "qty": 10,
    "askId": 1954072405852309104,
    "contractName": "E-ETH-USDT",
    "time": 1701419186000,
    "tradeId": 1527,
    "askUserId": 10378
  }
]
```

**Response parameters**

| Parameter name | Type    | Example               | Description                                     |
| :------------- | :------ | :-------------------- | :---------------------------------------------- |
| tradeId        | number  | `1528`                | Transaction ID                                  |
| bidId          | long    | `1874564572563538130` | Buyer order ID                                  |
| askId          | long    | `1954072405852309104` | Seller order ID                                 |
| bidUserId      | integer | `10034`               | Buyer User ID                                   |
| askUserId      | integer | `10378`               | Seller User ID                                  |
| price          | float   | `10.0`                | Transaction Price                               |
| qty            | float   | `3`                   | Transaction quantity                            |
| amount         | float   | `30.0`                | Transaction Amount                              |
| time           | number  | `1499865549590`       | Transaction timestamp                           |
| fee            | number  | `0.001`               | Transaction fee                                 |
| side           | string  | `BUY`                 | Current Order Direction,`BUY`: Buy,`SELL`: Sell |
| contractName   | string  | `E-BTC-USDT`          | `Uppercase`contract name                        |
| isMaker        | boolean | `true`                | Is it a maker                                   |
| isBuyer        | boolean | `true`                | Is the buyer                                    |

### Change position mode

`POST https://t(:futures_http_url)/fapi/v1/edit_user_position_model`

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API-KEY |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/edit_user_position_model

body
{"contractName":"E-BTC-USDT","positionModel":"1"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/edit_user_position_model"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","positionModel":"1"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API key";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/edit_user_position_model";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT","positionModel":"1"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API-KEY"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/edit_user_position_model"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","positionModel":"1"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/edit_user_position_model"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","positionModel":"1"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API key";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/edit_user_position_model";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName"  => "E-BTC-USDT",
    "positionModel" => "1"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API key";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/edit_user_position_model";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    positionModel: "1"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                           | Type    | Description                                          |
| :--------------------------------------- | :------ | :--------------------------------------------------- |
| contractName<font color="red">\*</font>  | string  | Contract name, e.g.,`E-BTC-USDT`                     |
| positionModel<font color="red">\*</font> | integer | Position mode, 1:`Net Position`, 2:`Hedged Position` |

> Response example

```json
{
  "code": "0",
  "msg": "Success",
  "data": null
}
```

### Change Margin Mode

`POST https://t(:futures_http_url)/fapi/v1/edit_user_margin_model`

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API-KEY |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/edit_user_margin_model

body
{"contractName":"E-BTC-USDT","marginModel":"1"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API key"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/edit_user_margin_model"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","marginModel":"1"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/edit_user_margin_model";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT","marginModel":"1"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API-KEY"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/edit_user_margin_model"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","marginModel":"1"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/edit_user_margin_model"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","marginModel":"1"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API-KEY";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/edit_user_margin_model";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName"  => "E-BTC-USDT",
    "marginModel" => "1"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API-KEY";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/edit_user_margin_model";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    marginModel: "1"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type    | Description                                        |
| :-------------------------------------- | :------ | :------------------------------------------------- |
| contractName<font color="red">\*</font> | string  | Contract Name, e.g.,`E-BTC-USDT`                   |
| marginModel<font color="red">\*</font>  | integer | Position Mode:，1：`Net Position`，2：`Hedge Mode` |

> Response example

```json
{
  "code": "0",
  "msg": "Success",
  "data": null
}
```

### Change Leverage Ratio

`POST` `https://t(:futures_http_url)/fapi/v1/edit_lever`

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API-KEY |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/edit_lever

body
{"contractName":"E-BTC-USDT","newLever":"1"}
```

```shell
#!/bin/bash

# API-related information
api_key="Your API-KEY"
api_secret="Your API-SECRET"

# Request information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond timestamp
method="POST"
request_path="/fapi/v1/edit_lever"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","newLever":"1"}'

# Remove whitespace characters from the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature string: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Signature (X-CH-SIGN): $signature"

# Send a POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "Response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API-related information
    private static final String API_KEY = "Your API-KEY";
    private static final String API_SECRET = "Your API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/edit_lever";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // Request method
            String method = "POST";

            // Request body (in JSON format, make sure to use compact format)
            String body = "{"contractName":"E-BTC-USDT","newLever":"1"}";
            System.out.println("Request body (body): " + body);

            // Concatenate the signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("Signature string: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("Signature (X-CH-SIGN): " + signature);

            // Create a URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send the request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output the response result
            System.out.println("Response (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generate HMAC SHA256 signature
     *
     * @param data   String to be signed
     * @param secret Secret key
     * @return HMAC SHA256 Signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API-related information
const (
	APIKey     = "Your API-KEY"
	APISecret  = "Your API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/edit_lever"
)

func main() {
	// Get timestamp in milliseconds
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// Request method
	method := "POST"

	// Request body (in JSON format)
	body := `{"contractName":"E-BTC-USDT","newLever":"1"}`

	// Concatenate the signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature string:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Signature (X-CH-SIGN):", signature)

	// Send a POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response:", string(responseBody))
}

// Generate HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API-related information
API_KEY = "Your API-KEY"
API_SECRET = "Your API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/edit_lever"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","newLever":"1"}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body (body):", body_str)

# Concatenate the signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("Signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("Signature (X-CH-SIGN):", signature)

# Build the request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send a POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output the response result
print("Response status code:", response.status_code)
print("Response content:", response.text)
```

```php
// API-related information
$apiKey = "Your API key";
$apiSecret = "Your API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/edit_lever";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName"  => "E-BTC-USDT",
    "newLever" => "1"
], JSON_UNESCAPED_SLASHES);

// Get timestamp in milliseconds
$timestamp = round(microtime(true) * 1000);

// Concatenate the signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "Signature string: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "Signature (X-CH-SIGN): " . $signature . PHP_EOL;

// Build the request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send a POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Only use in development environments; SSL verification should be enabled in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API-related information
const API_KEY = "Your API-KEY";
const API_SECRET = "Your API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/edit_lever";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    newLever: "1"
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("Signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("Signature (X-CH-SIGN):", signature);

// Build the request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send a POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type    | Description                      |
| :-------------------------------------- | :------ | :------------------------------- |
| contractName<font color="red">\*</font> | string  | Contract Name, e.g.,`E-BTC-USDT` |
| newLever<font color="red">\*</font>     | integer | Adjust Leverage Ratio            |

> Return example

```json
{
  "code": "0",
  "msg": "Success",
  "data": null
}
```

### Current Holdings List

`POST` `https://t(:futures_http_url)/fapi/v1/positionList`

**Request headers**

| Parameter name                         | Type    | Description  |
| :------------------------------------- | :------ | :----------- |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp    |
| X-CH-APIKEY<font color="red">\*</font> | string  | Your API-KEY |
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature    |

> Request example

```http
POST https://t(:futures_http_url)/fapi/v1/positionList

body
{"contractName":"E-BTC-USDT","limit":10,"page":1}
```

```shell
#!/bin/bash

# API Related Information
api_key="Your's API-KEY"
api_secret="Your's API-SECRET"

# Request Information
timestamp=$(($(date +%s%N)/1000000))  # Millisecond-level timestamp
method="POST"
request_path="/fapi/v1/positionList"

# Request body (in JSON format)
body='{"contractName":"E-BTC-USDT","limit":10,"page":1}'

# Remove whitespace characters in the body to ensure signature consistency
body=$(echo "$body" | jq -c)

# Concatenate the signature string
sign_str="${timestamp}${method}${request_path}${body}"
echo "Signature String: $sign_str"

# Generate HMAC SHA256 signature
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "Sign (X-CH-SIGN): $signature"

# Send POST request
response=$(curl -s -X POST "https://t(:futures_http_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# Output the response result
echo "response: $response"
```

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class SendOrder {

    // API Related Information
    private static final String API_KEY = "Your's API-KEY";
    private static final String API_SECRET = "Your's API-SECRET";
    private static final String BASE_URL = "https://t(:futures_http_url)";
    private static final String REQUEST_PATH = "/fapi/v1/positionList";

    public static void main(String[] args) {
        try {
            // Get timestamp (in milliseconds)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // HTTP request method
            String method = "POST";

            // Request body (in JSON format, use compact format)
            String body = "{"contractName":"E-BTC-USDT","limit":10,"page":1}";
            System.out.println("请求主体 (body): " + body);

            // Concatenate signature string
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // Generate HMAC SHA256 signature
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // Create URL using URI
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // Send request body
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // Read response
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // Output response result
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates an HMAC SHA256 signature.
     *
     * @param data   The string to be signed
     * @param secret The secret key
     * @return HMAC SHA256 signature
     */
    public static String hmacSHA256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// API Related Information
const (
	APIKey     = "Your's API-KEY"
	APISecret  = "Your's API-SECRET"
	BaseURL    = "https://t(:futures_http_url)"
	RequestPath = "/fapi/v1/positionList"
)

func main() {
	// Get timestamp (in milliseconds)
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// HTTP request method
	method := "POST"

	// Request body (in JSON format, use compact format)
	body := `{"contractName":"E-BTC-USDT","limit":10,"page":1}`

	// Concatenate signature string
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("Signature String:", signStr)

	// Generate HMAC SHA256 signature
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("Sign (X-CH-SIGN):", signature)

	// Send POST request
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("Failed to create request:", err)
		return
	}

	// Set request headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	// Read response
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response:", string(responseBody))
}

// Generates an HMAC SHA256 signature
func generateHMACSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
import time
import hmac
import hashlib
import requests

# API Related Information
API_KEY = "Your's API-KEY"
API_SECRET = "Your's API-SECRET"
BASE_URL = "https://t(:futures_http_url)"
REQUEST_PATH = "/fapi/v1/positionList"

# Request method and request body
method = "POST"
body = {"contractName":"E-BTC-USDT","limit":10,"page":1}


# Get timestamp (in milliseconds)
timestamp = int(time.time() * 1000)

# Convert the request body to a compact JSON string
import json
body_str = json.dumps(body, separators=(',', ':'))
print("Request body:", body_str)

# Concatenate signature string
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("signature string:", sign_str)

# Generate HMAC SHA256 signature
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("sign (X-CH-SIGN):", signature)

# Build request headers
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# Send POST request
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# Output response result
print("Response status code :", response.status_code)
print("Response content:", response.text)
```

```php
// API Related Information
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_http_url)";
$requestPath = "/fapi/v1/positionList";

// Request method and request body
$method = "POST";
$body = json_encode([
    "contractName"  => "E-BTC-USDT",
    "limit" => "10",
    "page" => "1"
], JSON_UNESCAPED_SLASHES);

// Millisecond-level timestamp
$timestamp = round(microtime(true) * 1000);

// Concatenate signature string
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// Generate HMAC SHA256 signature
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// Build request headers
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// Send POST request
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // This should only be used in development; enable SSL verification in production environments

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "Request failed: " . curl_error($ch) . PHP_EOL;
} else {
    echo "Response status code: $httpCode" . PHP_EOL;
    echo "Response content: $response" . PHP_EOL;
}

curl_close($ch);
```

```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "Your's API-KEY";
const API_SECRET = "Your's API-SECRET";
const BASE_URL = "https://t(:futures_http_url)";
const REQUEST_PATH = "/fapi/v1/positionList";

// Request method and request body
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    limit: "10",
    "page":1
});

// Get timestamp in milliseconds
const timestamp = Date.now();

// Concatenate the signature string
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("signature string:", signStr);

// Generate HMAC SHA256 signature
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("sign (X-CH-SIGN):", signature);

// Build request headers
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// Send POST request
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("Response status code:", response.status);
        console.log("Response content:", response.data);
    } catch (error) {
        console.error("Request failed:", error.response ? error.response.data : error.message);
    }
}

// Execute the request
sendOrder();

```

**Request parameters**

| Parameter name                          | Type    | Description                      |
| :-------------------------------------- | :------ | :------------------------------- |
| contractName<font color="red">\*</font> | string  | Contract Name, e.g.,`E-BTC-USDT` |
| limit<font color="red">\*</font>        | integer | Number of records displayed      |
| page<font color="red">\*</font>         | integer | Current page number              |

> Return example

```json
{
  "code": "0",
  "msg": "Success",
  "data": {
    "records": [
      {
        "id": 42888,
        "originUid": 18099,
        "uid": 10059,
        "contractName": "E-BTC-USDT",
        "volume": 2.0,
        "holdAmount": 0e-16,
        "openPrice": 94777.1,
        "closePrice": 0e-16,
        "closeVolume": 0e-16,
        "historyRealizedAmount": -0.014216565,
        "unRealizedAmount": -0.11638,
        "ctime": "2025-05-06 03:14:19",
        "status": 1,
        "side": "BUY",
        "leverageLevel": 100
      }
    ],
    "total": 23,
    "size": 1,
    "current": 1,
    "orders": [],
    "optimizeCountSql": true,
    "hitCount": false,
    "countId": null,
    "maxLimit": null,
    "searchCount": true,
    "pages": 23
  },
  "succ": true
}
```

**Response Parameters**

| Parameter name                                   | Type       | Description                                       |
| :----------------------------------------------- | :--------- | :------------------------------------------------ |
| id<font color="red">\*</font>                    | integer    | Data ID                                           |
| contractName<font color="red">\*</font>          | string     | Contract Name                                     |
| volume<font color="red">\*</font>                | bigDecimal | Position quantity                                 |
| holdAmount<font color="red">\*</font>            | bigDecimal | Position margin                                   |
| openPrice<font color="red">\*</font>             | bigDecimal | Opening price                                     |
| closePrice<font color="red">\*</font>            | bigDecimal | Closing average price                             |
| closeVolume<font color="red">\*</font>           | bigDecimal | Closed position quantity                          |
| historyRealizedAmount<font color="red">\*</font> | bigDecimal | Historical cumulative realized profits and losses |
| unRealizedAmount<font color="red">\*</font>      | bigDecimal | Unrealized Profit and Loss                        |
| ctime<font color="red">\*</font>                 | string     | Creation time                                     |
| status<font color="red">\*</font>                | integer    | Position Validity (0: Invalid, 1: Valid)          |
| side<font color="red">\*</font>                  | string     | Position direction                                |
| leverageLevel<font color="red">\*</font>         | integer    | Leverage ratio                                    |

# Websocket

## Overview

WebSocket is a new protocol in HTML5. It enables full-duplex communication between the client and the server, allowing data to be transmitted quickly in both directions. A connection between the client and the server can be established through a simple handshake, and the server can actively push information to the client based on business rules. Its advantages are as follows:

- The request header information is relatively small, about 2 bytes, when transmitting data between the client and the server.
- Both the client and the server can actively send data to each other.
- There is no need to create and destroy TCP requests multiple times, saving bandwidth and server resources.

<aside class="notice">It is strongly recommended that developers use the WebSocket API to get market data, such as market prices and order book depth.</aside>

## Spot

### Basic Information

- url：<wss://wsapi.fameex.com/v1/ws/stream/public>。

> Response example

```json
{
  "event_rep": "",
  "channel": "system",
  "data": {
    "status": "ready"
  },
  "tick": null,
  "ts": "1766066323820",
  "status": "ok"
}
```

### Heartbeat

To keep the connection active and stable, it is recommended to perform the following actions:

1. After receiving each message, the user should set a timer with a duration of N seconds, where N is less than 30.

2. If the timer is triggered (i.e., no new message is received within N seconds), send the string 'ping'.

3. You should expect a text string 'pong' as a response. If no response is received within N seconds, trigger an error or reconnect.

> Heartbeat example

```json
{
  "event": "heartbeat",
  "params": {
    "channel": "ping"
  }
}
```

> Response example

```json
{
  "event_rep": "",
  "channel": "",
  "data": {
    "channel": "pong"
  },
  "tick": null,
  "ts": "1766061007743",
  "status": "ok"
}
```

### Subscription / Unsubscription Parameters

Kline interval suffixes

- Seconds: 1s
- Minutes: 1m, 3m, 5m, 15m, 30m
- Hours: 1h, 2h, 4h, 6h, 8h, 12h
- Days: 1d, 3d
- Weeks: 1w
- Months: 1M

| event | channel                             | description                                  |
| :---- | :---------------------------------- | :------------------------------------------- |
| sub   | market\_${symbol}\_depth_step       | Subscribe incremental order book depth       |
| unsub | market\_${symbol}\_depth_step       | Unsubscribe incremental order book depth     |
| sub   | market\_${symbol}\_trade            | Subscribe real-time trades                   |
| unsub | market\_${symbol}\_trade            | Unsubscribe real-time trades                 |
| sub   | market\_${symbol}\_ticker           | Subscribe 24h market ticker                  |
| unsub | market\_${symbol}\_ticker           | Unsubscribe 24h market ticker                |
| sub   | market*${symbol}\_kline*${interval} | Subscribe ${interval} real-time Kline data   |
| unsub | market*${symbol}\_kline*${interval} | Unsubscribe ${interval} real-time Kline data |
| sub   | market\_${symbol}\_kline_1M         | Subscribe 1-month historical Kline data      |
| unsub | market\_${symbol}\_kline_1M         | Unsubscribe 1M real-time Kline data          |

### Subscription

### Subscribe Incremental Order Book Depth

> Subscription example

```json
{
  "event": "sub",
  "params": {
    "channel": "market_${symbol}_depth_step", // ${symbol}, E.g. btcusdt
    "cb_id": "1" // Business ID, optional
  }
}
```

> Response example

```json
{
  "event_rep": "",
  "channel": "market_btcusdt_depth_step",
  "data": null,
  "tick": {
    "pair": "BTCUSDT",
    "bids": [
      // Buy orders
      ["87263.1", "0.1"],
      ["87263.09", "0.1"]
    ],
    "asks": [
      // Sell orders
      ["85528.97", "0.1"],
      ["85554.73", "0.1"]
    ],
    "pre_update_id": "9164837",
    "last_update_id": "9164840"
  },
  "ts": "1766062757172",
  "status": "ok"
}
```

#### How to Properly Maintain a Local Order Book Copy

1. Open a WebSocket connection to <wss://wsapi.fameex.com/v1/ws/stream/public> and subscribe to the incremental depth channel.
2. Begin buffering the received events. Record the last_update_id value from the first event you receive.
3. Fetch the depth snapshot from <https://spotapi.fameex.com/spot/v1/market/orderbook?symbol=${symbol}>.
4. If the update_id in the snapshot is less than or equal to the last_update_id value from step 2, return to step 3.
5. From the received events, discard all events where last_update_id <= the update_id in the snapshot. Now the first event's last_update_id should be within the [pre_update_id; last_update_id] range.
6. Set your local order book to the snapshot. Its update ID is update_id.
7. Apply all buffered events, as well as all subsequent events.

#### To Apply an Event to Your Local Order Book, Follow This Update Process:

1. Determine whether the event needs to be processed:
   - If the event's last update ID (last_update_id) is less than the local order book's update ID (update_id), ignore the event.
   - If the event's first update ID (pre_update_id) is greater than the local order book's update ID plus 1, it means you have missed some events. Discard your local order book and resync from the beginning.
   - Typically, the next event's pre_update_id equals the previous event's last_update_id + 1.
2. Set the order book's update ID (update_id) to the last update ID (last_update_id) of the processed event.

### Subscribe Real-time Trades

> Subscription example

```json
{
  "event": "sub",
  "params": {
    "channel": "market_${symbol}_trade", // ${symbol}, E.g. btcusdt
    "cb_id": "1" // Business ID, optional
  }
}
```

> Response example

```json
{
  "event_rep": "",
  "channel": "market_btcusdt_trade",
  "data": [
    {
      "amount": "22790.07645", // Total amount
      "ds": "",
      "price": "87671.00", // Price
      "side": "SELL", // Trade side: buy, sell
      "ts": "1766063060107",
      "vol": "0.25995" // Quantity
    }
  ],
  "tick": null,
  "ts": "1766063061126",
  "status": "ok"
}
```

### Subscribe Kline Market Data

> Subscription example

```json
{
  "event": "sub",
  "params": {
    // ${symbol}, E.g. btcusdt
    // ${interval}, E.g. 1min/5min/15min/30min/60min/1day/1week/1
    "channel": "market_${symbol}_kline_${interval}",
    "cb_id": "1" // Business ID, optional
  }
}
```

> Response example

```json
{
  "event_rep": "",
  "channel": "market_btcusdt_kline_1m",
  "data": null,
  "tick": {
    "amount": "1701994.52252",
    "close": "88291.70", // Close price
    "ds": "",
    "high": "88328.90", // High price
    "ts": "1766065020000",
    "low": "88169.40", // Low price
    "open": "88211.60", // Open price
    "vol": "19.2841" // Trading volume
  },
  "ts": "1766065072255",
  "status": "ok"
}
```

### Subscribe 24h Market Ticker

> Subscription example

```json
{
  "event": "sub",
  "params": {
    "channel": "market_${symbol}_ticker", // ${symbol}, E.g. btcusdt
    "cb_id": "1" // Business ID, optional
  }
}
```

> Response example

```json
{
  "event_rep": "",
  "channel": "market_btcusdt_ticker",
  "data": null,
  "tick": {
    "amount": "1080601292.38171", // Trading amount
    "close": "88953.30", // Close price
    "high": "90364.3", // High price
    "low": "85312.9", // Low price
    "open": "87507.60", // Open price
    "rose": "0.0172601894", // Price change rate
    "vol": "12398.36035" // Trading volume
  },
  "ts": "1766065787125",
  "status": "ok"
}
```

## Futures

### Basic information

- The basic contract market data endpoint：<wss://t(:futures_ws_url)/kline-api/ws>。
- The basic contract market data backup endpoint：<wss://t(:futures_ws_url_bak)/kline-api/ws>。
- The returned data, except for heartbeat data, will be compressed in binary format (users need to decompress it using the Gzip algorithm).

### Heartbeat

To keep the connection active and stable, it is recommended to perform the following actions:

1. After receiving each message, the user should set a timer with a duration of N seconds, where N is less than 30.

2. If the timer is triggered (i.e., no new message is received within N seconds), send the string 'ping'.

3. You should expect a text string 'pong' as a response. If no response is received within N seconds, trigger an error or reconnect.

> The heartbeat response

```json
{
  "pong": 15359750
}
```

### Demo

[Websocket Demo](https://github.com/)

## Subscribe/Unsubscribe Parameters

| event | channel                       | description                                  |
| :---- | :---------------------------- | :------------------------------------------- |
| sub   | `market_$symbol_depth_step0`  | `Subscribe to Depth`                         |
| unsub | `market_$symbol_depth_step0`  | `Unsubscribe from Depth`                     |
| sub   | `market_$symbol_trade_ticker` | `Subscribe to Real-time Trades`              |
| unsub | `market_$symbol_trade_ticker` | `Unsubscribe from Real-time Trades`          |
| sub   | `market_$symbol_ticker`       | `Subscribe to 24h Market Data`               |
| unsub | `market_$symbol_ticker`       | `Unsubscribe from 24h Market Data`           |
| sub   | `market_$symbol_kline_1min`   | `Subscribe to 1-Minute Real-time Kline Data` |
| req   | `market_$symbol_kline_1month` | `Request 1-Month Historical Kline Data`      |

## Subscribe

### Subscribe to full depth

> Subscription Example

```json
{
  "event": "sub",
  "params": {
    "channel": "market_$symbol_depth_step0", // $symbol E.g. Spot trading：btcusdt Futures：e_btcusdt
    "cb_id": "1" // Business ID is optional
  }
}
```

> Return example

```json
{
  "channel": "market_btcusdt_depth_step0",
  "ts": 1506584998239,
  "tick": {
    "asks": [
      //Sell order
      [10000.19, 0.93],
      [10001.21, 0.2],
      [10002.22, 0.34]
    ],
    "bids": [
      //Buy order
      [9999.53, 0.93],
      [9998.2, 0.2],
      [9997.19, 0.21]
    ]
  }
}
```

### Subscribe to real-time trades

> Subscription Example

```json
{
  "event": "sub",
  "params": {
    "channel": "market_$symbol_trade_ticker", // $symbol E.g. Spot trading: btcusdt，Futures: e_btcusdt
    "cb_id": "1" // Business ID is optional
  }
}
```

> Response example

```json
{
  "channel": "market_$symbol_trade_ticker",
  "ts": 1506584998239, // Request time
  "tick": {
    "id": 12121, // The "maximum transaction ID in the data"
    "ts": 1506584998239, // The "maximum timestamp in the data"
    "data": [
      {
        "side": "buy", // Buy/Sell Direction
        "price": 32.233, // Unit Price
        "vol": 232, // Quantity
        "amount": 323, // Total Amount
        "ds": "2017-09-1023: 12: 21"
      }
    ]
  }
}
```

### Subscribe to K-line market data

> Subscription example

```json
{
  "event": "sub",
  "params": {
    "channel": "market_$symbol_kline_[1min/5min/15min/30min/60min/1day/1week/1month]", // $symbol E.g. btcusdt
    "cb_id": "1" // Business ID is optional
  }
}
```

> Return example

```json
{
  "channel": "market_$symbol_kline_1min", // 1min represents 1-minute candlestick
  "ts": 1506584998239, // Request time
  "tick": {
    "id": 1506602880, // The starting value of the time scale
    "vol": 1212.12211, // Trading volume
    "open": 2233.22, // Opening price
    "close": 1221.11, // Closing price
    "high": 22322.22, // Highest price
    "low": 2321.22 // Lowest price
  }
}
```

### Subscribe to 24h market ticker

> Subscription Example

```json
{
  "event": "sub",
  "params": {
    "channel": "market_$symbol_ticker", // $symbol E.g. 币币：btcusdt Futures：e_btcusdt
    "cb_id": "1" // Business ID is optional
  }
}
```

> Response example

```json
{
  "channel": "market_$symbol_ticker",
  "ts": 1506584998239, // Request time
  "tick": {
    "amount": 123.1221, // Trading volume
    "vol": 1212.12211, // Trading volume
    "open": 2233.22, // Opening price
    "close": 1221.11, // Closing price
    "high": 22322.22, // Highest price
    "low": 2321.22, // Lowest price
    "rose": -0.2922 // Price change or percentage change
  }
}
```

### Request Historical K-line Data

> Subscription Example

```json
{
  "event": "req",
  "params": {
    "channel": "market_$symbol_kline_[1min/5min/15min/30min/60min/1day/1week/1month]",
    "cb_id": "1",
    "endIdx": "1506602880", // Return the previous pageSize number of records before endIdx. This is optional
    "pageSize": 100 // Optional
  }
}
```

> Response example

```json
{
  "event_rep": "rep",
  "channel": "market_$symbol_kline_5min",
  "cb_id": "Return the same way",
  "ts": 1506584998239, // Request time
  "data": [
    // Up to 300 entries
    {
      "id": 1506602880, // The starting value of the time scale
      "amount": 123.1221, // Trading volume
      "vol": 1212.12211, // Trading volume
      "open": 2233.22, // Opening price
      "close": 1221.11, // Closing price
      "high": 22322.22, // Highest price
      "low": 2321.22 // Lowest price
    },
    {
      "id": 1506602880, // The starting value of the time scale
      "amount": 123.1221, // Trading volume
      "vol": 1212.12211, // Trading volume
      "open": 2233.22, // Opening price
      "close": 1221.11, // Closing price
      "high": 22322.22, // Highest price
      "low": 2321.22 // Lowest price
    }
  ]
}
```

### Request transaction records

> Request example

```json
{
  "event": "req",
  "params": {
    "channel": "market_$symbol_trade_ticker", // $symbol E.g. Spot trading：btcusdt Futures：e_btcusdt
    "cb_id": "1" // Business ID is optional
  }
}
```

> Response example

```json
{
  "event_rep": "rep",
  "channel": "market_$symbol_trade_ticker",
  "cb_id": "Return along the original route",
  "ts": 1506584998239,
  "status": "ok",
  "data": [
    {
      "side": "buy", // Order direction:buy，sell
      "price": 32.233, // Unit Price
      "vol": 232, // Quantity
      "amount": 323 // Total Amount
    },
    {
      "side": "buy", // Order direction:buy，sell
      "price": 32.233, // Unit Price
      "vol": 232, // Quantity
      "amount": 323 // Total Amount
    }
  ]
}
```

# SDK development library

## Java

[JAVA Demo](https://github.com/)

# "Frequently Asked Questions" (FAQ)

## What is the maximum allowable time difference between the timestamp parameter in the API request and the server's received time?

When the server receives a request, it checks the timestamp in the request. If the timestamp is from more than 5000 milliseconds ago, the request is considered invalid. This time window can be customized by sending the optional parameter recvWindow.

## The request header 'X-CH-TS' cannot be empty. How to resolve this?

First, it is recommended to print the`X-CH-TS`header. When an exception occurs, check if`X-CH-TS`is empty. Additionally, it is suggested to optimize the code by checking if`X-CH-TS`is empty before each request.

## Why does the signature authentication always return an invalid signature?

You can print the request header information and the string before signing. Key points to focus on are as follows:

- Compare your request headers with the following sample request headers one by one

```json
Example of request headers：

Content-Type: application/json

X-CH-APIKEY: 44c541a1-****-****-****-10fe390df2

X-CH-SIGN: ssseLeefrffraoEQ3yI9qEtI1CZ82ikZ4xSG5Kj8gnl3uw=

X-CH-TS: 1574327555669
```

- Is the API key correctly configured in the program?

- Does the string before signing conform to the standard format? The order of all elements must remain consistent. You can copy the following example and compare it with your string before signing：

> GET example

```http
1588591856950GET/sapi/v1/account
```

> POST example

```http
1588591856950POST/sapi/v1/order/test{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}
```

## Why does the API return ILLEGAL_CONTENT_TYPE(-1017)?

We recommend attaching`Content-Type`in all request headers and setting it to`'application/json'`

## Is there a limit on the API call frequency per second?

There is a limit. You can refer to the documentation for the access frequency limits of each API

## What is the basis for the API access frequency limit?

Personal data access is limited based on the**API-key**, while public data access is limited based on the**IP**. It is important to note that if a user provides valid personal information when requesting public data, the limit will be based on the**API-key**

## How is HTTP status code 429 caused?

Requesting the API exceeds the access frequency limit. It is recommended to reduce the access frequency.

## Will the IP be blocked if the API call exceeds the access frequency limit? How long will the block last?

Under normal circumstances, the IP will not be blocked. Reducing the access frequency should resolve the issue.

## Why did the WebSocket connection get disconnected?

- The WebSocket connection was disconnected because the heartbeat was not added. The client needs to send a pong message to maintain the connection stability
- The WebSocket connection may be disconnected due to network issues, such as the client sending a pong message that the server did not receive, or other network-related causes.
- It is recommended that users implement a WebSocket reconnection mechanism, so that the program can automatically reconnect if the heartbeat (ping/pong) connection is unexpectedly disconnected.

## Why does the user get a Time Out error when requesting the API?

Why does the user get a Time Out error when requesting the API?

## How to get all the trading pairs from the platform?

You can get all the trading pairs from the`/sapi/v1/symbols`endpoint in spot trading.

## Is there a limit on the number of orders or cancellations that can be processed in bulk?

Yes. The bulk API has a limit of 10 orders.

## What is newClientOrderId and what is its purpose?

- newClientOrderId is a custom order ID that you can use to identify your order. After placing the order, you can use the newClientOrderId and call the "Order Information" API to check the order status.
- The user needs to ensure that this ID is unique, as we do not perform duplicate checks. If there are duplicates, only the most recent order can be canceled or queried when performing cancel or order status operations.

## How to get the latest transaction price?

You can get the latest transaction price by fetching the Ticker information. The 'last' value in the returned result is the latest trade price.

## Can the 24-hour trading volume in the Ticker API show negative growth?

Yes, it can. The 24-hour trading volume is a rolling data (with a 24-hour sliding window), and it is possible for the cumulative trading volume and trading value in the later window to be smaller than in the previous window.
