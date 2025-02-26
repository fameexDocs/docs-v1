# 文档说明

## API基本信息

*   本篇 `现货交易` 列出 REST 接口的 baseurl `https://t(:open_url)`。
*   本篇 `合约交易` 列出 REST 接口的 baseurl `https://t(:futures_url)`。
*   所有接口都会返回一个 JSON、object 或者 array。
*   响应中如有数组，数组元素以时间倒序排列，越早的数据越靠前。
*   所有时间、时间戳均为 Unix 时间，单位为**毫秒**。



## 文档入参规范

入参名称的带有红色 <font color="red">\*</font> 号，说明该参数为必传，反之为非必传。

接口对入参字符大小写敏感，在接口中会明确指明。
如写明需要输入大写的币对名称，则需要输入 `BTCUSDT`，输入小写的 `btcusdt` 是不被允许的。

文档中的入参有明确的类型说明，需要按照指定的类型输入。
如 `integer` 类型只能输入数字类型，`3` 的输入是正确的，但 `"3"` 的输入是不被允许的。



## 接口通用信息

*   所有请求基于 Https 协议，请求头信息中 `Content-Type` 需要统一设置为：`'application/json'`。
*   `GET` 方法的接口，参数必须在 `query string` 中发送。
*   `POST` 方法的接口，参数必须在 `request body` 中发送。
*   对参数的顺序不做要求。



## 接口是否需要签名验证

接口类型分为：公共、行情、交易、账户。

*   公共和行情类下的接口无需 API-KEY 或者签名就可访问。
*   交易和账户安全需要 API-KEY 和签名验证后才可访问。
*   签名内容和参数有关，若参数输入错误则会返回提示参数错误或空值。
*   需要签名验证的接口 要在 Header 中添加 `X-CH-SIGN`，`X-CH-APIKEY`，`X-CH-TS` 进行验签。
*   `X-CH-TS`（时间戳），为 Unix 时间，单位为**毫秒**。
*   `X-CH-APIKEY`，用户的 `apiKey`。
*   `X-CH-SIGN`，签名加密钥匙为`secretKey`。签名规则和示例可参照：[签名规则](#需要签名的接口)、[签名示例](#有请求参数的示例)
*   (文档中的 `apiKey`，`secretKey` 均为虚拟值；真实内容需要用户在前台页面的API管理中申请获取)。

| 接口类型     | 鉴权类型     |
| :-----------| :-----------|
| 公共        | NONE        |
| 行情        | NONE        |
| 交易        | TRADE       |
| 账户        | USER\_DATA  |


### 接口鉴权类型

*   每个接口都有自己的鉴权类型，鉴权类型决定了访问时应当进行何种鉴权。
*   如果需要 API-KEY，应当在 HTTP 头中以 `X-CH-APIKEY` 字段传递。
*   API-KEY 与 API-Secret 是大小写敏感的。
*   可以在网页用户中心修改 API-KEY 所具有的权限，例如读取账户信息、发送交易指令、发送提现指令。

| 鉴权类型      | 描述                    | Header                               |
| :------------| :-----------------------| :------------------------------------|
| NONE         | 不需要鉴权的接口          |                                      |
| TRADE        | 需要有效的 API-KEY 和签名 | `X-CH-SIGN`，`X-CH-APIKEY`，`X-CH-TS` |
| USER\_DATA   | 需要有效的 API-KEY 和签名 | `X-CH-SIGN`，`X-CH-APIKEY`，`X-CH-TS` |
| USER\_STREAM | 需要有效的 API-KEY       | `X-CH-APIKEY`，`X-CH-TS`             |
| MARKET\_DATA | 需要有效的 API-KEY       | `X-CH-APIKEY`，`X-CH-TS`             |


<a name="需要签名的接口"></a>

### 需要签名的接口 (TRADE 与 USER\_DATA)

*   调用 `TRADE` 或者 `USER_DATA` 接口时，应当在 HTTP 头中以 `X-CH-SIGN` 字段传递签名参数。
*   `X-CH-SIGN` 签名使用 `HMAC SHA256` 加密算法，API-KEY 所对应的 API-Secret 作为 `HMAC SHA256` 的密钥。
*   `X-CH-SIGN` 的请求头是以 timestamp + method + requestPath + body 字符串（+表示字符串连接）作为操作对象。
*   其中 timestamp 的值与 `X-CH-TS` 请求头相同，method 是请求方法，字母全部大写：`GET`/`POST`。
*   requestPath 是请求接口路径，例如:`sapi/v1/order?symbol=ethusdt&orderID=111000111`。
*   `body` 是请求主体的字符串（post only），如果是 `GET` 请求则 `body` 可省略。
*   签名大小写不敏感。


### 接口示例

下方以接口作为示例，展示接口格式、访问链接和参数说明描述。


#### GET示例 获取服务器时间

`GET https://t(:open_url)/sapi/v1/time`

没有请求参数的 GET

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/time

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:open_url)/sapi/v1/time"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:open_url)/sapi/v1/time");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:open_url)/sapi/v1/time"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:open_url)/sapi/v1/time"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
<?
$url = "https://t(:open_url)/sapi/v1/time";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:open_url)/sapi/v1/time';

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
  console.log('请求错误:', err.message);
});
```

> 返回示例

```json
{
    "timezone": "China Standard Time",
    "serverTime": 1705039779880
}
```

**返回参数**

| 参数名     | 类型   | 示例                  | 描述         |
| :----------| :------| :---------------------| :------------|
| timezone   | string | `China Standard Time` | 服务器时区   |
| serverTime | long   | `1705039779880`       | 服务器时间戳 |



<a name="有请求参数的示例"></a>

#### GET示例 订单查询

`GET https://t(:open_url)/sapi/v1/order`

有请求参数的 GET

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

**请求参数**

| 参数名                             | 类型   | 描述                            |
| :----------------------------------| :------| :-------------------------------|
| orderId<font color="red">\*</font> | string | 订单id                          |
| symbol<font color="red">\*</font>  | string | `小写`币对名称，例如：`ethusdt` |

**API数据**

| Key       | Value                            |
| :---------| :--------------------------------|
| `apiKey`    | vmPUZE6mv9SD5V5e14y7Ju91duEh8A   |
| `secretKey` | 902ae3cb34ecee2779aa4d3e1d226686 |

以下是在 linux bash 环境下使用 echo，openssl 和 curl 工具实现的一个调用接口下单的示例。<font color="red">（其中以上的 `apikey`、`secretKey` 仅供示范，请将其替换为您的真实 `apiKey` 和 `secretKey`）</font>

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/order?orderId=12&symbol=ethusdt

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/order"
QUERY_STRING="?orderId=12&symbol=ethusdt"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API 认证信息
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/order";
            String queryString = "?orderId=12&symbol=ethusdt";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API 认证信息
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 生成当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "GET";

            // 生成签名 (X-CH-SIGN) - GET 请求没有 body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/order"
	queryString := "?orderId=12&symbol=ethusdt"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API 认证信息
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "GET"

	// 生成签名 (X-CH-SIGN) - GET 请求没有 body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// 计算 HMAC-SHA256 签名
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/order"
QUERY_STRING = "?orderId=12&symbol=ethusdt"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API 认证信息
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/order";
$QUERY_STRING = "?orderId=12&symbol=ethusdt";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API 认证信息
$API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/order";
const QUERY_STRING = "?orderId=12&symbol=ethusdt";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API 认证信息
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

> HMAC-SHA256 签名示例

```http
// 切换 Node.js 查看 『JavaScript 代码（归类在 HTTP 下）』
```

```shell
# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')
```

```java
// HMAC-SHA256 签名计算
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
// 计算 HMAC-SHA256 签名
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()
```

```php
// 生成签名 (X-CH-SIGN) - GET 请求没有 body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);
```

```javascript--node
// 生成签名 (X-CH-SIGN) - GET 请求没有 body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");
```

```javascript--node
// JavaScript 代码（归类在 HTTP 下）

let secretKey = pm.environment.get("SecretKey");  // 从环境变量中获取 API 密钥
let timestampString = String(Date.now()); // 生成时间戳（精确到毫秒）
let method = pm.request.method; // 获取请求方法 (GET, POST, etc.)

let fullUrl = pm.request.url.toString();
let requestPath = "/"+fullUrl.split("/").slice(3).join("/"); // 获取 `example.com` 之后的部分

// X-CH-SIGN的请求头是以timestamp + method + requestPath + body字符串（+表示字符串连接）
// body是请求主体的字符串（post only），如果是GET请求则body可省略。
let signPayload = timestampString + method.toUpperCase() + requestPath;
if (method.toUpperCase() === "POST") {
    let body = pm.request.body ? pm.request.body.raw : null; // 获取请求体（如果有）
    if (body) {
        try {
            const parsedBody = JSON.parse(body); // 尝试解析 JSON
            let bodyString = JSON.stringify(parsedBody);
            signPayload += bodyString
        } catch (e) {
            signPayload += body; // 如果不是 JSON，则直接附加原始 body
        }
    } else {
        console.log("POST 方法处理 Body 数据 失败");
    }
}

// 签名使用HMAC SHA256算法，API-KEY所对应的API-Secret作为 HMAC SHA256 的密钥。
const crypto = require('crypto-js'); // 加载 CryptoJS 库
// 计算签名
let signature = crypto.HmacSHA256(signPayload, secretKey).toString(crypto.enc.Hex);

// 设定 Headers
pm.variables.set('xChTs', timestampString);
pm.variables.set('xChSign', signature);
```

> 返回示例

```json
{}
```


#### POST示例  创建测试订单

`POST https://t(:open_url)/sapi/v1/order/test`

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

**请求参数**

| 参数名 | 示例    |
| :------| :-------|
| symbol | BTCUSDT |
| side   | BUY     |
| type   | LIMIT   |
| volume | 1       |
| price  | 9300    |

**API数据**

| Key       | Value                            |
| :---------| :--------------------------------|
| `apiKey`    | vmPUZE6mv9SD5V5e14y7Ju91duEh8A   |
| `secretKey` | 902ae3cb34ecee2779aa4d3e1d226686 |

以下是在 linux bash 环境下使用 echo，openssl 和 curl 工具实现的一个调用接口下单的示例。<font color="red">（其中以上的 `apikey`、`secretKey` 仅供示范，请将其替换为您的真实 `apiKey` 和 `secretKey`）</font>

> 请求示例

```http
POST https://t(:open_url)/sapi/v1/order/test

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
URL="https://t(:open_url)"
REQUEST_PATH="/sapi/v1/order/test"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="POST"

# 定义请求体 (JSON 格式)
BODY_JSON='{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}'

# 生成签名 (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# 发送请求
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
            // API 相关信息
            String url = "https://t(:open_url)";
            String requestPath = "/sapi/v1/order/test";
            String apiUrl = url + requestPath;\
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 获取当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "POST";

            // 定义请求体 (JSON 格式)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"price\":\"9300\",\"volume\":\"1\",\"side\":\"BUY\",\"type\":\"LIMIT\"}";

            // 生成签名 (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // 发送请求
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP POST 请求
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

            // 发送请求体
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // 读取响应
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
	// API 相关信息
    url := "https://t(:open_url)"
    requestPath := "/sapi/v1/order/test"
	apiURL := url + requestPath
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "POST"

	// 定义请求体 (JSON 格式)
	bodyJSON := `{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}`

	// 生成签名 (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// 发送请求
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 签名计算
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP POST 请求
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
URL = "https://t(:open_url)"
REQUEST_PATH = "/sapi/v1/order/test"
API_URL = URL + REQUEST_PATH
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "POST"

# 定义请求体 (JSON 格式)
body_json = {
    "symbol": "BTCUSDT",
    "price": "9300",
    "volume": "1",
    "side": "BUY",
    "type": "LIMIT"
}
body_str = json.dumps(body_json, separators=(',', ':'))  # 确保 JSON 字符串格式正确

# 生成签名 (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# 发送请求
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$url = "https://t(:open_url)";
$request_path = "/sapi/v1/order/test";
$api_url = $url . $request_path;
$api_key = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$api_secret = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$method = "POST";

// 定义请求体 (JSON 格式)
$body_json = json_encode([
    "symbol" => "BTCUSDT",
    "price" => "9300",
    "volume" => "1",
    "side" => "BUY",
    "type" => "LIMIT"
], JSON_UNESCAPED_SLASHES); // 确保 JSON 格式正确

// 生成签名 (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// 发送请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 POST 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const URL = "https://t(:open_url)";
const REQUEST_PATH = "/sapi/v1/order/test";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "POST";

// 定义请求体 (JSON 格式)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  price: "9300",
  volume: "1",
  side: "BUY",
  type: "LIMIT",
});

// 生成签名 (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// 发送请求
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
{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}
```

> HMAC-SHA256 签名示例

```http
// 切换 Node.js 查看 『JavaScript 代码（归类在 HTTP 下）』
```

```shell
# 生成 X-CH-SIGN 签名指令
echo -n "1739520816000POST/sapi/v1/order/test{\"symbol\":\"BTCUSDT\",\"price\":\"9300\",\"volume\":\"1\",\"side\":\"BUY\",\"type\":\"LIMIT\"}" | openssl dgst -sha256 -hmac "709f1e13068f5e51123252d1e6851117"

# 生成 X-CH-SIGN 签名数据
(stdin)= e496db94ec168f23d836d7c7be7223135e6fe6d9593e9c985a9e4017ed78a3f3
```

```java
// HMAC-SHA256 签名计算
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
// HMAC-SHA256 签名计算
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
```

```python
# 生成签名 (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()
```

```php
// 生成签名 (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);
```

```javascript--node
// 生成签名 (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");
```

```javascript--node
// JavaScript 代码（归类在 HTTP 下）

let secretKey = pm.environment.get("SecretKey");  // 从环境变量中获取 API 密钥
let timestampString = String(Date.now()); // 生成时间戳（精确到毫秒）
let method = pm.request.method; // 获取请求方法 (GET, POST, etc.)

let fullUrl = pm.request.url.toString();
let requestPath = "/"+fullUrl.split("/").slice(3).join("/"); // 获取 `example.com` 之后的部分

// X-CH-SIGN的请求头是以timestamp + method + requestPath + body字符串（+表示字符串连接）
// body是请求主体的字符串（post only），如果是GET请求则body可省略。
let signPayload = timestampString + method.toUpperCase() + requestPath;
if (method.toUpperCase() === "POST") {
    let body = pm.request.body ? pm.request.body.raw : null; // 获取请求体（如果有）
    if (body) {
        try {
            const parsedBody = JSON.parse(body); // 尝试解析 JSON
            let bodyString = JSON.stringify(parsedBody);
            signPayload += bodyString
        } catch (e) {
            signPayload += body; // 如果不是 JSON，则直接附加原始 body
        }
    } else {
        console.log("POST 方法处理 Body 数据 失败");
    }
}

// 签名使用HMAC SHA256算法，API-KEY所对应的API-Secret作为 HMAC SHA256 的密钥。
const crypto = require('crypto-js'); // 加载 CryptoJS 库
// 计算签名
let signature = crypto.HmacSHA256(signPayload, secretKey).toString(crypto.enc.Hex);

// 设定 Headers
pm.variables.set('xChTs', timestampString);
pm.variables.set('xChSign', signature);
```

> 返回示例

```json
{}
```

## HTTP返回代码的类型

*   `HTTP 4XX` 错误码用于指示错误的请求内容、行为、格式。
*   `HTTP 429` 错误码表示警告访问频次超限，即将被封IP。
*   `HTTP 418` 表示收到 `429` 后继续访问，于是被封了。
*   `HTTP 5XX` 返回错误码是内部系统错误；这说明这个问题是在服务器这边。在对待这个错误时，**千万**不要把它当成一个失败的任务，因为执行状态未知，有可能是成功也有可能是失败。
*   `HTTP 504` 表示 API 服务端已经向业务核心提交了请求但未能获取响应，特别需要注意的是 `504` 代码不代表请求失败，而是未知。很可能已经得到了执行，也有可能执行失败，需要做进一步确认。
*   任何接口都可能返回 ERROR（错误）；错误的返回 `payload` 如下：

> 返回示例

```json
{
    "code": -1121,
    "msg": "Invalid symbol."
}
```

其馀详见 [返回码类型](#返回码类型)



## 访问限制

*   在每个接口下面会有限频的说明。
*   违反频率限制都会收到 `HTTP 429`，这是一个警告。
*   当收到 `HTTP 429` 告警时，调用者应当降低访问频率或者停止访问。



## 时间同步安全

*   签名接口均需要在HTTP头中以 `X-CH-TS` 字段传递时间戳，其值应当是请求发送时刻的Unix时间戳（毫秒），E.g. `1528394129373`。
*   服务器收到请求时会判断请求中的时间戳，如果是 `5000` 毫秒之前发出的，则请求会被认为无效。这个时间窗口值可以通过发送可选参数 `recvWindow` 来自定义。
*   另外，如果服务器计算得出客户端时间戳在服务器时间的 `未来` 一秒以上，也会拒绝请求。

> Java 逻辑伪代码：

```
if (timestamp < (serverTime + 1000) && (serverTime - timestamp) <= recvWindow) {
  // process request
} else {
  // reject request
}
```

<aside class="notice">关于交易时效性：互联网状况并不100%可靠，不可完全依赖，因此你的程序本地到交易所服务器的时延会有抖动。这是我们设置<code>recvWindow</code>的目的所在，如果你从事高频交易，对交易时效性有较高的要求，可以灵活设置<code>recvWindow</code>以达到你的要求。不推荐使用5秒以上的<code>recvWindow</code>。</aside>






<a name="返回码类型"></a>

# 返回码类型

异常码和错误码的描述和原因

<aside class="warning">以下返回内容均为基本参数校验，若返回码不包含在以下列出的返回码类型中，则为业务层以外的错误提示返回，需要联系技术人员进行处理。</aside>

## 10XX - 通用服务器和网络错误

### Code:-1000 UNKNOWN

| Code  | Tag           | msg                    | 原因                   |
| :-----| :-------------| :----------------------| :----------------------|
| 1000  | UNKNOWN       | 处理请求时发生未知错误     | 处理请求时发生未知错误    |

### Code:-1001 DISCONNECTED

| Code  | Tag           | msg                              | 原因                  |
| :-----| :-------------| :--------------------------------| :---------------------|
| 1001  | DISCONNECTED  | 内部错误；无法处理您的请求。请再试一次 | 内部错误；无法处理您的请求 |

### Code:-1002 UNAUTHORIZED

| Code  | Tag           | msg                              | 原因                  |
| :-----| :-------------| :--------------------------------| :---------------------|
| 1002  | UNAUTHORIZED  | 您无权执行此请求。请求需要发送 API Key，我们建议在所有的请求头附加 `X-CH-APIKEY` | 请求头中缺少 `X-CH-APIKEY` |

### Code:-1003 TOO\_MANY\_REQUESTS

| Code  | Tag                 | msg                   | 原因                 |
| :-----| :-------------------| :---------------------| :-------------------|
| 1003  | TOO\_MANY\_REQUESTS | 请求过于频繁超过限制     | 请求过于频繁超过限制    |

### Code:-1004 NO\_THIS\_COMPANY

| Code  | Tag               | msg                         | 原因                         |
| :-----| :-----------------| :---------------------------| :----------------------------|
| 1004  | NO\_THIS\_COMPANY | 您无权执行此请求 user not exit | 您无权执行此请求 user not exit |

### Code:-1006 UNEXPECTED\_RESP

| Code  | Tag              | msg                                 | 原因                                |
| :-----| :----------------| :-----------------------------------| :-----------------------------------|
| 1006  | UNEXPECTED\_RESP | 接收到了不符合预设格式的消息，下单状态未知 | 接收到了不符合预设格式的消息，下单状态未知 |

### Code:-1007 TIMEOUT

| Code  | Tag              | msg                                        | 原因    |
| :-----| :----------------| :------------------------------------------| :------|
| 1007  | TIMEOUT          | 等待后端服务器响应超时。发送状态未知；执行状态未知 | 请求超时 |

### Code:-1014 UNKNOWN\_ORDER\_COMPOSITION

| Code  | Tag                         | msg           | 原因                            |
| :-----| :---------------------------| :-------------| :------------------------------|
| 1014  | UNKNOWN\_ORDER\_COMPOSITION | 不支持的订单组合 | 订单组合不存在或输入了错误的订单组合 |

### Code:-1015 TOO\_MANY\_ORDERS

| Code  | Tag               | msg                     | 原因                  |
| :-----| :-----------------| :-----------------------| :--------------------|
| 1015  | TOO\_MANY\_ORDERS | 订单太多。请减少你的订单数量 | 下单数量超过最大数量限制 |

### Code:-1016 SERVICE\_SHUTTING\_DOWN

| Code  | Tag                     | msg      | 原因                     |
| :-----| :-----------------------| :--------| :------------------------|
| 1016  | SERVICE\_SHUTTING\_DOWN | 服务器下线 | 服务器已下线，无法访问该接口 |

### Code:-1017 NO\_CONTENT\_TYPE

| Code  | Tag               | msg                                                        | 原因                   |
| :-----| :-----------------| :----------------------------------------------------------| :----------------------|
| 1017  | NO\_CONTENT\_TYPE | 我们建议在所有的请求头附加Content-Type，并设置成application/json | 请求头中缺少Content-Type |

### Code:-1020 UNSUPPORTED\_OPERATION

| Code  | Tag                    | msg        | 原因                                     |
| :-----| :----------------------| :----------| :----------------------------------------|
| 1020  | UNSUPPORTED\_OPERATION | 不支持此操作 | 进行了错误的请求操作，需要同技术团队进行对接解决 |

### Code:-1021 INVALID\_TIMESTAMP

| Code  | Tag                | msg                   | 原因                                                                 |
| :-----| :------------------| :----------------------| :-------------------------------------------------------------------|
| 1021  | INVALID\_TIMESTAMP | 无效的时间戳，时间偏移过大 | 时间戳偏移偏大，服务器根据请求中的时间戳判定客户端时间比服务器时间提前了1秒钟以上 |

### Code:-1022 INVALID\_SIGNATURE

| Code  | Tag                | msg      | 原因        |
| :-----| :------------------| :--------| :----------|
| 1022  | INVALID\_SIGNATURE | 无效的签名 | 签名验证失败 |

### Code:-1023 UNAUTHORIZED

| Code  | Tag          | msg                                                                  | 原因                  |
| :-----| :------------| :--------------------------------------------------------------------| :--------------------|
| 1023  | UNAUTHORIZED | 您无权执行此请求。请求需要发送 timestamp，我们建议在所有的请求头附加 `X-CH-TS` | 请求头中缺少 `X-CH-TS` |

### Code:-1024 UNAUTHORIZED

| Code  | Tag          | msg                                                               | 原因                    |
| :-----| :------------| :-----------------------------------------------------------------| :----------------------|
| 1024  | UNAUTHORIZED | 您无权执行此请求。请求需要发送 sign，我们建议在所有的请求头附加 `X-CH-SIGN` | 请求头中缺少 `X-CH-SIGN` |


## 11XX - 请求内容中的问题

### Code:-1100 ILLEGAL\_CHARS

| Code  | Tag            | msg             | 原因             |
| :-----| :--------------| :---------------| :---------------|
| 1100  | ILLEGAL\_CHARS | 请求中存在非法字符 | 请求中存在非法字符 |

### Code:-1101 TOO\_MANY\_PARAMETERS

| Code  | Tag                   | msg          | 原因                        |
| :-----| :---------------------| :------------| :--------------------------|
| 1101  | TOO\_MANY\_PARAMETERS | 发送的参数太多 | 参数内容过多或检测到的参数值重复 |

### Code:-1102 MANDATORY\_PARAM\_EMPTY\_OR\_MALFORMED

| Code  | Tag                                    | msg                           | 原因                              |
| :-----| :--------------------------------------| :-----------------------------| :---------------------------------|
| 1102  | MANDATORY\_PARAM\_EMPTY\_OR\_MALFORMED | 强制参数{0}未发送，为空/或格式错误 | 参数为空，必传参数未传或不正确的入参格式 |

### Code:-1103 UNKNOWN\_PARAM

| Code  | Tag            | msg          | 原因                                             |
| :-----| :--------------| :------------| :------------------------------------------------|
| 1103  | UNKNOWN\_PARAM | 发送了未知参数 | 请求参数中的参数内容或者格式错误，请检查是否字段中包含空格 |

### Code:-1104 UNREAD\_PARAMETERS

| Code  | Tag                | msg                   | 原因                                                 |
| :-----| :------------------| :----------------------| :--------------------------------------------------|
| 1104  | UNREAD\_PARAMETERS | 并非所有发送的参数都被读取 | 并非所有发送的参数都被读取；读取了'％s'参数，但被发送了'％s' |

### Code:-1105 PARAM\_EMPTY

| Code  | Tag          | msg        | 原因       |
| :-----| :------------| :----------| :----------|
| 1105  | PARAM\_EMPTY | 参数{0}为空 | 必传参数为空 |

### Code:-1106 PARAM\_NOT\_REQUIRED

| Code  | Tag                  | msg           | 原因              |
| :-----| :--------------------| :-------------| :----------------|
| 1106  | PARAM\_NOT\_REQUIRED | 不需要发送此参数 | 不需要发送参数'％s' |

### Code:-1111 BAD\_PRECISION

| Code  | Tag            | msg                   | 原因                    |
| :-----| :--------------| :---------------------| :----------------------|
| 1111  | BAD\_PRECISION | 精度超过此资产定义的最大值 | 精度超过此资产定义的最大值 |

### Code:-1112 NO\_DEPTH

| Code  | Tag       | msg         | 原因                |
| :-----| :---------| :------------| :------------------|
| 1112  | NO\_DEPTH | 交易对没有挂单 | 需要取消的该订单不存在 |

### Code:-1116 INVALID\_ORDER\_TYPE

| Code  | Tag                  | msg        | 原因        |
| :-----| :--------------------| :----------| :----------|
| 1116  | INVALID\_ORDER\_TYPE | 无效订单类型 | 无效订单类型 |

### Code:-1117 INVALID\_SIDE

| Code  | Tag           | msg        | 原因        |
| :-----| :-------------| :----------| :----------|
| 1117  | INVALID\_SIDE | 无效买卖方向 | 无效买卖方向 |

### Code:-1121 BAD\_SYMBOL

| Code  | Tag         | msg      | 原因                          |
| :-----| :-----------| :--------| :----------------------------|
| 1121  | BAD\_SYMBOL | 无效的合约 | 币对名称输入错误或合约名称输入错误 |

### Code:-1136 ORDER\_QUANTITY\_TOO\_SMALL

| Code  | Tag                         | msg             | 原因                 |
| :-----| :---------------------------| :---------------| :--------------------|
| 1136  | ORDER\_QUANTITY\_TOO\_SMALL | 订单数量小于最小值 | 订单quantity小于最小值 |

### Code:-1138 ORDER\_PRICE\_WAVE\_EXCEED

| Code  | Tag                        | msg               | 原因              |
| :-----| :--------------------------| :-----------------| :----------------|
| 1138  | ORDER\_PRICE\_WAVE\_EXCEED | 订单价格超出允许范围 | 订单价格超出允许范围 |

### Code:-1139 ORDER\_NOT\_SUPPORT\_MARKET

| Code  | Tag                         | msg               | 原因               |
| :-----| :---------------------------| :-----------------| :------------------|
| 1139  | ORDER\_NOT\_SUPPORT\_MARKET | 该币对不支持市价交易 | 该交易对不支持市价交易 |

### Code:-1145 ORDER\_NOT\_SUPPORT\_CANCELLATION

| Code  | Tag                               | msg               | 原因          |
| :-----| :---------------------------------| :-----------------| :-------------|
| 1145  | ORDER\_NOT\_SUPPORT\_CANCELLATION | 该订单状态不允许撤销 | 订单不能够被取消 |

### Code:-1147 PRICE\_VOLUME\_PRESION\_ERROR

| Code  | Tag                           | msg                   | 原因                     |
| :-----| :-----------------------------| :---------------------| :------------------------|
| 1147  | PRICE\_VOLUME\_PRESION\_ERROR | 价格或数量精度超过最大限制 | 订单的价格或数量超过最大限制 |


## 2XXX - 其他相关返回码

### Code:-2013 NO\_SUCH\_ORDER

| Code  | Tag             | msg      | 原因      |
| :-----| :---------------| :--------| :---------|
| 2013  | NO\_SUCH\_ORDER | 订单不存在 | 订单不存在 |

### Code:-2015 REJECTED\_API\_KEY

| Code  | Tag                | msg                     | 原因          |
| :-----| :------------------| :-----------------------| :------------|
| 2015  | REJECTED\_API\_KEY | 无效的API密钥，IP或操作权限 | 签名或IP不通过 |

### Code:-2016 EXCHANGE\_LOCK

| Code  | Tag            | msg      | 原因           |
| :-----| :--------------| :--------| :-------------|
| 2016  | EXCHANGE\_LOCK | 交易被冻结 | 该用户交易被冻结 |

### Code:-2017 BALANCE\_NOT\_ENOUGH

| Code  | Tag                  | msg    | 原因              |
| :-----| :--------------------| :-------| :----------------|
| 2017  | BALANCE\_NOT\_ENOUGH | 余额不足 | 用户该账户中余额不足 |

### Code:-2100 PARAM\_ERROR

| Code  | Tag          | msg     | 原因       |
| :-----| :------------| :-------| :----------|
| 2100  | PARAM\_ERROR | 参数问题 | 参数输入错误 |

### Code:-2200 ORDER\_CREATE\_FAILS

| Code  | Tag                  | msg        | 原因       |
| :-----| :--------------------| :----------| :----------|
| 2200  | ORDER\_CREATE\_FAILS | Illegal IP | 不是信任的IP |

### Code:35

| Code  | Tag     | msg     | 原因            |
| :-----| :-------| :-------| :--------------|
| 35    |         | 禁止下单 | 用户交易可能被限制 |

# 枚举类型

## 交易对

| 值      | 说明                                    |
| :-------| :--------------------------------------|
| `base`  | 指一个交易对的交易对象，即写在靠前部分的资产名 |
| `quote` | 指一个交易对的定价资产，即写在靠后部分资产名   |

## 订单状态

| 值                           | 说明           |
| :----------------------------| :-------------|
| `New Order`                  | 新建订单       |
| `Partially Filled`           | 部分成交       |
| `Filled`                     | 全部成交       |
| `Cancelled`                  | 已撤销         |
| `To be Cancelled`            | 正在撤销中     |
| `Partially Filled/Cancelled` | 部分成交/已取消 |
| `REJECTED`                   | 订单被拒绝     |

## 订单种类

| 值        | 说明  |
| :--------| :-----|
| `LIMIT`  | 限价单 |
| `MARKET` | 市价单 |

## 订单方向

| 值     | 说明 |
| :------| :---|
| `BUY`  | 买单 |
| `SELL` | 卖单 |

## K线间隔

| 值      | 说明  | 示例                                      |
| :-------| :----| :----------------------------------------|
| `min`   | 分钟 | `1min`, `5min`, `15min`, `30min`, `60min` |
| `h`     | 小时 | `1h`, `4h`                                |
| `day`   | 天   | `1day`                                    |
| `week`  | 周   | `1week`                                   |
| `month` | 月   |                                           |



# 现货交易

## 公共

### 安全类型: None

<aside class='notice'>公共类型接口不需要API-key或者签名就能自由访问。</aside>

### 测试连接

`GET https://t(:open_url)/sapi/v1/ping`

测试REST API的连通性

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/ping

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:open_url)/sapi/v1/ping"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:open_url)/sapi/v1/ping");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:open_url)/sapi/v1/ping"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:open_url)/sapi/v1/ping"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
<?
$url = "https://t(:open_url)/sapi/v1/ping";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:open_url)/sapi/v1/ping';

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
  console.log('请求错误:', err.message);
});
```

> 返回示例

```json
{}
```

### 服务器时间

`GET https://t(:open_url)/sapi/v1/time`

获取服务器时间

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/time

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:open_url)/sapi/v1/time"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:open_url)/sapi/v1/time");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:open_url)/sapi/v1/time"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:open_url)/sapi/v1/time"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
<?
$url = "https://t(:open_url)/sapi/v1/time";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:open_url)/sapi/v1/time';

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
  console.log('请求错误:', err.message);
});
```

> 返回示例

```json
{
    "timezone": "China Standard Time",
    "serverTime": 1705039779880
}
```


**返回参数**

| 参数名     | 类型   | 示例                  | 描述         |
| :----------| :------| :---------------------| :------------|
| timezone   | string | `China Standard Time` | 服务器时区   |
| serverTime | long   | `1705039779880`       | 服务器时间戳 |


<a name="现货交易-公共-币对列表"></a>

### 币对列表

`GET https://t(:open_url)/sapi/v1/symbols`

获取市场支持的币对集合

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/symbols

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:open_url)/sapi/v1/symbols"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:open_url)/sapi/v1/symbols");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:open_url)/sapi/v1/symbols"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:open_url)/sapi/v1/symbols"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
<?
$url = "https://t(:open_url)/sapi/v1/symbols";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:open_url)/sapi/v1/symbols';

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
  console.log('请求错误:', err.message);
});
```

> 返回示例

```json
{
    "symbols": [
        {
            "quantityPrecision": 3,
            "limitVolumeMin": 0.0001,
            "symbol": "sccadai",
            "pricePrecision": 6,
            "marketBuyMin": 0.0001,
            "marketSellMin": 0.0001,
            "baseAsset": "SCCA",
            "limitPriceMin": 0.001,
            "quoteAsset": "DAI"
        },
        {
            "quantityPrecision": 8,
            "limitVolumeMin": 0.0001,
            "symbol": "btcusdt",
            "pricePrecision": 2,
            "marketBuyMin": 0.0001,
            "marketSellMin": 0.0001,
            "baseAsset": "BTC",
            "limitPriceMin": 0.001,
            "quoteAsset": "USDT"
        },
        {
            "quantityPrecision": 3,
            "limitVolumeMin": 0.0001,
            "symbol": "bchusdt",
            "pricePrecision": 2,
            "marketBuyMin": 0.0001,
            "marketSellMin": 0.0001,
            "baseAsset": "BCH",
            "limitPriceMin": 0.001,
            "quoteAsset": "USDT"
        },
        {
            "quantityPrecision": 2,
            "limitVolumeMin": 0.0001,
            "symbol": "etcusdt",
            "pricePrecision": 2,
            "marketBuyMin": 0.0001,
            "marketSellMin": 0.0001,
            "baseAsset": "ETC",
            "limitPriceMin": 0.001,
            "quoteAsset": "USDT"
        },
        {
            "quantityPrecision": 2,
            "limitVolumeMin": 0.0001,
            "symbol": "ltcbtc",
            "pricePrecision": 6,
            "marketBuyMin": 0.0001,
            "marketSellMin": 0.0001,
            "baseAsset": "LTC",
            "limitPriceMin": 0.001,
            "quoteAsset": "BTC"
        }
    ]
}
```

**返回参数**

| 参数名            | 类型       | 示例      | 描述               |
| :-----------------| :----------| :---------| :------------------|
| symbol            | string     | `btcusdt` | `小写`币对名称     |
| baseAsset         | string     | `BTC`     | `基准货币`         |
| quoteAsset        | string     | `USDT`    | `计价货币`         |
| pricePrecision    | integer    | `6`       | 价格精度           |
| quantityPrecision | integer    | `3`       | 数量精度           |
| limitVolumeMin    | BigDecimal | `0.0001`  | 限价单最小数量限制 |
| marketBuyMin      | BigDecimal | `0.0001`  | 市价单最小购买数量 |
| marketSellMin     | BigDecimal | `0.0001`  | 市价单最小卖出数量 |
| limitPriceMin     | BigDecimal | `0.001`   | 限价单最小价格限制 |


## 行情

### 安全类型: None

<aside class='notice'>行情下方的接口不需要API-Key或者签名就能自由访问。</aside>

### 订单薄

`GET https://t(:open_url)/sapi/v1/depth`

获取市场订单薄深度信息

**请求参数**

| 参数名                            | 类型    | 描述                            |
| :---------------------------------| :-------| :-------------------------------|
| symbol<font color="red">\*</font> | string  | `大写`币对名称，例如：`BTCUSDT` |
| limit                             | integer | 默认：100；最大：100            |


> 请求示例

```http
GET https://t(:open_url)/sapi/v1/depth?symbol=BTCUSDT&limit=100

// Headers 设定
Content-Type: application/json
```


```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/depth"
QUERY_STRING="?symbol=BTCUSDT&limit=100"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# 定义请求方法
METHOD="GET"

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/depth";
            String queryString = "?symbol=BTCUSDT&limit=100";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // 请求方法
            String method = "GET";

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/depth"
	queryString := "?symbol=BTCUSDT&limit=100"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// 请求方法
	method := "GET"

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, method)
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/depth"
QUERY_STRING = "?symbol=BTCUSDT&limit=100"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **打印调试信息**
print("==== 请求信息 ====")
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/depth";
$QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/depth";
const QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

> 返回示例

```json
{
    "time": 1701658276000,
    "bids": [
        [
            3.90000000,     // 价格
            43.10000000    // 数量
        ],
        [
            4.00000000,
            19.20000000
        ]
    ],
    "asks": [
        [
            4.00000200,     // 价格
            12.00000000     // 数量
        ],
        [
            5.10000000,
            28.00000000
        ]
    ]
}
```

**返回参数**

| 参数名 | 类型  | 示例                      | 描述                                                                                          |
| :------| :-----| :-------------------------| :---------------------------------------------------------------------------------------------|
| time   | long  | `1595563624731`           | 当前时间戳                                                                                    |
| bids   | array | `[[3.9,43.1],[4.0,19.2]]` | 订单薄买盘信息，数组长度为2，角标1为价格，类型为float；角标2为当前价格对应的数量，类型为float |
| asks   | array | `[[4.0,12.0],[5.1,28.0]]` | 订单薄卖盘信息，数组长度为2，角标1为价格，类型为float；角标2为当前价格对应的数量，类型为float |


bids和asks所对应的信息代表了订单薄的所有价格以及价格对应的数量的信息, 由最优价格从上到下排列

### 行情Ticker

`GET https://t(:open_url)/sapi/v1/ticker`

获取24小时价格变化数据

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/ticker?symbol=BTCUSDT

// Headers 设定
Content-Type: application/json
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/ticker"
QUERY_STRING="?symbol=BTCUSDT"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# 定义请求方法
METHOD="GET"

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/ticker";
            String queryString = "?symbol=BTCUSDT";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // 请求方法
            String method = "GET";

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/ticker"
	queryString := "?symbol=BTCUSDT"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// 请求方法
	method := "GET"

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, method)
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/ticker"
QUERY_STRING = "?symbol=BTCUSDT"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **打印调试信息**
print("==== 请求信息 ====")
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/ticker";
$QUERY_STRING = "?symbol=BTCUSDT";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/ticker";
const QUERY_STRING = "?symbol=BTCUSDT";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

**请求参数**

| 参数名                            | 类型   | 描述                          |
| :---------------------------------| :------| :-----------------------------|
| symbol<font color="red">\*</font> | string | 大写币对名称，例如：`BTCUSDT` |

> 返回示例

```json
{
    "amount": 22400.0,
    "high": 9900.51,
    "vol": 4691.0,
    "last": 9211.60,
    "low": 9100.34,
    "buy": 9210.0,
    "sell": 9213.0,
    "rose": "+0.05",
    "time": 1595563624731
}
```

**返回参数**

| 参数名 | 类型   | 示例            | 描述                                      |
| :------| :------| :---------------| :-----------------------------------------|
| time   | long   | `1595563624731` | 当前时间戳                                |
| high   | float  | `9900.51`       | 最高价                                    |
| low    | float  | `9100.34`       | 最低价                                    |
| last   | float  | `9211.60`       | 最新成交价                                |
| vol    | float  | `4691.0`        | 交易量                                    |
| amount | float  | `22400.0`       | 交易额                                    |
| buy    | float  | `9210.0`        | 买一价格                                  |
| sell   | float  | `9213.0`        | 卖一价格                                  |
| rose   | string | `+0.05`         | 涨跌幅，`+`为涨，`-`为跌，`+0.05`为涨`5%` |

<a name="现货交易-行情-最近成交"></a>

### 最近成交

`GET https://t(:open_url)/sapi/v1/trades`

获取最近成交数据

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/trades?symbol=BTCUSDT&limit=10

// Headers 设定
Content-Type: application/json
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/trades"
QUERY_STRING="?symbol=BTCUSDT&limit=10"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# 定义请求方法
METHOD="GET"

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/trades";
            String queryString = "?symbol=BTCUSDT&limit=10";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // 请求方法
            String method = "GET";

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/trades"
	queryString := "?symbol=BTCUSDT&limit=10"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// 请求方法
	method := "GET"

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, method)
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/trades"
QUERY_STRING = "?symbol=BTCUSDT&limit=10"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **打印调试信息**
print("==== 请求信息 ====")
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/trades";
$QUERY_STRING = "?symbol=BTCUSDT&limit=10";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/trades";
const QUERY_STRING = "?symbol=BTCUSDT&limit=10";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

**请求参数**

| 参数名                            | 类型   | 描述                            |
| :---------------------------------| :------| :-------------------------------|
| symbol<font color="red">\*</font> | string | `大写`币对名称，例如：`BTCUSDT` |
| limit                             | string | 默认：100；最大：1000               |

> 返回示例

```json
[
    {
        "side": "buy",
        "price": 131.0000000000000000,
        "qty": 0.1000000000000000,
        "time": 1704788645416
    },
    {
        "side": "sell",
        "price": 132.0000000000000000,
        "qty": 0.2000000000000000,
        "time": 1704788282332
    }
]
```

**返回参数**

| 参数名 | 类型   | 示例                   | 描述         |
| :------| :------| :----------------------| :------------|
| price  | float  | `131.0000000000000000` | 交易价格     |
| time   | long   | `1704788645416`        | 当前时间戳   |
| qty    | float  | `0.1000000000000000`   | 数量（张数） |
| side   | string | `buy/sell`             | 主动单方向   |

### K线/蜡烛图数据

`GET https://t(:open_url)/sapi/v1/klines`

获取K线数据

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/klines?symbol=BTCUSDT&interval=1min&limit=5

// Headers 设定
Content-Type: application/json
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/klines"
QUERY_STRING="?symbol=BTCUSDT&interval=1min&limit=5"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# 定义请求方法
METHOD="GET"

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/klines";
            String queryString = "?symbol=BTCUSDT&interval=1min&limit=5";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // 请求方法
            String method = "GET";

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/klines"
	queryString := "?symbol=BTCUSDT&interval=1min&limit=5"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// 请求方法
	method := "GET"

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, method)
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, method string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/klines"
QUERY_STRING = "?symbol=BTCUSDT&interval=1min&limit=5"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# **打印调试信息**
print("==== 请求信息 ====")
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/klines";
$QUERY_STRING = "?symbol=BTCUSDT&interval=1min&limit=5";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/klines";
const QUERY_STRING = "?symbol=BTCUSDT&interval=1min&limit=5";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

**请求参数**

| 参数名                              | 类型    | 描述                                                                                                                                 |
| :-----------------------------------| :-------| :------------------------------------------------------------------------------------------------------------------------------------|
| symbol<font color="red">\*</font>   | string  | `大写`币对名称，例如：`BTCUSDT`                                                                                                      |
| interval<font color="red">\*</font> | string  | K线图区间，可识别发送的值为：`1min`，`5min`，`15min`，`30min`，`60min`，`1day`，`1week`，`1month`（min=分钟，day=天，week=星期，month=月） |
| limit                               | integer | 默认：100；最大：300                                                                                                                     |

> 返回示例

```json
[
    {
        "high": 6228.77,
        "vol": 2456.11,
        "low": 6220.13,
        "idx": 1594640340000,
        "close": 6225.63,
        "open": 6129.41
    },
    {
        "high": 6228.77,
        "vol": 1700.21,
        "low": 6228.77,
        "idx": 1587632160000,
        "close": 6228.77,
        "open": 6228.77
    },
    {
        "high": 6228.77,
        "vol": 1908.52,
        "low": 6228.77,
        "idx": 1587632100000,
        "close": 6228.77,
        "open": 6228.77
    }
]
```

**返回参数**

| 参数名 | 类型  | 示例            | 描述       |
| :------| :-----| :---------------| :----------|
| idx    | long  | `1538728740000` | 开始时间戳 |
| open   | float | `6129.41`       | 开盘价     |
| close  | float | `6225.63`       | 收盘价     |
| high   | float | `6228.77`       | 最高价     |
| low    | float | `6220.13`       | 最低价     |
| vol    | float | `2456.11`       | 成交量     |

## 交易

### 安全类型: TRADE

<aside class='notice'>交易下方的接口都需要签名和API-key验证。</aside>

### 创建新订单

`POST https://t(:open_url)/sapi/v1/order`

**限速规则: 100次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:open_url)/sapi/v1/order

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
URL="https://t(:open_url)"
REQUEST_PATH="/sapi/v1/order"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="POST"

# 定义请求体 (JSON 格式)
BODY_JSON='{"symbol":"BTCUSDT","volume":0.00001,"side":"BUY","type":"LIMIT","price":97081.19,"newClientOrderId":"111000000111"}'

# 生成签名 (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# 发送请求
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
            // API 相关信息
            String url = "https://t(:open_url)";
            String requestPath = "/sapi/v1/order";
            String apiUrl = url + requestPath;
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 获取当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法和路径
            String method = "POST";

            // 定义请求体 (JSON 格式)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"volume\":\"0.00001\",\"side\":\"BUY\",\"type\":\"LIMIT\",\"price\":\"97081.19\",\"newClientOrderId\":\"111000000111\"}";

            // 生成签名 (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // 发送请求
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP POST 请求
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

            // 发送请求体
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // 读取响应
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
	// API 相关信息
    url := "https://t(:open_url)"
    requestPath := "/sapi/v1/order"
	apiURL := url + requestPath
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法和路径
	method := "POST"

	// 定义请求体 (JSON 格式)
	bodyJSON := `{"symbol":"BTCUSDT","volume":"0.00001","side":"BUY","type":"LIMIT","price":"97081.19","newClientOrderId":"111000000111"}`

	// 生成签名 (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// 发送请求
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 签名计算
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP POST 请求
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
URL = "https://t(:open_url)"
REQUEST_PATH = "/sapi/v1/order"
API_URL = URL + REQUEST_PATH
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法和路径
METHOD = "POST"


# 定义请求体 (JSON 格式)
body_json = {
    "symbol": "BTCUSDT",
    "volume": "0.00001",
    "side": "BUY",
    "type": "LIMIT",
    "price": "97081.19",
    "newClientOrderId": "111000000111",
}
body_str = json.dumps(body_json, separators=(',', ':'))  # 确保 JSON 字符串格式正确

# 生成签名 (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# 发送请求
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$url = "https://t(:open_url)";
$request_path = "/sapi/v1/order";
$api_url = $url . $request_path;
$api_key = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$api_secret = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$method = "POST";

// 定义请求体 (JSON 格式)
$body_json = json_encode([
    "symbol" => "BTCUSDT",
    "price" => "9300",
    "volume" => "1",
    "side" => "BUY",
    "type" => "LIMIT"
], JSON_UNESCAPED_SLASHES); // 确保 JSON 格式正确

// 生成签名 (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// 发送请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 POST 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const URL = "https://t(:open_url)";
const REQUEST_PATH = "/sapi/v1/order";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "POST";

// 定义请求体 (JSON 格式)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  price: "9300",
  volume: "1",
  side: "BUY",
  type: "LIMIT",
});

// 生成签名 (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// 发送请求
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
{"symbol":"BTCUSDT","volume":1.00,"side":"BUY","type":"LIMIT","price":65000.00,"newClientOrderId":"111000000111"}
```

**请求参数**

| 参数名                            | 类型   | 描述                                                            |
| :---------------------------------| :------| :---------------------------------------------------------------|
| symbol<font color="red">\*</font> | string | `大写`币对名称，例如：`BTCUSDT` (参考 [币对列表](#现货交易-公共-币对列表) 的 `symbol` )  |
| volume<font color="red">\*</font> | number | 订单数量，有精度限制，精度由管理员配置 (参考 [币对列表](#现货交易-公共-币对列表) 的 `limitVolumeMin` )  |
| side<font color="red">\*</font>   | string | 订单方向，`BUY/SELL`                                            |
| type<font color="red">\*</font>   | string | 订单类型，`LIMIT/MARKET`                                        |
| price                             | number | 订单价格，对于`LIMIT`订单必须发送，有精度限制，精度由管理员配置 (参考 [最近成交](#现货交易-行情-最近成交) 的 `price` ) |
| newClientOrderId                  | string | 客户端订单标识                                                  |

> 返回示例

```json
{
    "symbol": "BTCUSDT",
    "side": "BUY",
    "executedQty": 0,
    "orderId": [
        "2618039663715064005"
    ],
    "price": 97081.19,
    "origQty": 0.00001,
    "clientOrderId": "111000000111",
    "transactTime": 1739867150800,
    "type": "LIMIT",
    "status": "NEW"
}
```

**返回参数**

| 参数名        | 类型    | 示例                  | 描述                                                                                                          |
| :-------------| :-------| :---------------------| :-------------------------------------------------------------------------------------------------------------|
| orderId       | long    | `2012274607240433332` | 订单ID（系统生成）                                                                                            |
| clientOrderId | string  | `213443`              | 订单ID（用户生成）                                                                                            |
| symbol        | string  | `BTCUSDT`             | `大写`币对名称                                                                                                |
| transactTime  | integer | `1704959985403`       | 订单创建时间戳                                                                                                |
| price         | float   | `47651.29`            | 订单价格                                                                                                      |
| origQty       | float   | `0.01`                | 订单数量                                                                                                      |
| executedQty   | float   | `0`                   | 已经成交订单数量                                                                                              |
| type          | string  | `LIMIT`               | 订单类型。可能出现的值只能为：`LIMIT`(限价)和`MARKET`（市价）                                                 |
| side          | string  | `BUY`                 | 订单方向。可能出现的值只能为：`BUY`（买入做多）和`SELL`（卖出做空）                                           |
| status        | string  | `NEW`                 | 订单状态。可能出现的值为：`New Order`（新订单，无成交）、`Partially Filled`（部分成交）、`Filled`（全部成交） |

### 创建新订单-V2

`POST https://t(:open_url)/sapi/v2/order`

**限速规则: 100次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:open_url)/sapi/v2/order

body
{
    "symbol": "BTCUSDT",
    "volume": 1.00,
    "side": "BUY",
    "type": "LIMIT",
    "price": 65000.00,
    "newClientOrderId": "111000000111"
}
```

**请求参数**

| 参数名                            | 类型   | 描述                                                            |
| :---------------------------------| :------| :---------------------------------------------------------------|
| symbol<font color="red">\*</font> | string | `大写`币对名称，例如：`BTCUSDT`                                 |
| volume<font color="red">\*</font> | number | 订单数量，有精度限制，精度由管理员配置                          |
| side<font color="red">\*</font>   | string | 订单方向，`BUY/SELL`                                            |
| type<font color="red">\*</font>   | string | 订单类型，`LIMIT/MARKET`                                        |
| price                             | number | 订单价格，对于`LIMIT`订单必须发送，有精度限制，精度由管理员配置 |
| newClientOrderId                  | string | 客户端订单标识                                                  |

> 返回示例

```json
{
    "symbol": "ETHUSDT",
    "side": "BUY",
    "executedQty": 0,
    "orderId": [
        "2012274607240433332"
    ],
    "price": 47651.29,
    "origQty": 0.01,
    "clientOrderId": "213443",
    "transactTime": 1704959985403,
    "type": "MARKET",
    "status": "NEW"
}
```

**返回参数**

| 参数名        | 类型    | 示例                  | 描述                                                                                                          |
| :-------------| :-------| :---------------------| :-------------------------------------------------------------------------------------------------------------|
| orderId       | string  | `2012274607240433332` | 订单ID（系统生成）                                                                                            |
| clientOrderId | string  | `213443`              | 订单ID（用户生成）                                                                                            |
| symbol        | string  | `BTCUSDT`             | `大写`币对名称                                                                                                |
| transactTime  | integer | `1704959985403`       | 订单创建时间戳                                                                                                |
| price         | float   | `47651.29`            | 订单价格                                                                                                      |
| origQty       | float   | `0.01`                | 订单数量                                                                                                      |
| executedQty   | float   | `0`                   | 已经成交订单数量                                                                                              |
| type          | string  | `LIMIT`               | 订单类型。可能出现的值只能为：`LIMIT`(限价)和`MARKET`（市价）                                                 |
| side          | string  | `BUY`                 | 订单方向。可能出现的值只能为：`BUY`（买入做多）和`SELL`（卖出做空）                                           |
| status        | string  | `NEW`                 | 订单状态。可能出现的值为：`New Order`（新订单，无成交）、`Partially Filled`（部分成交）、`Filled`（全部成交） |


### 创建测试订单

`POST https://t(:open_url)/sapi/v1/order/test`

创建和验证新订单, 但不会送入撮合引擎

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:open_url)/sapi/v1/order/test

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
URL="https://t(:open_url)"
REQUEST_PATH="/sapi/v1/order/test"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="POST"

# 定义请求体 (JSON 格式)
BODY_JSON='{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}'

# 生成签名 (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# 发送请求
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
            // API 相关信息
            String url = "https://t(:open_url)";
            String requestPath = "/sapi/v1/order/test";
            String apiUrl = url + requestPath;
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 获取当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "POST";

            // 定义请求体 (JSON 格式)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"price\":\"9300\",\"volume\":\"1\",\"side\":\"BUY\",\"type\":\"LIMIT\"}";

            // 生成签名 (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // 发送请求
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP POST 请求
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

            // 发送请求体
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // 读取响应
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
	// API 相关信息
    url := "https://t(:open_url)"
    requestPath := "/sapi/v1/order/test"
	apiURL := url + requestPath
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "POST"

	// 定义请求体 (JSON 格式)
	bodyJSON := `{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}`

	// 生成签名 (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// 发送请求
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 签名计算
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP POST 请求
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
URL = "https://t(:open_url)"
REQUEST_PATH = "/sapi/v1/order/test"
API_URL = URL + REQUEST_PATH
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "POST"

# 定义请求体 (JSON 格式)
body_json = {
    "symbol": "BTCUSDT",
    "price": "9300",
    "volume": "1",
    "side": "BUY",
    "type": "LIMIT"
}
body_str = json.dumps(body_json, separators=(',', ':'))  # 确保 JSON 字符串格式正确

# 生成签名 (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# 发送请求
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$url = "https://t(:open_url)";
$request_path = "/sapi/v1/order/test";
$api_url = $url . $request_path;
$api_key = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$api_secret = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$method = "POST";

// 定义请求体 (JSON 格式)
$body_json = json_encode([
    "symbol" => "BTCUSDT",
    "price" => "9300",
    "volume" => "1",
    "side" => "BUY",
    "type" => "LIMIT"
], JSON_UNESCAPED_SLASHES); // 确保 JSON 格式正确

// 生成签名 (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// 发送请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 POST 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const URL = "https://t(:open_url)";
const REQUEST_PATH = "/sapi/v1/order/test";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "POST";

// 定义请求体 (JSON 格式)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  price: "9300",
  volume: "1",
  side: "BUY",
  type: "LIMIT",
});

// 生成签名 (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// 发送请求
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
{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}
```

**请求参数**

| 参数名                            | 类型   | 描述                                                        |
| :---------------------------------| :------| :-----------------------------------------------------------|
| symbol<font color="red">\*</font> | string | `大写`币对名称，例如`BTCUSDT` (参考 [币对列表](#现货交易-公共-币对列表) 的 `symbol` )  |
| volume<font color="red">\*</font> | number | 订单数量，有精度限制，由管理员配置 (参考 [币对列表](#现货交易-公共-币对列表) 的 `limitVolumeMin` )  |
| side<font color="red">\*</font>   | string | 订单方向，`BUY/SELL`                                        |
| type<font color="red">\*</font>   | string | 订单类型，`LIMIT/MARKET`                                    |
| price                             | number | 订单价格，对于`LIMIT`订单必须发送，有精度限制，由管理员配置 (参考 [最近成交](#现货交易-行情-最近成交) 的 `price` ) |
| newClientOrderId                  | string | 客户端订单标识                                              |

> 返回示例

```json
{}
```

<!-- ### 批量下单

`POST https://t(:open_url)/sapi/v1/batchOrders`

**限速规则: 50次/2s 一个批量最多10个订单**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:open_url)/sapi/v1/batchOrders

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

**请求参数**

| 参数名    | 类型   | 示例           | 描述     |
| :---------| :------| :--------------| :--------|
| symbol    | string | `ETHUSDT`      | 币对名称 |
| price     | float  | `2100.00`      | 价格     |
| volume    | float  | `1.00`         | 数量     |
| side      | string | `BUY/SELL`     | 方向     |
| batchType | string | `LIMIT/MARKET` | 类型     |

> 返回示例

```json
{
    "ids": [
        165964665990709251,
        165964665990709252,
        165964665990709253
    ]
}
```

**返回参数**

| 参数名 | 类型  | 示例 | 描述       |
| :------| :-----| :----| :----------|
| ids    | array |      | 订单id数组 | -->

### 订单查询

`GET https://t(:open_url)/sapi/v1/order`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/order?orderId=2618039663715064005&symbol=btcusdt

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/order"
QUERY_STRING="?orderId=2618039663715064005&symbol=btcusdt"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API 认证信息
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/order";
            String queryString = "?orderId=2618039663715064005&symbol=btcusdt";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API 认证信息
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 生成当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "GET";

            // 生成签名 (X-CH-SIGN) - GET 请求没有 body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/order"
	queryString := "?orderId=2618039663715064005&symbol=btcusdt"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API 认证信息
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "GET"

	// 生成签名 (X-CH-SIGN) - GET 请求没有 body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// 计算 HMAC-SHA256 签名
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/order"
QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API 认证信息
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/order";
$QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API 认证信息
$API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/order";
const QUERY_STRING = "?orderId=2618039663715064005&symbol=btcusdt";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API 认证信息
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

**请求参数**

| 参数名                             | 类型   | 描述                            |
| :----------------------------------| :------| :-------------------------------|
| orderId<font color="red">\*</font> | string | 订单id（系统生成）              |
| symbol<font color="red">\*</font>  | string | `小写`币对名称，例如：`ethusdt` |

> 返回示例

```json
{
    "symbol": "btcusdt",
    "side": "BUY",
    "executedQty": 0E-16,
    "orderId": 2618039663715064005,
    "price": 97081.1900000000000000,
    "origQty": 0.0000100000000000,
    "avgPrice": 0E-16,
    "transactTime": 1739867150753,
    "type": "LIMIT",
    "status": "New Order"
}
```

**返回参数**

| 参数名        | 类型   | 示例                 | 描述                                                                                                        |
| :-------------| :------| :--------------------| :-----------------------------------------------------------------------------------------------------------|
| orderId       | long   | `150695552109032492` | 订单ID（系统生成）                                                                                          |
| clientOrderId | string | `213443`             | 订单ID（用户生成）                                                                                          |
| symbol        | string | `ethusdt`            | `小写`币对名称                                                                                              |
| price         | float  | `4765.29`            | 订单价格                                                                                                    |
| origQty       | float  | `1.01`               | 订单数量                                                                                                    |
| executedQty   | float  | `0`                  | 已经成交订单数量                                                                                            |
| avgPrice      | float  | `4754.24`            | 订单已经成交的平均价格                                                                                      |
| type          | string | `LIMIT`              | 订单类型。可能出现的值只能为：`LIMIT`(限价)和`MARKET`（市价）                                               |
| transactTime  | long   | `1672274311107`      | 时间戳                                                                                                      |
| side          | string | `BUY`                | 订单方向。可能出现的值只能为：`BUY`（买入做多）和`SELL`（卖出做空）                                         |
| status        | string | `New Order`          | 订单状态。可能出现的值为：`New Order`(新订单，无成交)、`Partially Filled`（部分成交）、`Filled`（全部成交） |

### 订单查询-V2

`GET https://t(:open_url)/sapi/v2/order`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
GET https://t(:open_url)/sapi/v2/order?symbol=ethusdt&orderID=111000111
```

**请求参数**

| 参数名                             | 类型   | 描述                            |
| :----------------------------------| :------| :-------------------------------|
| orderId<font color="red">\*</font> | string | 订单id                          |
| symbol<font color="red">\*</font>  | string | `小写`币对名称，例如：`ethusdt` |

> 返回示例

```json
{
    "symbol": "ethusdt",
    "side": "BUY",
    "executedQty": 0,
    "orderId": "150695552109032492",
    "price": 4765.29,
    "origQty": 1.01,
    "avgPrice": 4754.24,
    "transactTime": 1672274311107,
    "type": "LIMIT",
    "status": "New Order"
}
```

**返回参数**

| 参数名        | 类型   | 示例                 | 描述                                                                                                        |
| :-------------| :------| :--------------------| :-----------------------------------------------------------------------------------------------------------|
| orderId       | string | `150695552109032492` | 订单ID（系统生成）                                                                                          |
| clientOrderId | string | `213443`             | 订单ID（用户生成）                                                                                          |
| symbol        | string | `ethusdt`            | `小写`币对名称                                                                                              |
| price         | float  | `4765.29`            | 订单价格                                                                                                    |
| origQty       | float  | `1.01`               | 订单数量                                                                                                    |
| executedQty   | float  | `0`                  | 已经成交订单数量                                                                                            |
| avgPrice      | float  | `4754.24`            | 订单已经成交的平均价格                                                                                      |
| type          | string | `LIMIT`              | 订单类型。可能出现的值只能为：`LIMIT`(限价)和`MARKET`（市价）                                               |
| transactTime  | long   | `1672274311107`      | 时间戳                                                                                                      |
| side          | string | `BUY`                | 订单方向。可能出现的值只能为：`BUY`（买入做多）和`SELL`（卖出做空）                                         |
| status        | string | `New Order`          | 订单状态。可能出现的值为：`New Order`(新订单，无成交)、`Partially Filled`（部分成交）、`Filled`（全部成交） |


### 撤销订单

`POST https://t(:open_url)/sapi/v1/cancel`

**限速规则: 100次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:open_url)/sapi/v1/cancel

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739945835000
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 3c22ee3d2940df5e9dc5b7b862ba3d75e805e97a242f52f12fec9d16bc73e1c7
```

```shell
#!/bin/bash

# 设置 API 相关信息
URL="https://t(:open_url)"
REQUEST_PATH="/sapi/v1/cancel"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="POST"

# 定义请求体 (JSON 格式)
BODY_JSON='{"symbol":"btcusdt","orderId":"2618039663715064005"}'

# 生成签名 (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# 发送请求
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
            // API 相关信息
            String url = "https://t(:open_url)";
            String requestPath = "/sapi/v1/cancel";
            String apiUrl = url + requestPath;
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 获取当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "POST";

            // 定义请求体 (JSON 格式)
            String bodyJson = "{\"symbol\":\"btcusdt\",\"orderId\":\"2618039663715064005\"";

            // 生成签名 (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // 发送请求
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP POST 请求
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

            // 发送请求体
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // 读取响应
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
	// API 相关信息
    url := "https://t(:open_url)"
    requestPath := "/sapi/v1/cancel"
	apiURL := url + requestPath
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "POST"

	// 定义请求体 (JSON 格式)
	bodyJSON := `{"symbol":"btcusdt","orderId":"2618039663715064005"}`

	// 生成签名 (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// 发送请求
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 签名计算
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP POST 请求
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
URL = "https://t(:open_url)"
REQUEST_PATH = "/sapi/v1/cancel"
API_URL = URL + REQUEST_PATH
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "POST"

# 定义请求体 (JSON 格式)
body_json = {
    "symbol": "btcusdt",
    "orderId": "2618039663715064005"
}
body_str = json.dumps(body_json, separators=(',', ':'))  # 确保 JSON 字符串格式正确

# 生成签名 (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# 发送请求
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$url = "https://t(:open_url)";
$request_path = "/sapi/v1/cancel";
$api_url = $url . $request_path;
$api_key = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$api_secret = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$method = "POST";

// 定义请求体 (JSON 格式)
$body_json = json_encode([
    "symbol" => "btcusdt",
    "orderId" => "2618039663715064005"
], JSON_UNESCAPED_SLASHES); // 确保 JSON 格式正确

// 生成签名 (X-CH-SIGN)
$sign_payload = $timestamp . $method . $request_path . $body_json;
$signature = hash_hmac('sha256', $sign_payload, $api_secret);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $sign_payload . "\n";
echo "Signature (X-CH-SIGN): " . $signature . "\n";
echo "Request Body: " . $body_json . "\n";
echo "==================\n";

// 发送请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $signature",
    "X-CH-APIKEY: $api_key",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 POST 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body_json);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const URL = "https://t(:open_url)";
const REQUEST_PATH = "/sapi/v1/cancel";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "POST";

// 定义请求体 (JSON 格式)
const bodyJson = JSON.stringify({
  symbol: "btcusdt",
  orderId: "2618039663715064005",
});

// 生成签名 (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// 发送请求
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
{"symbol":"btcusdt","orderId":"2618039663715064005"}
```

**请求参数**

| 参数名                             | 类型   | 描述                          |
| :----------------------------------| :------| :---------------------------|
| orderId<font color="red">\*</font> | string | 订单id（系统生成）             |
| symbol<font color="red">\*</font>  | string | `小写`币对名称，例如：`ethusdt` |

> 返回示例

```json
{
    "symbol": "btcusdt",
    "orderId": [
        "2618039663715064005"
    ],
    "status": "PENDING_CANCEL"
}
```

**返回参数**

| 参数名  | 类型   | 示例                  | 描述                       |
| :-------| :------| :---------------------| :--------------------------|
| orderId | long   | `1938321163093079425` | 订单ID（系统生成）         |
| symbol  | string | `ethusdt`             | 币对名称                   |
| status  | string | `PENDING_CANCEL`      | 订单状态：`PENDING_CANCEL` |

### 撤销订单-V2

`POST https://t(:open_url)/sapi/v2/cancel`

**限速规则: 100次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:open_url)/sapi/v2/cancel

body
{
    "symbol": "ethusdt",
    "orderId": "111000111"
}
```

**请求参数**

| 参数名                             | 类型   | 描述                          |
| :----------------------------------| :------| :-----------------------------|
| orderId<font color="red">\*</font> | string | 订单id                        |
| symbol<font color="red">\*</font>  | string | `小写`币对名称，例如：`ethusdt` |

> 返回示例

```json
{
    "symbol": "ethusdt",
    "orderId": [
        "1938321163093079425"
    ],
    "status": "PENDING_CANCEL"
}
```

**返回参数**

| 参数名  | 类型   | 示例                  | 描述                       |
| :-------| :------| :---------------------| :--------------------------|
| orderId | string | `1938321163093079425` | 订单ID（系统生成）         |
| symbol  | string | `ethusdt`             | 币对名称                   |
| status  | string | `PENDING_CANCEL`      | 订单状态：`PENDING_CANCEL` |


### 批量撤销订单

`POST https://t(:open_url)/sapi/v1/batchCancel`

**限速规则: 50次/2s 一次批量最多10个订单**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:open_url)/sapi/v1/batchCancel

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739945835000
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 3c22ee3d2940df5e9dc5b7b862ba3d75e805e97a242f52f12fec9d16bc73e1c7
```

```shell
#!/bin/bash

# 设置 API 相关信息
URL="https://t(:open_url)"
REQUEST_PATH="/sapi/v1/batchCancel"
API_URL="${URL}${REQUEST_PATH}"
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="POST"

# 定义请求体 (JSON 格式)
BODY_JSON='{"symbol":"BTCUSDT","orderId":["111000111","111000112"]}'

# 生成签名 (X-CH-SIGN)
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}${BODY_JSON}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request Body: $BODY_JSON"
echo "=================="

# 发送请求
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
            // API 相关信息
            String url = "https://t(:open_url)";
            String requestPath = "/sapi/v1/batchCancel";
            String apiUrl = url + requestPath;
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 获取当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "POST";

            // 定义请求体 (JSON 格式)
            String bodyJson = "{\"symbol\":\"BTCUSDT\",\"orderId\":[\"111000111\",\"111000112\"]}";

            // 生成签名 (X-CH-SIGN)
            String signPayload = timestamp + method + requestPath + bodyJson;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request Body: " + bodyJson);
            System.out.println("==================");

            // 发送请求
            sendPostRequest(apiUrl, apiKey, timestamp, signature, bodyJson);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP POST 请求
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

            // 发送请求体
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = bodyJson.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // 读取响应
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
	// API 相关信息
    url := "https://t(:open_url)"
    requestPath := "/sapi/v1/batchCancel"
	apiURL := url + requestPath
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "POST"

	// 定义请求体 (JSON 格式)
	bodyJSON := `{"symbol":"BTCUSDT","orderId":["111000111","111000112"]}`

	// 生成签名 (X-CH-SIGN)
	signPayload := timestamp + method + requestPath + bodyJSON
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request Body:", bodyJSON)
	fmt.Println("==================")

	// 发送请求
	sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON)
}

// HMAC-SHA256 签名计算
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP POST 请求
func sendPostRequest(apiURL, apiKey, timestamp, signature, bodyJSON string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
URL = "https://t(:open_url)"
REQUEST_PATH = "/sapi/v1/batchCancel"
API_URL = URL + REQUEST_PATH
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "POST"

# 定义请求体 (JSON 格式)
body_json = {
    "symbol": "BTCUSDT",
    "orderId": {
        111000111,
        111000112
    }
}
body_str = json.dumps(body_json, separators=(',', ':'))  # 确保 JSON 字符串格式正确

# 生成签名 (X-CH-SIGN)
sign_payload = timestamp + METHOD + REQUEST_PATH + body_str
signature = hmac.new(API_SECRET.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", sign_payload)
print("Signature (X-CH-SIGN):", signature)
print("Request Body:", body_str)
print("==================")

# 发送请求
headers = {
    "X-CH-SIGN": signature,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.post(API_URL, headers=headers, data=body_str)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const URL = "https://t(:open_url)";
const REQUEST_PATH = "/sapi/v1/batchCancel";
const API_URL = URL + REQUEST_PATH;
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "POST";

// 定义请求体 (JSON 格式)
const bodyJson = JSON.stringify({
  symbol: "BTCUSDT",
  orderId: ["111000111", "111000112"],
});

// 生成签名 (X-CH-SIGN)
const signPayload = timestamp + METHOD + REQUEST_PATH + bodyJson;
const signature = crypto
  .createHmac("sha256", API_SECRET)
  .update(signPayload)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", signPayload);
console.log("Signature (X-CH-SIGN):", signature);
console.log("Request Body:", bodyJson);
console.log("==================");

// 发送请求
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
{"symbol":"BTCUSDT","oderIds":[111000111, 111000112]}
```

**请求参数**

| 参数名                              | 类型   | 描述                                              |
| :-----------------------------------| :------| :-------------------------------------------------|
| symbol<font color="red">\*</font>   | string | `大写`币对名称，例如：`BTCUSDT`                   |
| orderIds<font color="red">\*</font> | array  | 要取消的订单id集合，id值以数字格式输入`[123,456]` |

>成功返回数据

```json
{
    "success": [
        165964665990709251,
        165964665990709252,
        165964665990709253
    ],
    "failed": [ // 取消失败一般是因为订单不存在或订单状态已经到终态
        165964665990709250
    ]
}
```

> 失败返回数据

```json
{} //通常是因为订单号错误，需要检查orderIds里的内容是否正确
```

### 当前订单

`GET https://t(:open_url)/sapi/v1/openOrders`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/openOrders?symbol=btcusdt&limit=10

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/openOrders"
QUERY_STRING="?symbol=btcusdt&limit=10"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API 认证信息
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/openOrders";
            String queryString = "?symbol=btcusdt&limit=10";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API 认证信息
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 生成当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "GET";

            // 生成签名 (X-CH-SIGN) - GET 请求没有 body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/openOrders"
	queryString := "?symbol=btcusdt&limit=10"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API 认证信息
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "GET"

	// 生成签名 (X-CH-SIGN) - GET 请求没有 body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// 计算 HMAC-SHA256 签名
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/openOrders"
QUERY_STRING = "?symbol=btcusdt&limit=10"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API 认证信息
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/openOrders";
$QUERY_STRING = "?symbol=btcusdt&limit=10";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API 认证信息
$API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/openOrders";
const QUERY_STRING = "?symbol=btcusdt&limit=10";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API 认证信息
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

**请求参数**

| 参数名                            | 类型    | 描述                            |
| :---------------------------------| :-------| :-------------------------------|
| symbol<font color="red">\*</font> | string  | `小写`币对名称，例如：`ethusdt` |
| limit                             | integer | 最大1000                        |

> 返回示例

```json
[
    {
        "symbol": "ETHUSDT",
        "side": "BUY",
        "executedQty": "0",
        "orderId": 1938321163093077686,
        "price": "0",
        "origQty": "0.10",
        "avgPrice": "0",
        "time": 1701240367864,
        "type": "MARKET",
        "status": "NEW_"
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
```

**返回参数**

| 参数名      | 类型   | 示例                 | 描述                                                                                                        |
| :-----------| :------| :--------------------| :-----------------------------------------------------------------------------------------------------------|
| orderId     | long   | `150695552109032492` | 订单ID（系统生成）                                                                                          |
| symbol      | string | `ETHUSDT`            | 币对名称                                                                                                    |
| price       | float  | `4765.29`            | 订单价格                                                                                                    |
| origQty     | float  | `1.01`               | 订单数量                                                                                                    |
| executedQty | float  | `1.01`               | 已经成交订单数量                                                                                            |
| avgPrice    | float  | `4754.24`            | 订单已经成交的平均价格                                                                                      |
| type        | string | `LIMIT`              | 订单类型。可能出现的值只能为：`LIMIT`(限价)和`MARKET`（市价）                                               |
| time        | long   | `1701243281850`      | 时间戳                                                                                                      |
| side        | string | `BUY`                | 订单方向。可能出现的值只能为：`BUY`（买入做多）和`SELL`（卖出做空）                                         |
| status      | string | `New Order`          | 订单状态。可能出现的值为：`New Order`(新订单，无成交)、`Partially Filled`（部分成交）、`Filled`（全部成交） |

### 当前订单-V2

`GET https://t(:open_url)/sapi/v2/openOrders`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

**请求参数**

| 参数名                            | 类型    | 描述                            |
| :---------------------------------| :-------| :-------------------------------|
| symbol<font color="red">\*</font> | string  | `小写`币对名称，例如：`ethusdt` |
| limit<font color="red">\*</font>  | integer | 最大1000                        |

> 返回示例

```json
[
    {
        "symbol": "ETHUSDT",
        "side": "BUY",
        "executedQty": "0",
        "orderId": "1938321163093077686",
        "price": "0",
        "origQty": "0.10",
        "avgPrice": "0",
        "time": 1701240367864,
        "type": "MARKET",
        "status": "NEW_"
    },
    {
        "symbol": "ETHUSDT",
        "side": "BUY",
        "executedQty": "0",
        "orderId": "1938321163093078022",
        "price": "0",
        "origQty": "0.01",
        "avgPrice": "0",
        "time": 1701243281850,
        "type": "MARKET",
        "status": "NEW_"
    }
]
```

**返回参数**

| 参数名      | 类型   | 示例                 | 描述                                                                                                        |
| :-----------| :------| :--------------------| :-----------------------------------------------------------------------------------------------------------|
| orderId     | string | `150695552109032492` | 订单ID（系统生成）                                                                                          |
| symbol      | string | `ETHUSDT`            | 币对名称                                                                                                    |
| price       | float  | `4765.29`            | 订单价格                                                                                                    |
| origQty     | float  | `1.01`               | 订单数量                                                                                                    |
| executedQty | float  | `1.01`               | 已经成交订单数量                                                                                            |
| avgPrice    | float  | `4754.24`            | 订单已经成交的平均价格                                                                                      |
| type        | string | `LIMIT`              | 订单类型。可能出现的值只能为：`LIMIT`(限价)和`MARKET`（市价）                                               |
| time        | long   | `1701243281850`      | 时间戳                                                                                                      |
| side        | string | `BUY`                | 订单方向。可能出现的值只能为：`BUY`（买入做多）和`SELL`（卖出做空）                                         |
| status      | string | `New Order`          | 订单状态。可能出现的值为：`New Order`(新订单，无成交)、`Partially Filled`（部分成交）、`Filled`（全部成交） |


### 交易记录

`GET https://t(:open_url)/sapi/v1/myTrades`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/myTrades?symbol=BTCUSDT&limit=100

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/myTrades"
QUERY_STRING="?symbol=BTCUSDT&limit=100"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API 认证信息
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/myTrades";
            String queryString = "?symbol=BTCUSDT&limit=100";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API 认证信息
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 生成当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "GET";

            // 生成签名 (X-CH-SIGN) - GET 请求没有 body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/myTrades"
	queryString := "?symbol=BTCUSDT&limit=100"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API 认证信息
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "GET"

	// 生成签名 (X-CH-SIGN) - GET 请求没有 body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// 计算 HMAC-SHA256 签名
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/myTrades"
QUERY_STRING = "?symbol=BTCUSDT&limit=100"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API 认证信息
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/myTrades";
$QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API 认证信息
$API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/myTrades";
const QUERY_STRING = "?symbol=BTCUSDT&limit=100";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API 认证信息
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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


**请求参数**

| 参数名                            | 类型   | 描述                            |
| :---------------------------------| :------| :-------------------------------|
| symbol<font color="red">\*</font> | string | `大写`币对名称，例如：`BTCUSDT` |
| limit                             | string | 默认：100；最大：1000               |

> 返回示例

```json
[
    {
        "symbol": "ETHUSDT",
        "side": "BUY",
        "fee": 0.00000000428,
        "isMaker": false,
        "isBuyer": true,
        "bidId": 1954603951049381893,
        "bidUserId": 10083,
        "feeCoin": "ETH",
        "price": 2334,
        "qty": 0.00000428,
        "askId": 1856176838352995447,
        "id": 159,
        "time": 1701623660989,
        "isSelf": false,
        "askUserId": 10671
    },
    {
        "symbol": "ETHUSDT",
        "side": "BUY",
        "fee": 0.00000004284,
        "isMaker": false,
        "isBuyer": true,
        "bidId": 1938321163093068889,
        "bidUserId": 10083,
        "feeCoin": "ETH",
        "price": 2334,
        "qty": 0.00004284,
        "askId": 1856176838352995447,
        "id": 158,
        "time": 1701165091964,
        "isSelf": false,
        "askUserId": 10671
    }
]
```

**返回参数**

| 参数名    | 类型    | 示例                  | 描述                                              |
| :---------| :-------| :---------------------| :-------------------------------------------------|
| symbol    | string  | `ETHBTC`              | `大写`币种名称                                    |
| id        | integer | `159`                 | 交易ID                                            |
| bidId     | long    | `1954603951049381893` | 买方订单ID                                        |
| askId     | long    | `1856176838352995447` | 卖方订单ID                                        |
| price     | integer | `2334`                | 交易价格                                          |
| qty       | float   | `0.00004284`          | 交易数量                                          |
| time      | number  | `1701165091964`       | 交易时间戳                                        |
| isBuyer   | boolean | `true`                | `true`=Buyer，`false`=Seller                      |
| isMaker   | boolean | `false`               | `true`=Maker，`false`=Taker                       |
| feeCoin   | string  | `ETH`                 | 交易手续费币种                                    |
| fee       | number  | `0.00000000428`       | 交易手续费                                        |
| bidUserId | integer | `10083`               | 买方用户uid                                       |
| askUserId | integer | `10671`               | 卖方用户uid                                       |
| isSelf    | boolean | `false`               | 是否为自成交，`true`=是自成交，`false`=不是自成交 |
| side      | string  | `BUY`                 | 主动单方向`BUY`/`SELL`                            |

## 账户

### 安全类型: USER\_DATA

<aside class="notice">账户下方的接口都需要签名和API-key验证。</aside>

### 账户信息（废弃）

`GET https://t(:open_url)/sapi/v1/account`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
GET https://t(:open_url)/sapi/v1/account

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/account"
QUERY_STRING=""

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API 认证信息
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/account";
            String queryString = "";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API 认证信息
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 生成当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "GET";

            // 生成签名 (X-CH-SIGN) - GET 请求没有 body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/account"
	queryString := ""

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API 认证信息
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "GET"

	// 生成签名 (X-CH-SIGN) - GET 请求没有 body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// 计算 HMAC-SHA256 签名
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/v1/account"
QUERY_STRING = ""

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API 认证信息
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/account";
$QUERY_STRING = "";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API 认证信息
$API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/account";
const QUERY_STRING = "";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API 认证信息
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

> 返回示例

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

**返回参数**

| 参数名   | 类型   | 描述         |
| :--------| :------| :------------|
| balances | array  | 账户余额集合 |
| asset    | string | 交易对       |
| free     | string | 可用余额     |
| locked   | string | 冻结余额     |

### 账户信息（推荐）

`GET https://t(:open_url)/sapi/v1/account/balance`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
// 查询所有币种
GET https://t(:open_url)/sapi/v1/account/balance

// 查询USDT，BTC，ETH
GET https://t(:open_url)/sapi/v1/account/balance?symbols=USDT,BTC,ETH

// Headers 设定
Content-Type: application/json
X-CH-TS: 1739503617552
X-CH-APIKEY: vmPUZE6mv9SD5V5e14y7Ju91duEh8A
X-CH-SIGN: 325b02a8444da041c71fb6e3c35c6baf87e5cb48acc19e4cd312b8bf821bfc1b
```

```shell
#!/bin/bash

# 设置 API 相关信息
API_URL="https://t(:open_url)"
REQUEST_URL="/sapi/v1/account/balance"
QUERY_STRING="?symbols=USDT,BTC,ETH"

# 计算完整的请求路径
REQUEST_PATH="${REQUEST_URL}${QUERY_STRING}"
FULL_URL="${API_URL}${REQUEST_PATH}"

# API 认证信息
API_KEY="vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET="902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp=$(date +%s | awk '{print $1 * 1000}')

# 定义请求方法
METHOD="GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD="${timestamp}${METHOD}${REQUEST_PATH}"
SIGNATURE=$(echo -n "$SIGN_PAYLOAD" | openssl dgst -sha256 -hmac "$API_SECRET" | awk '{print $2}')

# **打印调试信息**
echo "==== 请求信息 ===="
echo "Timestamp (X-CH-TS): $timestamp"
echo "Sign Payload (待签名字符串): $SIGN_PAYLOAD"
echo "Signature (X-CH-SIGN): $SIGNATURE"
echo "Request URL: ${FULL_URL}"
echo "=================="

# 发送 GET 请求
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
            // API 相关信息
            String apiUrl = "https://t(:open_url)";
            String requestUrl = "/sapi/v1/account/balance";
            String queryString = "?symbols=USDT,BTC,ETH";

            // 计算完整的请求路径
            String requestPath = requestUrl + queryString;
            String fullUrl = apiUrl + requestPath;

            // API 认证信息
            String apiKey = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
            String apiSecret = "902ae3cb34ecee2779aa4d3e1d226686";

            // 生成当前毫秒级时间戳
            String timestamp = String.valueOf(Instant.now().toEpochMilli());

            // 请求方法
            String method = "GET";

            // 生成签名 (X-CH-SIGN) - GET 请求没有 body
            String signPayload = timestamp + method + requestPath;
            String signature = hmacSha256(signPayload, apiSecret);

            // **打印调试信息**
            System.out.println("==== 请求信息 ====");
            System.out.println("Timestamp (X-CH-TS): " + timestamp);
            System.out.println("Sign Payload (待签名字符串): " + signPayload);
            System.out.println("Signature (X-CH-SIGN): " + signature);
            System.out.println("Request URL: " + fullUrl);
            System.out.println("==================");

            // 发送 GET 请求
            sendGetRequest(fullUrl, apiKey, timestamp, signature);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // HMAC-SHA256 签名计算
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

    // 发送 HTTP GET 请求
    public static void sendGetRequest(String fullUrl, String apiKey, String timestamp, String signature) {
        try {
            URL url = new URL(fullUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // 设置请求头
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("X-CH-APIKEY", apiKey);
            conn.setRequestProperty("X-CH-TS", timestamp);

            // 发送请求并获取响应
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
	// API 相关信息
	apiURL := "https://t(:open_url)"
	requestURL := "/sapi/v1/account/balance"
	queryString := "?symbols=USDT,BTC,ETH"

	// 计算完整的请求路径
	requestPath := requestURL + queryString
	fullURL := apiURL + requestPath

	// API 认证信息
	apiKey := "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
	apiSecret := "902ae3cb34ecee2779aa4d3e1d226686"

	// 生成当前毫秒级时间戳
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)

	// 请求方法
	method := "GET"

	// 生成签名 (X-CH-SIGN) - GET 请求没有 body
	signPayload := timestamp + method + requestPath
	signature := hmacSHA256(signPayload, apiSecret)

	// **打印调试信息**
	fmt.Println("==== 请求信息 ====")
	fmt.Println("Timestamp (X-CH-TS):", timestamp)
	fmt.Println("Sign Payload (待签名字符串):", signPayload)
	fmt.Println("Signature (X-CH-SIGN):", signature)
	fmt.Println("Request URL:", fullURL)
	fmt.Println("==================")

	// 发送 GET 请求
	sendGetRequest(fullURL, apiKey, timestamp, signature)
}

// 计算 HMAC-SHA256 签名
func hmacSHA256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 发送 HTTP GET 请求
func sendGetRequest(fullURL, apiKey, timestamp, signature string) {
	client := &http.Client{}

	// 创建请求
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-SIGN", signature)
	req.Header.Set("X-CH-APIKEY", apiKey)
	req.Header.Set("X-CH-TS", timestamp)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
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

# API 相关信息
API_URL = "https://t(:open_url)"
REQUEST_URL = "/sapi/account/balance"
QUERY_STRING = "?symbols=USDT,BTC,ETH"

# 计算完整的请求路径
REQUEST_PATH = REQUEST_URL + QUERY_STRING
FULL_URL = API_URL + REQUEST_PATH

# API 认证信息
API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A"
API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686"

# 生成当前毫秒级时间戳
timestamp = str(int(time.time() * 1000))

# 请求方法
METHOD = "GET"

# 生成签名 (X-CH-SIGN) - GET 请求没有 body
SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH
SIGNATURE = hmac.new(API_SECRET.encode(), SIGN_PAYLOAD.encode(), hashlib.sha256).hexdigest()

# **打印调试信息**
print("==== 请求信息 ====")
print("Timestamp (X-CH-TS):", timestamp)
print("Sign Payload (待签名字符串):", SIGN_PAYLOAD)
print("Signature (X-CH-SIGN):", SIGNATURE)
print("Request URL:", FULL_URL)
print("==================")

# 发送 GET 请求
headers = {
    "X-CH-SIGN": SIGNATURE,
    "X-CH-APIKEY": API_KEY,
    "X-CH-TS": timestamp,
    "Content-Type": "application/json"
}

response = requests.get(FULL_URL, headers=headers)

# 打印响应
print("Response Code:", response.status_code)
print("Response Body:", response.text)

```

```php
<?

// API 相关信息
$API_URL = "https://t(:open_url)";
$REQUEST_URL = "/sapi/v1/account/balance";
$QUERY_STRING = "?symbols=USDT,BTC,ETH";

// 计算完整的请求路径
$REQUEST_PATH = $REQUEST_URL . $QUERY_STRING;
$FULL_URL = $API_URL . $REQUEST_PATH;

// API 认证信息
$API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
$API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 请求方法
$METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
$SIGN_PAYLOAD = $timestamp . $METHOD . $REQUEST_PATH;
$SIGNATURE = hash_hmac('sha256', $SIGN_PAYLOAD, $API_SECRET);

// **打印调试信息**
echo "==== 请求信息 ====\n";
echo "Timestamp (X-CH-TS): " . $timestamp . "\n";
echo "Sign Payload (待签名字符串): " . $SIGN_PAYLOAD . "\n";
echo "Signature (X-CH-SIGN): " . $SIGNATURE . "\n";
echo "Request URL: " . $FULL_URL . "\n";
echo "==================\n";

// 发送 GET 请求
$headers = [
    "Content-Type: application/json",
    "X-CH-SIGN: $SIGNATURE",
    "X-CH-APIKEY: $API_KEY",
    "X-CH-TS: $timestamp"
];

// 使用 cURL 发送 GET 请求
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $FULL_URL);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

// 执行请求并获取响应
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 打印响应
echo "Response Code: $http_code\n";
echo "Response Body: $response\n";

?>
```

```javascript--node
const axios = require("axios");
const crypto = require("crypto");

// API 相关信息
const API_URL = "https://t(:open_url)";
const REQUEST_URL = "/sapi/v1/account/balance";
const QUERY_STRING = "?symbols=USDT,BTC,ETH";

// 计算完整的请求路径
const REQUEST_PATH = REQUEST_URL + QUERY_STRING;
const FULL_URL = API_URL + REQUEST_PATH;

// API 认证信息
const API_KEY = "vmPUZE6mv9SD5V5e14y7Ju91duEh8A";
const API_SECRET = "902ae3cb34ecee2779aa4d3e1d226686";

// 生成当前毫秒级时间戳
const timestamp = Date.now().toString();

// 请求方法
const METHOD = "GET";

// 生成签名 (X-CH-SIGN) - GET 请求没有 body
const SIGN_PAYLOAD = timestamp + METHOD + REQUEST_PATH;
const SIGNATURE = crypto
  .createHmac("sha256", API_SECRET)
  .update(SIGN_PAYLOAD)
  .digest("hex");

// **打印调试信息**
console.log("==== 请求信息 ====");
console.log("Timestamp (X-CH-TS):", timestamp);
console.log("Sign Payload (待签名字符串):", SIGN_PAYLOAD);
console.log("Signature (X-CH-SIGN):", SIGNATURE);
console.log("Request URL:", FULL_URL);
console.log("==================");

// 发送 GET 请求
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

**请求参数**

| 参数名  | 类型   | 描述                                                                     |
| :-------| :------| :------------------------------------------------------------------------|
| symbols | string | 大写币种名称，例如：`BTC`，支持多币种查询，不超过20个，币种之间以`,`分隔 |

> 返回示例

```json
{
    "balances": [
        {
            "asset": "USDT",
            "free": "15.00",
            "locked": "30.00"
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
```

**返回参数**

| 参数名   | 类型   | 描述     |
| :--------| :------| :--------|
| balances | array  | 账户余额 |
| asset    | string | 交易对   |
| free     | string | 可用余额 |
| locked   | string | 冻结余额 |

# 合约交易

## 公共

### 安全类型: None

<aside class="notice">公共下方的接口不需要API-key或者签名就能自由访问。</aside>

### 测试连接

`GET https://t(:futures_url)/fapi/v1/ping`

> 请求示例

```http
GET https://t(:futures_url)/fapi/v1/ping

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_url)/fapi/v1/ping"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:futures_url)/fapi/v1/ping");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:futures_url)/fapi/v1/ping"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:futures_url)/fapi/v1/ping"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
$url = "https://t(:futures_url)/fapi/v1/ping";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_url)/fapi/v1/ping';

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
  console.log('请求错误:', err.message);
});
```

> 返回示例

```json
{}
```

**返回参数**

{}



测试REST API的连通性

### 获取服务器时间

`GET https://t(:futures_url)/fapi/v1/time`

> 请求示例

```http
GET https://t(:futures_url)/fapi/v1/time

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_url)/fapi/v1/time"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:futures_url)/fapi/v1/time");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:futures_url)/fapi/v1/time"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:futures_url)/fapi/v1/time"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
$url = "https://t(:futures_url)/fapi/v1/time";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_url)/fapi/v1/time';

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
  console.log('请求错误:', err.message);
});
```

> 返回示例

```json
{
    "timezone": "China Standard Time",
    "serverTime": 1704962055664
}
```

**返回参数**

| 参数名     | 类型   | 示例                  | 描述         |
| :----------| :------| :---------------------| :------------|
| timezone   | string | `China Standard Time` | 服务器时区   |
| serverTime | long   | `1607702400000`       | 服务器时间戳 |

### 合约列表

`GET https://t(:futures_url)/fapi/v1/contracts`

> 请求示例

```http
GET https://t(:futures_url)/fapi/v1/contracts

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_url)/fapi/v1/contracts"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:futures_url)/fapi/v1/contracts");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:futures_url)/fapi/v1/contracts"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:futures_url)/fapi/v1/contracts"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
$url = "https://t(:futures_url)/fapi/v1/contracts";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_url)/fapi/v1/contracts';

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
  console.log('请求错误:', err.message);
});
```

> 返回示例

```json
[
    {
        "symbol": "E-ETC-USDT",
        "pricePrecision": 3,
        "side": 1,
        "maxMarketVolume": 200000,
        "multiplier": 1.0000000000000000,
        "minOrderVolume": 1,
        "maxMarketMoney": 500000.0000000000000000,
        "type": "E",
        "maxLimitVolume": 300000,
        "maxValidOrder": 10,
        "multiplierCoin": "ETC",
        "minOrderMoney": 1.0000000000000000,
        "maxLimitMoney": 500000.0000000000000000,
        "status": 1
    },
    {
        "symbol": "E-ATOM-USDT",
        "pricePrecision": 3,
        "side": 1,
        "maxMarketVolume": 100000,
        "multiplier": 1.0000000000000000,
        "minOrderVolume": 1,
        "maxMarketMoney": 200000.0000000000000000,
        "type": "E",
        "maxLimitVolume": 200000,
        "maxValidOrder": 10,
        "multiplierCoin": "ATOM",
        "minOrderMoney": 20.0000000000000000,
        "maxLimitMoney": 2000000.0000000000000000,
        "status": 1
    }
]
```

**返回参数**

| 参数名          | 类型   | 示例                      | 描述                                                       |
| :---------------| :-----| :-------------------------| :----------------------------------------------------------|
| symbol          | string | `E-BTC-USDT`              | `大写`合约名称                                             |
| pricePrecision  | number | `3`                       | 价格精度                                                   |
| status          | number | `1`                       | 合约状态（0：`不可交易`，1：`可交易`）                     |
| type            | string | `E`                       | 合约类型（E：`永续合约`，S：`模拟合约`，其他为`混合合约`） |
| side            | number | `1`                       | 合约方向（0：`反向`，1：`正向`）                           |
| multiplier      | number | `1.0000000000000000`      | 合约面值                                                   |
| minOrderVolume  | number | `1`                       | 最小下单量                                                 |
| minOrderMoney   | number | `1.0000000000000000`      | 最小下单金额                                               |
| maxMarketVolume | number | `200000`                  | 市价单最大下单数量                                         |
| maxMarketMoney  | number | `500000.0000000000000000` | 市价最大下单金额                                           |
| maxLimitVolume  | number | `300000`                  | 限价单最大下单数量                                         |
| maxLimitMoney   | number | `500000.0000000000000000` | 限价最大下单金额                                           |
| maxValidOrder   | number | `10`                      | 最大有效委托的订单数量                                     |

## 行情

### 安全类型: None

<aside class="notice">行情下方的接口不需要API-Key或者签名就能自由访问</aside>

### 订单薄

`GET https://t(:futures_url)/fapi/v1/depth`

市场订单薄深度信息

> 请求示例

```http
GET https://t(:futures_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:futures_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:futures_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:futures_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
$url = "https://t(:futures_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_url)/fapi/v1/depth?contractName=E-BTC-USDT&limit=100';

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
  console.log('请求错误:', err.message);
});
```

**请求参数**

| 参数名                                  | 类型    | 描述                               |
| :---------------------------------------| :-------| :----------------------------------|
| contractName<font color="red">\*</font> | string  | `大写`合约名称，例如：`E-BTC-USDT` |
| limit                                   | integer | 默认：100；最大：100               |

> 返回示例

```json
{
    "time": 1704962463000,
    "bids": [
        [
            3.90000000,     //价格
            16.10000000     //数量
        ],
        [
            4.00000000,
            29.30000000
        ]
    ],
    "asks": [
        [
            4.00000200,     //价格
            12.00000000     //数量
        ],
        [
            5.10000000,
            28.00000000
        ]
    ]
}
```

**返回参数**

| 参数名 | 类型 | 示例                             | 描述                                                                                   |
| :------| :----| :--------------------------------| :--------------------------------------------------------------------------------------|
| time   | long | `1595563624731`                  | 当前时间戳                                                                             |
| bids   | list | `[[3.9,16.1],[4.0,29.3]]`        | 订单薄买盘信息，数组第一位为价格，类型为float；第二位为当前价格对应的数量，类型为float |
| asks   | list | `[[4.00000200,12.0],[5.1,28.0]]` | 订单薄卖盘信息，数组第一位为价格，类型为float；第二位为当前价格对应的数量，类型为float |

bids和asks所对应的信息代表了订单薄的所有价格以及价格对应的数量的信息, 由最优价格从上到下排列

### 行情Ticker

`GET https://t(:futures_url)/fapi/v1/ticker`

24小时价格变化数据

> 请求示例

```http
GET https://t(:futures_url)/fapi/v1/ticker?contractName=E-BTC-USDT

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_url)/fapi/v1/ticker?contractName=E-BTC-USDT"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:futures_url)/fapi/v1/ticker?contractName=E-BTC-USDT");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:futures_url)/fapi/v1/ticker?contractName=E-BTC-USDT"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:futures_url)/fapi/v1/ticker?contractName=E-BTC-USDT"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
$url = "https://t(:futures_url)/fapi/v1/ticker?contractName=E-BTC-USDT";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_url)/fapi/v1/ticker?contractName=E-BTC-USDT';

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
  console.log('请求错误:', err.message);
});
```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |


> 返回示例

```json
{
    "high": 56120.22,
    "vol": 51.21,
    "last": 55989.93,
    "low": 55982.24,
    "buy": 55988.10,
    "sell": 55990.10,
    "rose": "+0.05",
    "time": 1704966225000
}
```

**返回参数**

| 参数名 | 类型   | 示例            | 描述                                      |
| :------| :------| :---------------| :-----------------------------------------|
| time   | long   | `1595563624731` | 时间戳                                    |
| high   | float  | `56120.22`      | 最高价                                    |
| low    | float  | `55982.24`      | 最低价                                    |
| last   | float  | `55989.93`      | 最新价                                    |
| vol    | float  | `51.21`         | 交易量                                    |
| rose   | string | `+0.05`         | 涨跌幅，`+`为涨，`-`为跌，`+0.05`为涨`5%` |
| buy    | float  | `55988.10`      | 买一价格                                  |
| sell   | float  | `55990.10`      | 卖一价格                                  |

### 获取指数/标记价格

`GET` `https://t(:futures_url)/fapi/v1/index`

> 请求示例

```http
GET https://t(:futures_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:futures_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:futures_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:futures_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
$url = "https://t(:futures_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_url)/fapi/v1/index?contractName=E-BTC-USDT&limit=100';

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
  console.log('请求错误:', err.message);
});
```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |
| limit                                   | string | 默认：100；最大：1000              |

> 返回示例

```json
{
    "currentFundRate": -0.0037500000000000,
    "indexPrice": 27905.9800000000000000,
    "tagPrice": 27824.4422146875000000,
    "nextFundRate": -0.0037500000000000
}
```

**返回参数**

| 名称            | 类型  | 例子                     | 描述                         |
| :---------------| :-----| :------------------------| :----------------------------|
| indexPrice      | float | `27905.9800000000000000` | 指数价格                     |
| tagPrice        | float | `27824.4422146875000000` | 标记价格                     |
| nextFundRate    | float | `-0.0037500000000000`    | 资金费率价格                 |
| currentFundRate | float | `-0.0037500000000000`    | 上期资金费率（用于本期结算） |

### K线/蜡烛图数据

`GET https://t(:futures_url)/fapi/v1/klines`

> 请求示例

```http
GET https://t(:futures_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000

// Headers 设定
Content-Type:application/json
```

```shell
curl -X GET "https://t(:futures_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000"
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
      // 使用 URI 创建 URL
      URI uri = new URI("https://t(:futures_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000");
      HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
      conn.setRequestMethod("GET");
      conn.setRequestProperty("User-Agent", "Java-Client");

      // 读取响应
      BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();

      // 输出结果
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
	url := "https://t(:futures_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000"

	// 发送 GET 请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	// 打印响应
	fmt.Println("服务器返回:", string(body))
}
```

```python
import requests

url = "https://t(:futures_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000"

try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
    print("Response:", response.text)
except requests.exceptions.RequestException as e:
    print("请求错误:", e)
```

```php
$url = "https://t(:futures_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000";

// 初始化 cURL
$ch = curl_init();

// 设置 cURL 选项
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 跳过 SSL 证书验证（如果 API 需要）

// 执行请求
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL 错误：" . curl_error($ch);
} else {
    echo "Response: " . $response;
}

// 关闭 cURL
curl_close($ch);
```

```javascript--node
const https = require('https');

const url = 'https://t(:futures_url)/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1739116800000&endTime=1739852318000';

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
  console.log('请求错误:', err.message);
});
```

**请求参数**

| 参数名                                  | 类型    | 描述                                                                                                                                            |
| :---------------------------------------| :-------| :-----------------------------------------------------------------------------------------------------------------------------------------------|
| contractName<font color="red">\*</font> | string  | `大写`合约名称，例如：`E-BTC-USDT`                                                                                                              |
| interval<font color="red">\*</font>     | string  | K线图区间，可识别的参数值为：`1min`，`5min`，`15min`，`30min`，`1h`，`1day`，`1week`，`1month`（min=分钟，h=小时，day=天，week=星期，month=月） |
| limit                                   | integer | 默认：100；最大：300                                                                                                                            |
| startTime                               | long    | 开始时间戳                                                                                                                                      |
| endTime                                 | long    | 结束时间戳                                                                                                                                      |

> 返回示例

```json
[
    {
        "high": 6228.77,
        "vol": 111,
        "low": 6190.48,
        "idx": 15946403400000,
        "close": 6210.51,
        "open": 6195.80
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

**返回参数**

| 参数名 | 类型  | 示例             | 描述       |
| :------| :-----| :----------------| :----------|
| idx    | long  | `15946403400000` | 开始时间戳 |
| open   | float | `6195.80`        | 开盘价     |
| close  | float | `6210.51`        | 收盘价     |
| high   | float | `6228.77`        | 最高价     |
| low    | float | `6190.48`        | 最低价     |
| vol    | float | `111`            | 成交量     |

## 交易

### 安全类型: TRADE

<aside class="notice">交易下方的接口都需要签名和API-key验证</aside>

### 创建订单

`POST https://t(:futures_url)/fapi/v1/order`

创建单个新订单

**请求头**

| 参数名                                 | 类型   | 描述        |
| :--------------------------------------| :------| :-----------|
| X-CH-TS<font color="red">\*</font>     | string | 时间戳      |
| X-CH-APIKEY<font color="red">\*</font> | string | 您的API-KEY |
| X-CH-SIGN<font color="red">\*</font>   | string | 签名        |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/order

body
{"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/order"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/order";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{\"contractName\":\"E-BTC-USDT\",\"price\":65000.00,\"volume\":1.00,\"type\":\"LIMIT\",\"side\":\"BUY\",\"open\":\"OPEN\",\"positionType\":1,\"clientOrderId\":\"111000111\",\"timeInForce\":\"IOC\"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/order"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/order"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","price":65000.00,"volume":1.00,"type":"LIMIT","side":"BUY","open":"OPEN","positionType":1,"clientOrderId":"111000111","timeInForce":"IOC"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/order";

// 请求方法和请求主体
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

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/order";

// 请求方法和请求主体
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

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                                                             |
| :---------------------------------------| :------| :----------------------------------------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT`                               |
| price                                   | number | 下单价格，限价单时该字段为必传，有精度限制，精度由管理员设置       |
| volume<font color="red">\*</font>       | number | 下单张数，有精度限制，精度由管理员设置，市价开仓时这里单位是价值 |
| type<font color="red">\*</font>         | string | 订单类型，`LIMIT/MARKET`                                         |
| side<font color="red">\*</font>         | string | 买卖方向，`BUY/SELL`                                             |
| open<font color="red">\*</font>         | string | 开平仓方向，`OPEN/CLOSE`                                         |
| positionType<font color="red">\*</font> | number | 持仓类型，`1:全仓/2:逐仓`                                        |
| timeInForce                             | string | `IOC, FOK, POST_ONLY`                                            |
| clientOrderId                           | string | 客户端下单标识，长度小于32位的字符串                             |

> 返回示例

```json
{
    "orderId": 256609229205684228
}
```

**返回参数**

| 参数名  | 类型   | 示例                 | 描述   |
| :-------| :------| :--------------------| :------|
| orderId | string | `256609229205684228` | 订单ID |

### 创建条件单

`POST https://t(:futures_url)/fapi/v1/conditionOrder`

**请求头**

| 参数名                                 | 类型   | 描述        |
| :--------------------------------------| :------| :-----------|
| X-CH-TS<font color="red">\*</font>     | string | 时间戳      |
| X-CH-APIKEY<font color="red">\*</font> | string | 您的API-KEY |
| X-CH-SIGN<font color="red">\*</font>   | string | 签名        |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/conditionOrder

body
{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/conditionOrder"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/conditionOrder";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/conditionOrder"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/conditionOrder"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","price":"100.00","volume":"1.00","type":"LIMIT","side":"BUY","positionType":"1","open":"OPEN","triggerType":"1","triggerPrice":"455"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/conditionOrder";

// 请求方法和请求主体
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

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/conditionOrder";

// 请求方法和请求主体
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

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                                                             |
| :---------------------------------------| :------| :----------------------------------------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT`                               |
| price<font color="red">\*</font>        | number | 下单价格，有精度限制，精度由管理员设置                           |
| volume<font color="red">\*</font>       | number | 下单数量，市价开仓时这里单位是价值，有精度限制，精度由管理员设置 |
| type<font color="red">\*</font>         | string | 订单类型，`LIMIT`/`MARKET`                                      |
| side<font color="red">\*</font>         | string | 买卖方向，`BUY`/`SELL`                                           |
| positionType<font color="red">\*</font> | number | 持仓类型，1：`全仓`，2：`逐仓`                                   |
| open<font color="red">\*</font>         | string | 开平仓方向，`OPEN`/`CLOSE`                                       |
| triggerType<font color="red">\*</font>  | string | 条件的类型，1：`止损`，2：`止盈`，3：`追涨`，4：`杀跌`           |
| triggerPrice<font color="red">\*</font> | string | 触发价                                                           |
| clientOrderId                           | string | 客户端下单标识，长度小于32位的字符串                             |

> 返回示例

```json
{
    "code": "0",
    "msg": "Success",
    "data": {
        "triggerIds": [
            "1322738336974712847"
        ],
        "ids": [
            
        ],
        "cancelIds": [
            
        ]
    },
    "succ": true
}
```

如果该接口返回与期望不符，请联系技术团队，我们会为您提供相关帮助

### 取消订单

`POST https://t(:futures_url)/fapi/v1/cancel`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/cancel

body
{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/cancel"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/cancel";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/cancel"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/cancel"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/cancel";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "orderId" => 2616833860188981826
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/cancel";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    orderId: "2616833860188981826"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |
| orderId<font color="red">\*</font>      | string | 订单ID                             |

> 返回示例

```json
{
    "orderId": "256609229205684228"
}
```

### 取消条件单

`POST https://t(:futures_url)/fapi/v1/cancel_trigger_order`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/cancel_trigger_order

body
{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/cancel_trigger_order"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/cancel_trigger_order";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/cancel_trigger_order"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/cancel_trigger_order"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/cancel_trigger_order";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "orderId" => 2616833860188981826
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/cancel_trigger_order";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    orderId: "2616833860188981826"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |
| orderId<font color="red">\*</font>      | string | 订单ID                             |
| clientOrderId                           | string | 客户端唯一标识，默认：0            |

> 返回示例

```json
{
    "orderId": "256609229205684228"
}
```

### 订单详情

`GET https://t(:futures_url)/fapi/v1/order`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型   | 描述        |
| :--------------------------------------| :------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | string | 时间戳      |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/order

body
{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/order"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/order";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/order"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/order"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","orderId":"2616833860188981826"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/order";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT",
    "orderId" => 2616833860188981826
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/order";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    orderId: "2616833860188981826"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                   | 类型   | 描述                               |
| :----------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font>  | string | `大写`合约名称，例如：`E-BTC-USDT` |
| orderId<font color="red">\*</font>       | string | 订单ID                             |
| clientOrderId<font color="red">\*</font> | string | 客户端唯一标识，默认：0            |

> 返回示例

```json
{
    "side": "BUY",
    "executedQty": 0,
    "orderId": 2006628907041292645,
    "price": 67000.0000000000000000,
    "origQty": 2.0000000000000000,
    "avgPrice": 0,
    "transactTime": 1704967622000,
    "action": "OPEN",
    "contractName": "E-BTC-USDT",
    "type": "LIMIT",
    "timeInForce": "1",
    "status": "NEW",
    "fills": [

    ]
}
```

**返回参数**

| 参数名       | 类型    | 示例                     | 描述                                                                                                                                                  |
| :------------| :-------| :------------------------| :-----------------------------------------------------------------------------------------------------------------------------------------------------|
| orderId      | long    | `2006628907041292645`    | 订单ID（系统生成                                                                                                                                      |
| contractName | string  | `E-BTC-USDT`             | `大写`合约名称                                                                                                                                        |
| price        | float   | `67000.0000000000000000` | 委托价格                                                                                                                                              |
| origQty      | float   | `2.0000000000000000`     | 委托数量                                                                                                                                              |
| executedQty  | float   | `0`                      | 成交数量                                                                                                                                              |
| avgPrice     | float   | `0`                      | 成交均价                                                                                                                                              |
| status       | string  | `NEW`                    | 订单状态。可能出现的值为：`NEW`（新订单，无成交）、`PARTIALLY_FILLED`（部分成交）、`FILLED`（全部成交）、`CANCELED`（已取消）和`REJECTED`（订单被拒绝） |
| side         | string  | `BUY`                    | 订单方向。可能出现的值只能为：`BUY`（买入做多）和`SELL`（卖出做空）                                                                                   |
| action       | string  | `OPEN`                   | `OPEN/CLOSE`                                                                                                                                          |
| transactTime | long    | `1704967622000`          | 订单创建时间                                                                                                                                          |
| type         | string  | `LIMIT`                  | 订单类型`LIMIT`/`MARKET`                                                                                                                              |
| timeInForce  | integer | `1`                      | 条件单有效方式，1：`limit`，2：`market`，3：`IOC`，4：`FOK`，5： `POST\_ONLY`                                                                         |
| fills        | array   |                          | 成交记录                                                                                                                                              |

### 当前订单

`GET https://t(:futures_url)/fapi/v1/openOrders`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型   | 描述        |
| :--------------------------------------| :------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | string | 时间戳      |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/openOrders

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/openOrders"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/openOrders";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/openOrders"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/openOrders"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/openOrders";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/openOrders";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |

> 返回示例

```json
[
    {
        "side": "BUY",
        "executedQty": 0.5,
        "orderId": 259396989397942275,
        "price": 72000.0000000000000000,
        "origQty": 1.0000000000000000,
        "avgPrice": 71990.0,
        "transactTime": 1607702400000,
        "action": "OPEN",
        "contractName": "E-BTC-USDT",
        "type": "LIMIT",
        "status": "NEW"
    }
]
```

返回参数

| 参数名       | 类型   | 示例                     | 描述                                                                                                                                                    |
| :------------| :------| :------------------------| :-------------------------------------------------------------------------------------------------------------------------------------------------------|
| orderId      | long   | `259396989397942275`     | 订单ID（系统生成）                                                                                                                                      |
| contractName | string | `E-BTC-USDT`             | `大写`合约名称                                                                                                                                          |
| price        | float  | `72000.0000000000000000` | 订单价格                                                                                                                                                |
| origQty      | float  | `1.0000000000000000`     | 订单数量                                                                                                                                                |
| executedQty  | float  | `0.5`                    | 已经成交订单数量                                                                                                                                        |
| avgPrice     | float  | `71990.0`                | 订单已经成交的平均价格                                                                                                                                  |
| type         | string | `LIMIT`                  | 订单类型。可能出现的值只能为：`LIMIT`（限价）和`MARKET`（市价）                                                                                         |
| side         | string | `BUY`                    | 订单方向。可能出现的值只能为：`BUY`（买入做多）和 `SELL`（卖出做空）                                                                                    |
| status       | string | `NEW`                    | 订单状态。可能出现的值为：`NEW`（新订单，无成交）、`PARTIALLY_FILLED`（部分成交）、`FILLED`（全部成交）、`CANCELED`（已取消）和`REJECTED`（订单被拒绝） |
| action       | string | `OPEN`                   | `OPEN/CLOSE`                                                                                                                                            |
| transactTime | long   | `1607702400000`          | 订单创建时间戳                                                                                                                                          |

### 历史委托

`POST https://t(:futures_url)/fapi/v1/orderHistorical`

**请求头**

| 参数名                                 | 类型   | 描述        |
| :--------------------------------------| :------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | string | 时间戳      |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/orderHistorical

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/orderHistorical"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/orderHistorical";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/orderHistorical"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/orderHistorical"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/orderHistorical";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/orderHistorical";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |
| limit                                   | string | 分页条数，默认：100；最大：1000    |
| fromId                                  | long   | 从这条记录开始检索                 |

> 返回示例

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

如果该接口返回与期望不符，请联系技术团队，我们会为您提供相关帮助

### 盈亏记录

`POST https://t(:futures_url)/fapi/v1/profitHistorical`

如果该接口返回报错，请联系技术团队，我们会为您提供相关帮助

**请求头**

| 参数名                                 | 类型   | 描述        |
| :--------------------------------------| :------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | string | 时间戳      |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/profitHistorical

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/profitHistorical"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/profitHistorical";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/profitHistorical"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/profitHistorical"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/profitHistorical";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/profitHistorical";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |
| limit                                   | string | 分页条数，默认：100；最大：1000    |
| fromId                                  | long   | 从这条记录开始检索                 |

> 返回示例

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

如果该接口返回与期望不符，请联系技术团队，我们会为您提供相关帮助

### 交易记录

`GET https://t(:futures_url)/fapi/v1/myTrades`

**限速规则: 20次/2s**

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/myTrades

body
{"contractName":"E-BTC-USDT"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/myTrades"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/myTrades";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/myTrades"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/myTrades"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/myTrades";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName" => "E-BTC-USDT"
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/myTrades";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型   | 描述                               |
| :---------------------------------------| :------| :----------------------------------|
| contractName<font color="red">\*</font> | string | `大写`合约名称，例如：`E-BTC-USDT` |
| limit                                   | string | 分页条数，默认：100；最大：1000    |
| fromId                                  | long   | 从这个tradeId开始检索              |

> 返回示例

```json
[
    {
        "amount": 0.30000000000000000000000000000000,
        "side": "BUY",
        "fee": 0.001,
        "isMaker": true,
        "isBuyer": true,
        "bidId": 1874564572563538130,
        "bidUserId": 10034,
        "price": 10.0000000000000000,
        "qty": 3,
        "askId": 1954072405852309104,
        "contractName": "E-ETH-USDT",
        "time": 1701419186000,
        "tradeId": 1528,
        "askUserId": 10378
    },
    {
        "amount": 1.00000000000000000000000000000000,
        "side": "BUY",
        "fee": 0.00025,
        "isMaker": true,
        "isBuyer": true,
        "bidId": 1874564572563538059,
        "bidUserId": 10034,
        "price": 10.0000000000000000,
        "qty": 10,
        "askId": 1954072405852309104,
        "contractName": "E-ETH-USDT",
        "time": 1701419186000,
        "tradeId": 1527,
        "askUserId": 10378
    }
]
```

**返回参数**

| 参数名       | 类型    | 示例                  | 描述                                    |
| :------------| :-------| :---------------------| :---------------------------------------|
| tradeId      | number  | `1528`                | 交易ID                                  |
| bidId        | long    | `1874564572563538130` | 买方订单ID                              |
| askId        | long    | `1954072405852309104` | 卖方订单ID                              |
| bidUserId    | integer | `10034`               | 买方用户ID                              |
| askUserId    | integer | `10378`               | 卖方用户ID                              |
| price        | float   | `10.0`                | 成交价格                                |
| qty          | float   | `3`                   | 交易数量                                |
| amount       | float   | `30.0`                | 成交金额                                |
| time         | number  | `1499865549590`       | 交易时间戳                              |
| fee          | number  | `0.001`               | 交易手续费                              |
| side         | string  | `BUY`                 | 当前订单方向，`BUY`：买入，`SELL`：卖出 |
| contractName | string  | `E-BTC-USDT`          | `大写`合约名称                          |
| isMaker      | boolean | `true`                | 是否是maker                             |
| isBuyer      | boolean | `true`                | 是否买方                                |

### 更改持仓模式

`POST https://t(:futures_url)/fapi/v1/edit_user_position_model`

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/edit_user_position_model

body
{"contractName":"E-BTC-USDT","positionModel":"1"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/edit_user_position_model"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","positionModel":"1"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/edit_user_position_model";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT","positionModel":"1"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/edit_user_position_model"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","positionModel":"1"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/edit_user_position_model"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","positionModel":"1"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/edit_user_position_model";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName"  => "E-BTC-USDT",
    "positionModel" => "1"
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/edit_user_position_model";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    positionModel: "1"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                   | 类型    | 描述                                 |
| :----------------------------------------| :-------| :------------------------------------|
| contractName<font color="red">\*</font>  | string  | 合约名称，例如：`E-BTC-USDT`         |
| positionModel<font color="red">\*</font> | integer | 持仓模式，1：`净持仓`，2：`双向持仓` |

> 返回示例

```json
{
    "code": "0",
    "msg": "成功",
    "data": null
}
```

### 更改保证金模式

`POST https://t(:futures_url)/fapi/v1/edit_user_margin_model`

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/edit_user_margin_model

body
{"contractName":"E-BTC-USDT","marginModel":"1"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/edit_user_margin_model"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","marginModel":"1"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/edit_user_margin_model";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT","marginModel":"1"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/edit_user_margin_model"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","marginModel":"1"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/edit_user_margin_model"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","marginModel":"1"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/edit_user_margin_model";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName"  => "E-BTC-USDT",
    "marginModel" => "1"
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/edit_user_margin_model";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    marginModel: "1"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                  | 类型    | 描述                                 |
| :---------------------------------------| :-------| :------------------------------------|
| contractName<font color="red">\*</font> | string  | 合约名称，例如：`E-BTC-USDT`         |
| marginModel<font color="red">\*</font>  | integer | 持仓模式，1：`净持仓`，2：`双向持仓` |

> 返回示例

```json
{ 
    "code": "0", 
    "msg": "成功", 
    "data": null 
}
```

### 更改杠杆倍数

`POST` `https://t(:futures_url)/fapi/v1/edit_lever`

**请求头**

| 参数名                                 | 类型    | 描述        |
| :--------------------------------------| :-------| :-----------|
| X-CH-TS<font color="red">\*</font>     | integer | 时间戳      |
| X-CH-APIKEY<font color="red">\*</font> | string  | 您的API-key |
| X-CH-SIGN<font color="red">\*</font>   | string  | 签名        |

> 请求示例

```http
POST https://t(:futures_url)/fapi/v1/edit_lever

body
{"contractName":"E-BTC-USDT","newLever":"1"}
```

```shell
#!/bin/bash

# API 相关信息
api_key="您的API-KEY"
api_secret="您的API-SECRET"

# 请求信息
timestamp=$(($(date +%s%N)/1000000))  # 毫秒级时间戳
method="POST"
request_path="/fapi/v1/edit_lever"

# 请求主体 (JSON 格式)
body='{"contractName":"E-BTC-USDT","newLever":"1"}'

# 删除 body 中的空白字符，保证签名的一致性
body=$(echo "$body" | jq -c)

# 拼接签名字符串
sign_str="${timestamp}${method}${request_path}${body}"
echo "签名字符串: $sign_str"

# 生成 HMAC SHA256 签名
signature=$(echo -n "$sign_str" | openssl dgst -sha256 -hmac "$api_secret" | awk '{print $2}')
echo "签名 (X-CH-SIGN): $signature"

# 发送 POST 请求
response=$(curl -s -X POST "https://t(:futures_url)${request_path}" \
    -H "Content-Type: application/json" \
    -H "X-CH-TS: $timestamp" \
    -H "X-CH-APIKEY: $api_key" \
    -H "X-CH-SIGN: $signature" \
    -d "$body")

# 输出响应结果
echo "响应: $response"
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

    // API 相关信息
    private static final String API_KEY = "您的API-KEY";
    private static final String API_SECRET = "您的API-SECRET";
    private static final String BASE_URL = "https://t(:futures_url)";
    private static final String REQUEST_PATH = "/fapi/v1/edit_lever";

    public static void main(String[] args) {
        try {
            // 获取时间戳 (毫秒)
            long timestamp = TimeUnit.MILLISECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

            // 请求方法
            String method = "POST";

            // 请求主体 (JSON 格式，注意使用紧凑格式)
            String body = "{"contractName":"E-BTC-USDT","newLever":"1"}";
            System.out.println("请求主体 (body): " + body);

            // 拼接签名字符串
            String signStr = timestamp + method + REQUEST_PATH + body;
            System.out.println("签名字符串: " + signStr);

            // 生成 HMAC SHA256 签名
            String signature = hmacSHA256(signStr, API_SECRET);
            System.out.println("签名 (X-CH-SIGN): " + signature);

            // 使用 URI 创建 URL
            URI uri = new URI(BASE_URL + REQUEST_PATH);
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-CH-TS", String.valueOf(timestamp));
            conn.setRequestProperty("X-CH-APIKEY", API_KEY);
            conn.setRequestProperty("X-CH-SIGN", signature);
            conn.setRequestProperty("User-Agent", "Java-Client");
            conn.setDoOutput(true);

            // 发送请求主体
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            // 读取响应
            int responseCode = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    responseCode >= 200 && responseCode < 300 ? conn.getInputStream() : conn.getErrorStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // 输出响应结果
            System.out.println("响应 (" + responseCode + "): " + response.toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成 HMAC SHA256 签名
     *
     * @param data   要签名的字符串
     * @param secret 密钥
     * @return HMAC SHA256 签名
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

// API 相关信息
const (
	APIKey     = "您的API-KEY"
	APISecret  = "您的API-SECRET"
	BaseURL    = "https://t(:futures_url)"
	RequestPath = "/fapi/v1/edit_lever"
)

func main() {
	// 获取毫秒级时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	// 请求方法
	method := "POST"

	// 请求主体 (JSON 格式)
	body := `{"contractName":"E-BTC-USDT","newLever":"1"}`

	// 拼接签名字符串
	signStr := fmt.Sprintf("%d%s%s%s", timestamp, method, RequestPath, body)
	fmt.Println("签名字符串:", signStr)

	// 生成 HMAC SHA256 签名
	signature := generateHMACSHA256(signStr, APISecret)
	fmt.Println("签名 (X-CH-SIGN):", signature)

	// 发送 POST 请求
	url := BaseURL + RequestPath
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	req.Header.Set("X-CH-APIKEY", APIKey)
	req.Header.Set("X-CH-SIGN", signature)

	// 执行请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	responseBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("响应:", string(responseBody))
}

// 生成 HMAC SHA256 签名
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

# API 相关信息
API_KEY = "您的API-KEY"
API_SECRET = "您的API-SECRET"
BASE_URL = "https://t(:futures_url)"
REQUEST_PATH = "/fapi/v1/edit_lever"

# 请求方法和请求主体
method = "POST"
body = {"contractName":"E-BTC-USDT","newLever":"1"}


# 获取时间戳 (毫秒级)
timestamp = int(time.time() * 1000)

# 将请求主体转换为紧凑的 JSON 字符串
import json
body_str = json.dumps(body, separators=(',', ':'))
print("请求主体 (body):", body_str)

# 拼接签名字符串
sign_str = f"{timestamp}{method}{REQUEST_PATH}{body_str}"
print("签名字符串:", sign_str)

# 生成 HMAC SHA256 签名
signature = hmac.new(API_SECRET.encode('utf-8'), sign_str.encode('utf-8'), hashlib.sha256).hexdigest()
print("签名 (X-CH-SIGN):", signature)

# 构建请求头
headers = {
    "Content-Type": "application/json",
    "X-CH-TS": str(timestamp),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Python-Client"
}

# 发送 POST 请求
url = BASE_URL + REQUEST_PATH
response = requests.post(url, headers=headers, data=body_str)

# 输出响应结果
print("响应状态码:", response.status_code)
print("响应内容:", response.text)
```
```php
// API 相关信息
$apiKey = "您的API-KEY";
$apiSecret = "您的API-SECRET";
$baseUrl = "https://t(:futures_url)";
$requestPath = "/fapi/v1/edit_lever";

// 请求方法和请求主体
$method = "POST";
$body = json_encode([
    "contractName"  => "E-BTC-USDT",
    "newLever" => "1"
], JSON_UNESCAPED_SLASHES);

// 获取毫秒级时间戳
$timestamp = round(microtime(true) * 1000);

// 拼接签名字符串
$signStr = $timestamp . $method . $requestPath . $body;
echo "签名字符串: " . $signStr . PHP_EOL;

// 生成 HMAC SHA256 签名
$signature = hash_hmac('sha256', $signStr, $apiSecret);
echo "签名 (X-CH-SIGN): " . $signature . PHP_EOL;

// 构建请求头
$headers = [
    "Content-Type: application/json",
    "X-CH-TS: $timestamp",
    "X-CH-APIKEY: $apiKey",
    "X-CH-SIGN: $signature",
    "User-Agent: PHP-Client"
];

// 发送 POST 请求
$url = $baseUrl . $requestPath;
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // 仅在开发环境中使用，生产环境应启用 SSL 验证

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if (curl_errno($ch)) {
    echo "请求失败: " . curl_error($ch) . PHP_EOL;
} else {
    echo "响应状态码: $httpCode" . PHP_EOL;
    echo "响应内容: $response" . PHP_EOL;
}

curl_close($ch);
```
```javascript--node
const crypto = require('crypto');
const axios = require('axios');

// API 相关信息
const API_KEY = "您的API-KEY";
const API_SECRET = "您的API-SECRET";
const BASE_URL = "https://t(:futures_url)";
const REQUEST_PATH = "/fapi/v1/edit_lever";

// 请求方法和请求主体
const method = "POST";
const body = JSON.stringify({
    contractName: "E-BTC-USDT",
    newLever: "1"
});

// 获取毫秒级时间戳
const timestamp = Date.now();

// 拼接签名字符串
const signStr = `${timestamp}${method}${REQUEST_PATH}${body}`;
console.log("签名字符串:", signStr);

// 生成 HMAC SHA256 签名
const signature = crypto.createHmac('sha256', API_SECRET).update(signStr).digest('hex');
console.log("签名 (X-CH-SIGN):", signature);

// 构建请求头
const headers = {
    "Content-Type": "application/json",
    "X-CH-TS": timestamp.toString(),
    "X-CH-APIKEY": API_KEY,
    "X-CH-SIGN": signature,
    "User-Agent": "Node.js-Client"
};

// 发送 POST 请求
async function sendOrder() {
    try {
        const response = await axios.post(`${BASE_URL}${REQUEST_PATH}`, body, { headers });
        console.log("响应状态码:", response.status);
        console.log("响应内容:", response.data);
    } catch (error) {
        console.error("请求失败:", error.response ? error.response.data : error.message);
    }
}

// 执行请求
sendOrder();

```

**请求参数**

| 参数名                                     | 类型    | 描述                   |
|:----------------------------------------| :-------|:---------------------|
| contractName<font color="red">\*</font> | string  | 合约名称，例如：`E-BTC-USDT` |
| newLever<font color="red">\*</font>     | integer | 调整杠杆倍数               |

> 返回示例

```json
{ 
    "code": "0", 
    "msg": "成功", 
    "data": null 
}
```

# Websocket

## 概述

WebSocket是HTML5一种新的协议（Protocol）。它实现了客户端与服务器全双工通信，使得数据可以快速地双向传播。通过一次简单的握手就可以建立客户端和服务器连接，服务器根据业务规则可以主动推送信息给客户端。其优点如下：

*   客户端和服务器进行数据传输时，请求头信息比较小，大概2个字节。
*   客户端和服务器皆可以主动地发送数据给对方。
*   不需要多次创建TCP请求和销毁，节约宽带和服务器的资源。

<aside class="notice">强烈建议开发者使用WebSocket API获取市场行情和买卖深度等信息。</aside>

## 基本信息

*   币币行情基础站点：<wss://t(:ws_url)/kline-api/ws>。
*   合约行情基础站点：<wss://t(:futures_ws_url)/kline-api/ws>。
*   返回数据除了心跳数据都会二进制压缩（用户需要通过Gzip算法进行解压）。

### 心跳

为了保持连接有效且稳定，建议您进行以下操作：

1. 每次接收到消息后，用户设置一个定时器，定时N秒，N小于30。

2. 如果定时器被触发（N秒内没有收到新消息），发送字符串'ping'。

3. 期待一个文字字符串'pong'作为回应。如果在N秒内未收到，请发出错误或重新连接。

> 心跳返回

```json
{
    "pong": 15359750
}
```

### Demo

[Websocket Demo](https://github.com/exchange2021/openapidemo/blob/master/src/main/java/com/ws/WsTest.java)

## 订阅/取消订阅参数

| event | channel                       | description             |
| :-----| :-----------------------------| :-----------------------|
| sub   | `market_$symbol_depth_step0`  | `订阅深度`              |
| unsub | `market_$symbol_depth_step0`  | `取消订阅深度`          |
| sub   | `market_$symbol_trade_ticker` | `订阅实时成交`          |
| unsub | `market_$symbol_trade_ticker` | `取消订阅实时成交`      |
| sub   | `market_$symbol_ticker`       | `订阅24h行情数据`       |
| unsub | `market_$symbol_ticker`       | `取消订阅24h行情数据`   |
| sub   | `market_$symbol_kline_1min`   | `订阅1min实时K线信息`   |
| req   | `market_$symbol_kline_1month` | `请求1month历史K线记录` |


## 订阅

### 订阅全量深度

> 订阅示例

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_depth_step0", // $symbol E.g. 币币：btcusdt 合约：e_btcusdt
        "cb_id": "1" // 业务id非必填
    }
}
```

> 返回示例

```json
{
    "channel": "market_btcusdt_depth_step0",
    "ts": 1506584998239,
    "tick": {
        "asks": [ //卖盘
            [
                10000.19,
                0.93
            ],
            [
                10001.21,
                0.2
            ],
            [
                10002.22,
                0.34
            ]
        ],
        "bids": [ //买盘
            [
                9999.53,
                0.93
            ],
            [
                9998.2,
                0.2
            ],
            [
                9997.19,
                0.21
            ]
        ]
    }
}
```

### 订阅实时成交

> 订阅示例

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_trade_ticker", // $symbol E.g. 币币: btcusdt，合约: e_btcusdt
        "cb_id": "1" // 业务id非必填
    }
}
```

> 返回示例

```json
{
    "channel": "market_$symbol_trade_ticker",
    "ts": 1506584998239, // 请求时间
    "tick": {
        "id": 12121, // data中最大交易ID
        "ts": 1506584998239, // data中最大时间
        "data": [
            {
                "side": "buy", // 买卖方向buy，sell
                "price": 32.233, // 单价
                "vol": 232, // 数量
                "amount": 323, // 总额
                "ds": "2017-09-1023: 12: 21"
            }
        ]
    }
}
```
### 订阅K线行情

> 订阅示例

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_kline_[1min/5min/15min/30min/60min/1day/1week/1month]", // $symbol E.g. btcusdt
        "cb_id": "1" // 业务id非必填
    }
}
```

> 返回示例

```json
{
    "channel": "market_$symbol_kline_1min", // 1min代表1分钟K线
    "ts": 1506584998239, // 请求时间
    "tick": {
        "id": 1506602880, // 时间刻度起始值
        "vol": 1212.12211, // 交易量
        "open": 2233.22, // 开盘价
        "close": 1221.11, // 收盘价
        "high": 22322.22, // 最高价
        "low": 2321.22 // 最低价
    }
}
```

### 订阅24h行情Ticker

> 订阅示例

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_ticker", // $symbol E.g. 币币：btcusdt 合约：e_btcusdt
        "cb_id": "1" // 业务id非必填
    }
}
```

> 返回示例

```json
{
    "channel": "market_$symbol_ticker",
    "ts": 1506584998239, // 请求时间
    "tick": {
        "amount": 123.1221, // 交易额
        "vol": 1212.12211, // 交易量
        "open": 2233.22, // 开盘价
        "close": 1221.11, // 收盘价
        "high": 22322.22, // 最高价
        "low": 2321.22, // 最低价
        "rose": -0.2922, // 涨幅
    }
}
```

### 请求K线历史数据

> 订阅示例

```json
{
    "event": "req",
    "params": {
        "channel": "market_$symbol_kline_[1min/5min/15min/30min/60min/1day/1week/1month]",
        "cb_id": "1",
        "endIdx": "1506602880", // 返回endIdx前pageSize条数据 非必填
        "pageSize": 100 // 非必填
    }
}
```

> 返回示例

```json
{
    "event_rep": "rep",
    "channel": "market_$symbol_kline_5min",
    "cb_id": "原路返回",
    "ts": 1506584998239, // 请求时间
    "data": [ // 最多300条
        {
            "id": 1506602880, // 时间刻度起始值
            "amount": 123.1221, // 交易额
            "vol": 1212.12211, // 交易量
            "open": 2233.22, // 开盘价
            "close": 1221.11, // 收盘价
            "high": 22322.22, // 最高价
            "low": 2321.22 // 最低价
        },
        {
            "id": 1506602880, // 时间刻度起始值
            "amount": 123.1221, // 交易额
            "vol": 1212.12211, // 交易量
            "open": 2233.22, // 开盘价
            "close": 1221.11, // 收盘价
            "high": 22322.22, // 最高价
            "low": 2321.22 // 最低价
        }
    ]
}
```

### 请求成交记录

> 请求示例

```json
{
    "event": "req",
    "params": {
        "channel": "market_$symbol_trade_ticker", // $symbol E.g. 币币：btcusdt 合约：e_btcusdt
        "cb_id": "1" // 业务id非必填
    }
}
```

> 返回示例

```json
{
    "event_rep": "rep",
    "channel": "market_$symbol_trade_ticker",
    "cb_id": "原路返回",
    "ts": 1506584998239,
    "status": "ok",
    "data": [
        {
            "side": "buy", // 买卖方向buy，sell
            "price": 32.233, // 单价
            "vol": 232, // 数量
            "amount": 323 // 总额
        },
        {
            "side": "buy", // 买卖方向buy，sell
            "price": 32.233, // 单价
            "vol": 232, // 数量
            "amount": 323 // 总额
        }
    ]
}
```

# SDK开发库

## Java

[JAVA Demo](https://github.com/exchange2021/openApi-java-demo/tree/master/src/main/java/com)

# 常见问题

## 请求接口的timestamp参数和到达服务器时间最大差值是多少？

服务器收到请求时会判断请求中的时间戳，如果是5000毫秒之前发出的，则请求会被认为无效。这个时间窗口值可以通过发送可选参数`recvWindow`来自定义。

## 请求头"X-CH-TS"不能为空，如何解决？

首先建议用户打印一下`X-CH-TS`，出现异常时检查`X-CH-TS`是否为空，另外建议用户对代码优化，每次请求前先判断`X-CH-TS`是否为空。

## 为什么签名认证总返回无效的签名？

可以打印出请求头信息和签名前字符串，重点有以下几点：

* 将您的请求头和下面的请求头示例一一对比

```json
请求头示例：

Content-Type: application/json

X-CH-APIKEY: 44c541a1-****-****-****-10fe390df2

X-CH-SIGN: ssseLeefrffraoEQ3yI9qEtI1CZ82ikZ4xSG5Kj8gnl3uw=

X-CH-TS: 1574327555669
```

* 是否在程序中正确的配置了API-key。

* 签名前字符串是否符合标准格式，所有要素的顺序要保持一致。可以复制如下示例跟您的签名前字符串进行比对：

> GET示例

```http
1588591856950GET/sapi/v1/account
```

> POST示例

```http
1588591856950POST/sapi/v1/order/test{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}
```

## 调用接口提示ILLEGAL\_CONTENT\_TYPE(-1017)，是什么原因？

我们建议在所有的请求头附加`Content-Type`，并设置成`'application/json'`。

## API每秒调用频率有限制吗？

有限制，具体可以看下文档中每个接口的访问频率限制。

## API的访问频率是根据什么限制的？

个人数据是根据**API-key**限制的，公共数据是根据**ip**限制，需要注意的是，若用户请求公共数据时传入有效的个人信息就根据**API-key**限制。

## HTTP状态码429是怎样造成的？

请求接口超过访问频率限制，建议降低访问频率。

## API调用接口报超过访问频率会被封IP吗？封多久？

通常情况下不会的，降低访问频率就可以。

## 为什么WebSocker出现了断开连接？

*   未添加心跳，WebSocket连接需客户端需要回pong，保证连接的稳定。
*   网络原因造成客户端发送的pong消息，但服务端并未接收到，或其他网络原因也会导致自动断开连接。
*   建议用户做好WebSocket断开重连机制，在确保心跳（ping/pong）连接意外断开时，程序能够自动重新进行连接。

## 用户请求接口报错Time Out？

网络无法连接服务器，建议您检查下网络是否通畅。

## 如何拿到平台所有的币对

现货交易中的`/sapi/v1/symbols`接口可以拿到。

## 批量下单/撤单有条数限制吗？

是的。批量接口会限制10条订单。

## newClientOrderId是什么, 有什么作用?

* newClientOrderId是您自定义的订单号，可以用来标识您的一笔订单，当下单完成后，可以使用newClientOrderId并调用`订单信息`接口，查看订单状态。
* 用户需要自己保证此ID不重复，我方不会进行重复检测，如有重复，撤单和查询订单时只能撤销或者查询其中最新的一条数据。

## 如何获取最新成交价格？

可以通过获取Ticker信息，返回结果中的last就是最新成交价。

## Ticker接口中的24小时成交量会出现负增长吗？

会的。因为24小时成交量，为24小时滚动数据（平移窗口大小24小时），有可能会出现后一个窗口内的累计成交量、累计成交额小于前一窗口的情况。

