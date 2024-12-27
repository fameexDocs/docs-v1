# Documentation Description

## Example of Interface

The interface below is the interface for obtaining server time. This interface is used as an example to show the interface format, access link, and parameter description.

### Check Server Time

`GET https://openapi.xxx.com/sapi/v1/time`

Check Server Time

> request example

```http
GET https://openapi.xxx.com/sapi/v1/time
```

> response example

```json
{
    "timezone": "China Standard Time",
    "serverTime": 1705039779880
}
```

**Response Parameter**

| Parameter  | Type   | Example               | Description      |
| :----------| :------| :---------------------| :----------------|
| timezone   | string | `China Standard Time` | Server time zone |
| serverTime | long   | `1705039779880`       | Server timestamp |

## Document Parameter Specifications

The red <font color="red">\*</font> in the upper right corner of the input parameter name indicates that the parameter must be inputted, otherwise it is not required.

The interface is case-sensitive to input parameter characters, which will be clearly specified in the interface. If the currency pair name is in uppercase, you need to enter BTCUSDT, but btcusdt is not allowed.

The input parameters in the document have clear type descriptions and need to be entered according to the specified type. For example, the integer type can only input numeric types. The input of 3 is correct, but the input of "3" is not allowed.

## Does the Interface Require Signature Verification?

Interface types are divided into: Public, Market, Trade, Account.

*   The interfaces under the "Public" and "Market" categories can be accessed without requiring an API key or signature.
*   "Trade" and "Account" security require API-Key and signature verification before access.
*   The signature content is related to the parameters. If the parameters are entered incorrectly, the parameter error or null value will be returned.
*   For interfaces that require signature verification, X-CH-SIGN, X-CH-APIKEY, and X-CH-TS must be added to the header for signature verification. For signature rules and examples, please refer to: [Signature Example](https://fameexdoc.github.io/docs-v1/en/index.html?go#example-of-signature) (apiKey and secretKey in this document are virtual values. The real content needs to be obtained by the user in the API management of the front page.)

## Return Code Type

Please refer to the document: [Return Enums](https://fameexdoc.github.io/docs-v1/en/index.html?go#return-code-type-2)

## API Basic Information

*   baseurl `https://openapi.xxx.com`
*   All endpoints return either a JSON object or array. 
*   Data is returned in Reverse order. newest first, oldest last.
*   All time and timestamp related fields are in **milliseconds**.

HTTP Error Codes

*   HTTP `4XX` return codes are used for malformed requests; the issue is on the sender's side.
*   HTTP `429` return code is used when breaking a request rate limit.
*   HTTP `418` return code is used when an IP has been auto-banned for continuing to send requests after receiving the 429 code.
*   HTTP `5XX` return codes are used for internal errors.
*   HTTP `504` return code is used when the API successfully sent the message but not get a response within the timeout period. It is important to NOT treat this as a failure operation; the execution status is UNKNOWN and could have been a success.
*   All endpoints can possibly return an ERROR, the error payload is as follows:

> response example

```json
{
    "code": -1121,
    "msg": "Invalid symbol."
}
```

## General Interface Information

*   All requests are based on the Https protocol, and the `Content-Type` in the request header information needs to be uniformly set to: `'application/json'`
*   For the interface of the `GET` method, the parameters must be sent in the `query string`.
*   For the interface of the `POST` method, the parameters must be sent in the `request body`.
*   Parameters may be sent in any order.

## Request Limits

*   There will be a limited frequency description below each interface.
*   The `429` code will be returned when either rate limit is violated.
*   When the `429` code is returned, the caller should reduce the access frequency or stop accessing.

## Endpoint Security Type

*   Each endpoint has a security type that determines how you will interact with it.
*   API-keys are passed into the Rest API via the `X-CH-APIKEY` header.
*   API-keys and secret-keys are case-sensitive.
*   In the web user center, the permissions associated with the API key can be modified, such as for reading account information, sending trade instructions, or initiating withdrawal requests.

| Security Type | Description                                              |
| :-------------| :--------------------------------------------------------|
| NONE          | Endpoint can be accessed freely.                         |
| TRADE         | Endpoint requires sending a valid API-Key and signature. |
| USER\_DATA    | Endpoint requires sending a valid API-Key and signature. |
| USER\_STREAM  | Endpoint requires sending a valid API-Key.               |
| MARKET\_DATA  | Endpoint requires sending a valid API-Key.               |

## SIGNED (TRADE and USER\_DATA) Endpoint Security

*   When calling the `TRADE` or `USER_DATA` interface, the signature parameter should be passed in the `X-CH-SIGN` field in the HTTP header.
*   The signature uses the `HMAC SHA256` algorithm. The API-Secret corresponding to the API-KEY is used as the `HMAC SHA256` key.
*   The request header of `X-CH-SIGN` is based on timestamp + method + requestPath + body string  (+ means string connection) as the operation object.
*   The value of timestamp is the same as the `X-CH-TS` request header, method is the request method, and the letters are all uppercase: GET/POST.
*   requestPath is the request interface path. For example: `sapi/v1/order?symbol=ethusdt&orderID=111000111`
*   `body` is the string of the request body (post only).
*   The signature is not case-sensitive.

## Timing Security

*   The signature interface needs to pass the timestamp in the `X-CH-TS` field in the HTTP header, and its value should be the unix timestamp (ms) of the request sending time. E.g. 1528394129373
*   An additional parameter, recvWindow, may be sent to specify the number of milliseconds after timestamp the request is valid for. If recvWindow is not sent, it defaults to 5000.
*   In addition, if the server calculates that the client's timestamp is more than one second ‘in the future’ of the server’s time, it will also reject the request.
*   The logic is as follows:

```java
if (timestamp < (serverTime + 1000) && (serverTime - timestamp) <= recvWindow) {
  // process request
} else {
  // reject request
}
```

<aside class="notice">Networks may be unstable and unreliable, which can lead to requests taking varying amounts of time to reach the servers. With <code>recvWindow</code>, you can specify that the request must be processed within a certain number of milliseconds or be rejected by the server. It is recommended to use a small <code>recvWindow</code> of 5000 or less!</aside>

## Endpoint Example for POST /sapi/v1/order/test

Here is a step-by-step example of how to send a valid signed payload from the Linux command line using echo, openssl, and curl.

| Key       | Value                            |
| :---------| :--------------------------------|
| apiKey    | vmPUZE6mv9SD5V5e14y7Ju91duEh8A   |
| secretKey | 902ae3cb34ecee2779aa4d3e1d226686 |

| Parameter | Value   |
| :---------| :-------|
| symbol    | BTCUSDT |
| side      | BUY     |
| type      | LIMIT   |
| volume    | 1       |
| price     | 9300    |

> Signature Example

> body

```json
{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}
```

> HMAC-SHA256 signature

```shell
echo -n "1588591856950POST/sapi/v1/order/test{\"symbol\":\"BTCUSDT\",\"price\":\"9300\",\"volume\":\"1\",\"side\":\"BUY\",\"type\":\"LIMIT\"}" | openssl dgst -sha256 -hmac "902ae3cb34ecee2779aa4d3e1d226686"
(stdin)= c50d0a74bb9427a9a03933d0eded03af9bf50115dc5b706882a4fcf07a26b761
```

> curl

```shell
curl -H "X-CH-APIKEY: c3b165fd5218cdd2c2874c65da468b1e" -H "X-CH-SIGN: c50d0a74bb9427a9a03933d0eded03af9bf50115dc5b706882a4fcf07a26b761
```

# Return Code Type

Descriptions and reasons of exception codes

<aside class="warning">The following return content is basic parameter verification. If the return code is not included in the return code types listed below, it is an error message returned from outside the business layer and needs to be docked with technical personnel.</aside>

## 10XX - General Server or Network Issues

### Code:-1000 UNKNOWN

msg: An unknown error occurred while processing the request.

Reason: An unknown error occurred while processing the request.

### Code:-1001 DISCONNECTED

msg: Internal error; unable to process your request. Please try again.

Reason: Internal error; unable to process your request.

### Code:-1002 UNAUTHORIZED

msg: You are not authorized to execute this request. The request needs to send an API Key, and we recommend appending the X-CH-APIKEY to all request headers.

Reason: The X\_CH\_APIKEY required for signature is not added to the header.

### Code:-1003 TOO\_MANY\_REQUESTS

msg: Requests exceed the limit too frequently.

Reason: Requests exceed the limit too frequently.

### Code:-1004 NO\_THIS\_COMPANY

msg: You are not authorized to execute this request. User does not exist.

Reason: You are not authorized to execute this request. User does not exist.

### Code:-1006 UNEXPECTED\_RESP

msg: An unexpected response was received from the message bus. Execution status unknown.

Reason: An unexpected response was received from the message bus. Execution status unknown. The OPEN API server finds some exceptions in executing the request. Please report to our Customer Service.

### Code:-1007 TIMEOUT

msg: Timeout waiting for response from backend server. Send status unknown; execution status unknown.

Reason: Request timed out.

### Code:-1014 UNKNOWN\_ORDER\_COMPOSITION

msg: Unsupported order combination.

Reason: The order combination does not exist or an incorrect order combination was entered.

### Code:-1015 TOO\_MANY\_ORDERS

msg: Too many orders. Please reduce the number of your orders.

Reason: The order quantity exceeds the maximum quantity limit.

### Code:-1016 SERVICE\_SHUTTING\_DOWN

msg: This server is no longer available.

Reason: This server is no longer available and the interface cannot be accessed.

### Code:-1017 NO\_CONTENT\_TYPE

msg: We recommend attaching Content-Type to all request headers and setting it to application/json.

Reason: The Content-Type is missing in the request header.

### Code:-1020 UNSUPPORTED\_OPERATION

msg: This operation is not supported.

Reason: An incorrect request operation was made, and coordination with the technical team is required to resolve the issue.

### Code:-1021 INVALID\_TIMESTAMP

msg: Invalid timestamp with too large time offset.

Reason: The timestamp offset is too large. Timestamp for this request was 1000ms ahead of the server's time. Please check the difference between your local time and server time.

### Code:-1022 INVALID\_SIGNATURE

msg: Invalid signature.

Reason: Signature verification failed.

### Code:-1023 UNAUTHORIZED

msg: You are not authorized to execute this request. The request need to send timestamps, and we recommend appending X-CH-TS to all request headers.

Reason: The X-CH-TS required for signature is not added to the header.

### Code:-1024 UNAUTHORIZED

msg: You are not authorized to execute this request. The request needs to send sign, and we recommend appending X-CH-SIGN to all request headers.

Reason: The X-CH-SIGN required for signature is not added to the header.

## 11XX - Request Issues

### Code:-1100 ILLEGAL\_CHARS

msg: Illegal characters found in a parameter.

Reason: Illegal characters exist in the request parameters.

### Code:-1101 TOO\_MANY\_PARAMETERS

msg: Too many parameters sent for this endpoint.

Reason: The parameter content is too large or duplicate parameter values were detected.

### Code:-1102 MANDATORY\_PARAM\_EMPTY\_OR\_MALFORMED

msg: Forced parameter XXX not sent, empty or incorrect format.

Reason: The parameter is null,  a required parameter is missing, or the input parameters are in an incorrect format.

### Code:-1103 UNKNOWN\_PARAM

msg: An unknown parameter was sent.

Reason: The parameter content or format in the request is incorrect. Please check if the fields contain any spaces.

### Code:-1104 UNREAD\_PARAMETERS

msg: Not all sent parameters were read.

Reason: Not all sent parameters were read; read '%s' parameter(s) but was sent '%s'.

### Code:-1105

msg: The parameter XXX is empty.

Reason: The required parameter is empty.

### Code:-1106 PARAM\_NOT\_REQUIRED

msg: This parameter is not required.

Reason: Parameter '%s' sent when not required.

### Code:-1111 BAD\_PRECISION

msg: Precision is over the maximum defined for this asset.

Reason: Precision is over the maximum defined for this asset.

### Code:-1112

msg: There are no pending orders for trading pairs.

Reason: The order that needs to be canceled does not exist.

### Code:-1116 INVALID\_ORDER\_TYPE

msg: Invalid order type.

Reason: Invalid order type.

### Code:-1117 INVALID\_SIDE

msg: Invalid buying or selling direction.

Reason: Invalid side.

### Code:-1121

msg: Invalid contract.

Reason: Invalid symbol.

### Code:-1136 ORDER\_QUANTITY\_TOO\_SMALL

msg: The order quantity is less than the minimum value.

Reason: Order quantity lower than the minimum.

### Code:-1138 ORDER\_PRICE\_WAVE\_EXCEED

msg: The order price is outside the allowable range.

Reason: Order price exceeds the permissible range.

### Code:-1139 ORDER\_NOT\_SUPPORT\_MARKET

msg: The pair does not support market trading.

Reason: This trading pair does not support market trading.

### Code:-1145

msg: The order status does not allow for cancellation.

Reason: The order cannot be canceled.

### Code:-1147 PRICE\_VOLUME\_PRESION\_ERROR

msg: The price or quantity precision exceeds the maximum limit.

Reason: Order price or quantity exceeds the maximum limit.

## 2XXX - Other Issues

### Code:-2013 NO\_SUCH\_ORDER

msg: The order does not exist.

Reason: The order does not exist.

### Code:-2015

msg: Invalid API key, IP, or operation permission.

Reason: Signature or IP is incorrect.

### Code:-2016

msg: Transactions are frozen.

Reason: The user's transaction is frozen.

### Code:-2017 balance\_not\_enough

msg: Insufficient balance.

Reason: Insufficient balance in the user's account.

### Code:-2100

msg: Parameter error.

Reason: Input wrong parameter or exist block in the parameter.

### Code:-2200

msg: Illegal IP.

Reason: Not a trusted IP.

### Code:35

msg: Forbidden to order.

Reason: User's transactions may be restricted.

# Enum Type

## Symbol Pair

*   `base`  asset refers to the asset that represents the quantity of a symbol.
*   `quote` asset refers to the asset that represents the price of a symbol.

## Order Statu

*   `New Order`
*   `Partially Filled`
*   `Filled`
*   `Canceled`
*   `To be Canceled`
*   `Partially Filled/Canceled`
*   `REJECTED`

## Order Type

*   `LIMIT`
*   `MARKET`

## Order Side

*   `BUY`
*   `SELL`

## Kline/Candlestick Interval

min -> minutes; h -> hours; day -> days; week -> weeks; month -> months

*   `1min`
*   `5min`
*   `15min`
*   `30min`
*   `60min`
*   `1h`
*   `4h`
*   `1day`
*   `1week`

# Spot Trading API

## Public

### Security: None

<aside class='notice'>Public section can be accessed freely without requiring any API-key or signatures.</aside>

### Test Connectivity

`GET https://openapi.xxx.com/sapi/v1/ping`

Test the connectivity of the REST API.

> request example

```http
GET https://openapi.xxx.com/sapi/v1/ping
```

### Check Server Time

`GET https://openapi.xxx.com/sapi/v1/time`

Check Server Time

> request example

```http
GET https://openapi.xxx.com/sapi/v1/time
```

> response example

```json
{
    "timezone": "GMT+08:00",
    "serverTime": 1595563624731
}
```

**Response Parameters**

| Parameter  | Type   | Example               | Description      |
| :----------| :------| :---------------------| :----------------|
| timezone   | string | `China Standard Time` | Server time zone |
| serverTime | long   | `1705039779880`       | Server timestamp |

### Symbol Pair List 

`GET https://openapi.xxx.com/sapi/v1/symbols`

The supported symbol pair collection which in the exchange.

> request example

```http
GET https://openapi.xxx.com/sapi/v1/symbols
```

> response example

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

**Response Parameters**

| Parameter         | Type       | Example   | Description                                |
| :-----------------| :----------| :---------| :------------------------------------------|
| symbol            | string     | `btcusdt` | `Lowercase` symbol name                    |
| baseAsset         | string     | `BTC`     | `Base` asset for the symbol                |
| quoteAsset        | string     | `USDT`    | `Quote` asset for the symbol               |
| pricePrecision    | integer    | `6`       | Price accuracy                             |
| quantityPrecision | integer    | `3`       | Quantity accuracy                          |
| limitVolumeMin    | BigDecimal | `0.0001`  | Minimum quantity limit for limit order     |
| marketBuyMin      | BigDecimal | `0.0001`  | Minimum purchase quantity for market order |
| marketSellMin     | BigDecimal | `0.0001`  | Minimum selling quantity for market orders |
| limitPriceMin     | BigDecimal | `0.001`   | Minimum price limit for limit orders       |

## Market

### Security: None

<aside class='notice'>Market section can be accessed freely without requiring any API-key or signatures.</aside>

### Depth

`GET https://openapi.xxx.com/sapi/v1/depth`

Market detpth data

> request example

```http
GET https://openapi.xxx.com/sapi/v1/depth?symbol=BTCUSDT&limit=100
```

**Request Parameters**

| Parameter                         | Type    | Description                            |
| :---------------------------------| :-------| :--------------------------------------|
| symbol<font color="red">\*</font> | string  | `Uppercase` symbol name E.g. `BTCUSDT` |
| limit<font color="red">\*</font>  | integer | default: 100; maximum: 100             |

> response example

```json
{
    "time": 1701658276000,
    "bids": [
        [
            3.90000000,     // price
            43.10000000    // volume
        ],
        [
            4.00000000,
            19.20000000
        ]
    ],
    "asks": [
        [
            4.00000200,     // price
            12.00000000     // volume
        ],
        [
            5.10000000,
            28.00000000
        ]
    ]
}
```

**Response Parameters**

| Paramter | Type  | Example                   | Description                                                                                                                                                                        |
| :--------| :-----| :-------------------------| :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| time     | long  | `1595563624731`           | Timestamp                                                                                                                                                                          |
| bids     | array | `[[3.9,43.1],[4.0,19.2]]` | Order book buying information, the array length is 2, subscript one is the price, type is float; subscript two is the quantity corresponding to the current price, type is float.  |
| asks     | array | `[[4.0,12.0],[5.1,28.0]]` | Order book selling information, the array length is 2, subscript one is the price, type is float; subscript two is the quantity corresponding to the current price, type is float. |

The bid and ask information represents all the prices in the order book along with the corresponding quantities, listed from the best price to the rest in descending order.

### 24hrs Ticker

`GET https://openapi.xxx.com/sapi/v1/ticker`

24-hour price change data

> request example

```http
GET https://openapi.xxx.com/sapi/v1/ticker?symbol=BTCUSDT
```

**Request Parameters**

| Parameter                         | Type   | Description                            |
| :---------------------------------| :------| :--------------------------------------|
| symbol<font color="red">\*</font> | string | `Uppercase` symbol name E.g. `BTCUSDT` |

> response example

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

**Response Parameters**

| Parameter | Type   | Example         | Description                                                                                      |
| :---------| :------| :---------------| :------------------------------------------------------------------------------------------------|
| time      | long   | `1595563624731` | Timestamp                                                                                        |
| high      | float  | `9900.51`       | Highest price                                                                                    |
| low       | float  | `9100.34`       | Lowest price                                                                                     |
| last      | float  | `9211.60`       | Latest trade price                                                                               |
| vol       | float  | `4691.0`        | Trading volume                                                                                   |
| amount    | float  | `22400.0`       | Trading amount                                                                                   |
| buy       | float  | `9210.0`        | Best bid price                                                                                   |
| sell      | float  | `9213.0`        | Best ask price                                                                                   |
| rose      | string | `+0.05`         | Range of increase and decrease, `+` is increase, `-` is decrease, `+0.05` means increase by `5%` |

### Recent Trade List

`GET https://openapi.xxx.com/sapi/v1/trades`

Market recent trade

> request example

```http
GET https://openapi.xxx.com/sapi/v1/trades?symbol=BTCUSDT&limit=100
```

**Request Parameters**

| Parameter                         | Type   | Description                            |
| :---------------------------------| :------| :--------------------------------------|
| symbol<font color="red">\*</font> | string | `Uppercase` symbol name E.g. `BTCUSDT` |
| limit<font color="red">\*</font>  | string | default: 100; maximum: 1000            |

> response example

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

**Response Parameters**

| Parameter | Type   | Example                | Description         |
| :---------| :------| :----------------------| :-------------------|
| price     | float  | `131.0000000000000000` | Trade price         |
| time      | long   | `1704788645416`        | Timestamp           |
| qty       | float  | `0.1000000000000000`   | The quantity traded |
| side      | string | `buy/sell`             | Taker side          |

### K-Line/Candlestick Data

`GET https://openapi.xxx.com/sapi/v1/klines`

K-Line/Candlestick data

> request example

```http
GET https://openapi.xxx.com/sapi/v1/klines?symbol=BTCUSDT&interval=1min&limit=100
```

**Request Parameters**

| Parameter                           | Type    | Description                                                                                                           |
| :-----------------------------------| :-------| :---------------------------------------------------------------------------------------------------------------------|
| symbol<font color="red">\*</font>   | string  | `Uppercase` symbol name E.g. `BTCUSDT`                                                                                |
| interval<font color="red">\*</font> | string  | Interval of the candlesticks. Possible values include:  `1min`,`5min`,`15min`,`30min`,`60min`,`1day`,`1week`,`1month` |
| limit                               | integer | default: 100; maximum: 300                                                                                            |

> response example

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

**Response Parameters**

| Parameter | Type  | Example         | Description     |
| :---------| :-----| :---------------| :---------------|
| idx       | long  | `1538728740000` | Start timestamp |
| open      | float | `6129.41`       | Open price      |
| close     | float | `6225.63`       | Close price     |
| high      | float | `6228.77`       | Highest price   |
| low       | float | `6220.13`       | Lowest price    |
| vol       | float | `2456.11`       | Trading volume  |

## Trade

### Security: TRADE

<aside class='notice'>The interface in Trade requires API-key and signature verification for access.</aside>

### Create New Order

`POST https://openapi.xxx.com/sapi/v1/order`

**Rate Limit: 100 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
POST https://openapi.xxx.com/sapi/v1/order

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

**Request Parameters**

| Parameter                         | Type   | Description                                                                                                        |
| :---------------------------------| :------| :------------------------------------------------------------------------------------------------------------------|
| symbol<font color="red">\*</font> | string | `Uppercase` symbol name E.g. `BTCUSDT`                                                                             |
| volume<font color="red">\*</font> | number | Order quantity, there is a precision limit, which is configured by the administrator.                              |
| side<font color="red">\*</font>   | string | Order side, `BUY/SELL`                                                                                             |
| type<font color="red">\*</font>   | string | Order type, `LIMIT/MARKET`                                                                                         |
| price                             | number | Order price, fo `LIMIT` orders must be sent, there is a precision limit, which is configured by the administrator. |
| newClientOrderId                  | string | Client order ID                                                                                                    |

> response example

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

**Response Parameters**

| Parameter     | Type    | Example               | Description                                                                                                      |
| :-------------| :-------| :---------------------| :----------------------------------------------------------------------------------------------------------------|
| orderId       | long    | `2012274607240433332` | Order ID(system generated)                                                                                       |
| clientOrderId | string  | `213443`              | Order ID(user generated)                                                                                         |
| symbol        | string  | `BTCUSDT`             | `Uppercase` symbol name                                                                                          |
| transactTime  | integer | `1704959985403`       | The time of order placed                                                                                         |
| price         | float   | `47651.29`            | Order price                                                                                                      |
| origQty       | float   | `0.01`                | Order volume                                                                                                     |
| executedQty   | float   | `0`                   | The number of orders already executed                                                                            |
| type          | string  | `LIMIT`               | Type of the order: `LIMIT/MARKET`                                                                                |
| side          | string  | `BUY`                 | Side of the order: `BUY/ SELL`                                                                                   |
| status        | string  | `NEW`                 | Order status: New Order (new order, no execution), Partially Filled (partial execution), Filled (fully executed) |

### Test New Order

`POST https://openapi.xxx.com/sapi/v1/order/test`

Create and validate a new order but do not send the order into the matching engine.

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
POST https://openapi.xxx.com/sapi/v1/order/test

body
{
    "symbol": "BTCUSDT",
    "volume": 1.00,
    "side": "BUY",
    "type": "LIMIT",
    "price": 65000.00,
    "newClientOrderId": "111000001111"
}
```
**Request Parameters**

| Parameter                         | Type   | Description                                                                                               |
| :---------------------------------| :------| :---------------------------------------------------------------------------------------------------------|
| symbol<font color="red">\*</font> | string | `Uppercase` symbol name E.g. `BTCUSDT`                                                                    |
| volume<font color="red">\*</font> | number | Order quantity, with precision limits, configured by the administrator                                    |
| side<font color="red">\*</font>   | string | Order side, `BUY/SELL`                                                                                    |
| type<font color="red">\*</font>   | string | Order type, `LIMIT/MARKET`                                                                                |
| price                             | number | Order price, for `LIMIT` orders must be sent, there is a precision limit, configured by the administrator |
| newClientOrderId                  | string | Client order ID                                                                                           |

> response example

```json
{}
```

### Batch Orders

`POST https://openapi.xxx.com/sapi/v1/batchOrders`

**Rate Limit: 50 times/2s Up to 10 orders in one batch order request**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
POST https://openapi.xxx.com/sapi/v1/batchOrders

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

**Request Parameters**

| Parameter | Type   | Example        | Description             |
| :---------| :------| :--------------| :-----------------------|
| symbol    | string | `ETHUSDT`      | `Uppercase` symbol name |
| price     | float  | `2100.00`      | Order price             |
| volume    | float  | `1.00`         | Order volume            |
| side      | string | `BUY/SELL`     | Order side              |
| batchType | string | `LIMIT/MARKET` | Order type              |

> response example

```json
{
    "ids": [
        165964665990709251,
        165964665990709252,
        165964665990709253
    ]
}
```

**Response Parameters**

| Parameter | Type  | Example | Description       |
| :---------| :-----| :-------| :-----------------|
| ids       | array |         | ids of Order List |


### Query Order

`GET https://openapi.xxx.com/sapi/v1/order`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
GET https://openapi.xxx.com/sapi/v1/order?symbol=ethusdt&orderID=111000111
```

**Request Parameters**

| Parameter                          | Type   | Description                            |
| :----------------------------------| :------| :--------------------------------------|
| orderId<font color="red">\*</font> | string | Order id                               |
| symbol<font color="red">\*</font>  | string | `Lowercase` symbol name E.g. `ethusdt` |

> response example

```json
{
    "symbol": "ethusdt",
    "side": "BUY",
    "executedQty": 0,
    "orderId": 150695552109032492,
    "price": 4765.29,
    "origQty": 1.01,
    "avgPrice": 4754.24,
    "transactTime": 1672274311107,
    "type": "LIMIT",
    "status": "New Order"
}
```

**Response Parameters**

| Parameter     | Type   | Example              | Description                                                                                                      |
| :-------------| :------| :--------------------| :----------------------------------------------------------------------------------------------------------------|
| orderId       | long   | `150695552109032492` | Order ID (system generated)                                                                                      |
| clientOrderId | string | `213443`             | Order ID (user generated)                                                                                        |
| symbol        | string | `ethusdt`            | `Lowercase` symbol name                                                                                          |
| price         | float  | `4765.29`            | Order price                                                                                                      |
| origQty       | float  | `1.01`               | Order volume                                                                                                     |
| executedQty   | float  | `0`                  | The number of orders already executed                                                                            |
| avgPrice      | float  | `4754.24`            | The average price of executed orders                                                                             |
| type          | string | `LIMIT`              | Order type:`LIMIT`/`MARKET`                                                                                      |
| transactTime  | long   | `1672274311107`      | Timestamp                                                                                                        |
| side          | string | `BUY`                | Order side: `BUY`/`SELL`                                                                                         |
| status        | string | `New Order`          | Order status: New Order (new order, no execution), Partially Filled (partial execution), Filled (fully executed) |

### Cancel Order

`POST https://openapi.xxx.com/sapi/v1/cancel`

**Rate Limit: 100 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
POST https://openapi.xxx.com/sapi/v1/cancel

body
{
    "symbol": "ethusdt",
    "orderId": "111000111"
}
```

**Request Parameters**

| Parameter                          | Type   | Description                            |
| :----------------------------------| :------| :--------------------------------------|
| orderId<font color="red">\*</font> | string | Order id                               |
| symbol<font color="red">\*</font>  | string | `Lowercase` symbol name E.g. `ethusdt` |

> response example

```json
{
    "symbol": "ethusdt",
    "orderId": [
        "1938321163093079425"
    ],
    "status": "PENDING_CANCEL"
}
```

**Response Parameters**

| Parameter | Type   | Example               | Description                     |
| :---------| :------| :---------------------| :-------------------------------|
| orderId   | long   | `1938321163093079425` | Order ID (system generated)     |
| symbol    | string | `ethusdt`             | `Lowercase` symbol name         |
| status    | string | `To be Cancelled`     | Order Status: `To be Cancelled` |

### Batch Order Cancellation

`POST https://openapi.xxx.com/sapi/v1/batchCancel`

**Rate Limit: 50 times/2s  Every batch cancellation request contains at most 10 orders**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
POST https://openapi.xxx.com/sapi/v1/batchCancel

body
{
    "symbol": "BTCUSDT",
    "oderIds": [111000111, 111000112]
}
```

**Request Parameters**

| Parameter                           | Type   | Description                                                                                                            |
| :-----------------------------------| :------| :----------------------------------------------------------------------------------------------------------------------|
| symbol<font color="red">\*</font>   | string | `Uppercase` symbol name E.g. `BTCUSDT`                                                                                 |
| orderIds<font color="red">\*</font> | array  | Collection of order IDs to be canceled. The order id must be of numeric type rather than String type. E.g. `[123,456]` |

>success response example

```json
{
    "success": [
        165964665990709251,
        165964665990709252,
        165964665990709253
    ],
    "failed": [ // Cancellation failure is usually because the order does not exist or the order status has reached the final state.
        165964665990709250
    ]
}
```

> failure response example

```json
{} //Usually it is because the order number is wrong and you need to check whether the content in orderIds is correct.
```

### Current Open Orders

`GET https://openapi.xxx.com/sapi/v1/openOrders`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameters**

| Parameter                         | Type    | Description                            |
| :---------------------------------| :-------| :--------------------------------------|
| symbol<font color="red">\*</font> | string  | `Lowercase` symbol name E.g. `ethusdt` |
| limit<font color="red">\*</font>  | integer | Maximum: 1000                          |

> response example

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

**Response Parameters**

| Parameter   | Type   | Example              | Description                                                                                                            |
| :-----------| :------| :--------------------| :----------------------------------------------------------------------------------------------------------------------|
| orderId     | long   | `150695552109032492` | Order ID (system generated)                                                                                            |
| symbol      | string | `ETHUSDT`            | `Uppercase` symbol name                                                                                                |
| price       | float  | `4765.29`            | Order price                                                                                                            |
| origQty     | float  | `1.01`               | Order volume                                                                                                           |
| executedQty | float  | `1.01`               | The number of orders already executed                                                                                  |
| avgPrice    | float  | `4754.24`            | The average price of executed orders                                                                                   |
| type        | string | `LIMIT`              | Order type:`LIMIT`/`MARKET`                                                                                            |
| time        | long   | `1701243281850`      | Timestamp                                                                                                              |
| side        | string | `BUY`                | Order side: `BUY`/`SELL`                                                                                               |
| status      | string | `New Order`          | Order status: `New Order` (new order, no execution), `Partially Filled` (partial execution), `Filled` (fully executed) |

### Trading Records

`GET https://openapi.xxx.com/sapi/v1/myTrades`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |


> request example

```http
GET https://openapi.xxx.com/sapi/v1/myTrades?symbol=BTCUSDT&limit=100
```

**Request Parameters**

| Parameter                         | Type   | Description                            |
| :---------------------------------| :------| :--------------------------------------|
| symbol<font color="red">\*</font> | string | `Uppercase` symbol name E.g. `BTCUSDT` |
| limit<font color="red">\*</font>  | string | default: 100; maximum: 1000            |

> response example

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

**Response Parameters**

| Parameter | Type    | Example               | Description                                                     |
| :---------| :-------| :---------------------| :---------------------------------------------------------------|
| symbol    | string  | `ETHBTC`              | `Uppercase` symbol name                                         |
| id        | integer | `159`                 | Trade ID                                                        |
| bidId     | long    | `1954603951049381893` | Buy side order ID                                               |
| askId     | long    | `1856176838352995447` | Sell side order ID                                              |
| price     | integer | `2334`                | Trade price                                                     |
| qty       | float   | `0.00004284`          | Trade volume                                                    |
| time      | number  | `1701165091964`       | Trade timestamp                                                 |
| isBuyer   | boolean | `true`                | `true`= Buyer, `false`= Seller                                  |
| isMaker   | boolean | `false`               | `true`= Maker, `false`= Taker                                   |
| feeCoin   | string  | `ETH`                 | Trade fee coin                                                  |
| fee       | number  | `0.00000000428`       | Trade fee                                                       |
| bidUserId | integer | `10083`               | Buy side user id                                                |
| askUserId | integer | `10671`               | Sell side user id                                               |
| isSelf    | boolean | `false`               | Self deal status `true` = is self deal, `false` = not self deal |
| side      | string  | `BUY`                 | Taker order side: `BUY`/`SELL`                                  |

## Account

### Security: USER\_DATA

<aside class="notice">The interface in Trade requires API-key and signature verification for access.</aside>

### Account Information

`GET https://openapi.xxx.com/sapi/v1/account`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> response example

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

**Response Parameters**

| Parameter | Type   | Description                       |
| :---------| :------| :---------------------------------|
| balances  | array  | The collection of account balance |
| asset     | string | Symbol                            |
| free      | string | Available balance                 |
| locked    | string | Frozen balance                    |

# Futures Trading API

## Public

### Security: None

<aside class="notice">Public section can be accessed freely without requiring any API-key or signatures.</aside>

### Test Connectivity

`GET https://futuresopenapi.xxx.com/fapi/v1/ping`

This interface checks connectivity to the host.

### Check Server Time

`GET https://futuresopenapi.xxx.com/fapi/v1/time`

> return example

```json
{
    "timezone": "China Standard Time",
    "serverTime": 1704962055664
}
```

**Request Parameter**

| Parameter  | Type   | Example               | Description      |
| :----------| :------| :---------------------| :----------------|
| timezone   | string | `China Standard Time` | Server time zone |
| serverTime | long   | `1607702400000`       | Server timestamp |

### Futures List

`GET https://futuresopenapi.xxx.com/fapi/v1/contracts`

> request example

```http
GET https://futuresopenapi.xxx.com/fapi/v1/contracts
```

> response example

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

**Response Parameter**

| Parameter       | Type   | Example                   | Description                                                                                   |
| :---------------| :------| :-------------------------| :---------------------------------------------------------------------------------------------|
| symbol          | string | `E-BTC-USDT`              | `Uppercase` Contract name                                                                     |
| pricePrecision  | number | `3`                       | Price accuracy                                                                                |
| status          | number | `1`                       | Contract status(0:`not tradable`, 1:`tradable`)                                               |
| type            | string | `E`                       | Contract type(E: `Perpetual contract`, S: `Simulated contract`, others are `mixed contracts`) |
| side            | number | `1`                       | Contract direction(0: `reverse`, 1: `forward`)                                                |
| multiplier      | number | `1.0000000000000000`      | Contract value                                                                                |
| minOrderVolume  | number | `1`                       | Minimum order quantity                                                                        |
| minOrderMoney   | number | `1.0000000000000000`      | Minimum order amount                                                                          |
| maxMarketVolume | number | `200000`                  | Maximum order quantity for market orders                                                      |
| maxMarketMoney  | number | `500000.0000000000000000` | Maximum order amount at market price                                                          |
| maxLimitVolume  | number | `300000`                  | Maximum order quantity for limit orders                                                       |
| maxLimitMoney   | number | `500000.0000000000000000` | Maximum order amount at limit price                                                           |
| maxValidOrder   | number | `10`                      | The maximum number of valid orders                                                            |

## Market

### Security: None

<aside class="notice">Market section can be accessed freely without requiring any API-key or signatures.</aside>

### Depth

`GET https://futuresopenapi.xxx.com/fapi/v1/depth`

Market detpth data

> request example

```http
GET https://futuresopenapi.xxx.com/fapi/v1/depth?contractName=E-BTC-USDT&limit=100
```

**Request Parameters**

| Parameter    | Type    | Description                                 |
| :------------| :-------| :-------------------------------------------|
| contractName | string  | `Uppercase` contract name E.g. `E-BTC-USDT` |
| limit        | integer | default: 100; maximum: 100                  |

> response example

```json
{
    "time": 1704962463000,
    "bids": [
        [
            3.90000000,     //price
            16.10000000     //volume
        ],
        [
            4.00000000,
            29.30000000
        ]
    ],
    "asks": [
        [
            4.00000200,     //price
            12.00000000     //volume
        ],
        [
            5.10000000,
            28.00000000
        ]
    ]
}
```

**Response Parameters**

| Parameter | Type | Example                          | Description                                                                                                                                                                       |
| :---------| :----| :--------------------------------| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| time      | long | `1595563624731`                  | Current time                                                                                                                                                                      |
| bids      | list | `[[3.9,16.1],[4.0,29.3]]`        | Order book buying information, the array length is 2, subscript one is the price, type is float; subscript two is the quantity corresponding to the current price, type is float  |
| asks      | list | `[[4.00000200,12.0],[5.1,28.0]]` | Order book selling information, the array length is 2, subscript one is the price, type is float; subscript two is the quantity corresponding to the current price, type is float |

The bid and ask information represents all the prices in the order book along with the corresponding quantities, listed from the best price to the rest in descending order.

### 24hrs Ticker

`GET https://futuresopenapi.xxx.com/fapi/v1/ticker`

24-hour price change data

> request example

```http
GET https://futuresopenapi.xxx.com/fapi/v1/ticker?contractName=E-BTC-USDT
```

**Request Parameters**

| Parameter                               | Type   | Description                                 |
| :---------------------------------------| :------| :-------------------------------------------|
| contractName<font color="red">\*</font> | string | `Uppercase` contract name E.g. `E-BTC-USDT` |


> response example

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

**Response Parameters**

| Parameter | Type   | Example         | Description                                                                                      |
| :---------| :------| :---------------| :------------------------------------------------------------------------------------------------|
| time      | long   | `1595563624731` | Timestamp                                                                                        |
| high      | float  | `56120.22`      | Highest price                                                                                    |
| low       | float  | `55982.24`      | Lowest price                                                                                     |
| last      | float  | `55989.93`      | Last price                                                                                       |
| vol       | float  | `51.21`         | Trade volume                                                                                     |
| rose      | string | `+0.05`         | Range of increase and decrease, `+` is increase, `-` is decrease, `+0.05` means increase by `5%` |
| buy       | float  | `55988.10`      | Best bid price                                                                                   |
| sell      | float  | `55990.10`      | Best ask price                                                                                   |

### Obtain Index/Mark Price

`GET` `https://futuresopenapi.xxx.com/fapi/v1/index`

> request example

```http
GET https://futuresopenapi.xxx.com/fapi/v1/index?contractName=E-BTC-USDT
```

**Request Parameters**

| Name                                    | Type   | Description                                 |
| :---------------------------------------| :------| :-------------------------------------------|
| contractName<font color="red">\*</font> | string | `Uppercase` contract name E.g. `E-BTC-USDT` |
| limit                                   | string | Default 100; maximum 1000                   |

> response example

```json
{
    "indexPrice": 27905.9800000000000000,
    "tagPrice": 27824.4422146875000000,
    "currentFundRate": -0.0037500000000000,
    "nextFundRate": -0.0037500000000000
}
```

**Response Parameters**

| Parameter       | Type  | Example                  | Description                                                                     |
| :---------------| :-----| :------------------------| :-------------------------------------------------------------------------------|
| indexPrice      | float | `27905.9800000000000000` | Index price                                                                     |
| tagPrice        | float | `27824.4422146875000000` | Mark price                                                                      |
| currentFundRate | float | `-0.0037500000000000`    | Funding rate price for the previous period (used for settlement in this period) |
| nextFundRate    | float | `-0.0037500000000000`    | Funding rate price                                                              |

### K-Line/Candlestick Data

`GET https://futuresopenapi.xxx.com/fapi/v1/klines`

> request example

```http
GET https://futuresopenapi.xxx.com/fapi/v1/klines?contractName=E-BTC-USDT&interval=1min&limit=100&startTime=1111111100000&endTime=222222222000000
```

**Request Parameter**

| Parameter                               | Type    | Description                                                                                                           |
| :---------------------------------------| :-------| :---------------------------------------------------------------------------------------------------------------------|
| contractName<font color="red">\*</font> | string  | `Uppercase` contract name E.g. `E-BTC-USDT`                                                                           |
| interval<font color="red">\*</font>     | string  | Interval of the candlesticks. Possible values include:  `1min`,`5min`,`15min`,`30min`,`60min`,`1day`,`1week`,`1month` |
| limit                                   | integer | default: 100; maximum: 300                                                                                            |
| startTime                               | long    | Timestamp                                                                                                             |
| endTime                                 | long    | Timestamp                                                                                                             |

> response example

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

**Response Parameter**

| Parameter | Type  | Example          | Description     |
| :---------| :-----| :----------------| :---------------|
| idx       | long  | `15946403400000` | Start timestamp |
| open      | float | `6195.80`        | Open price      |
| close     | float | `6210.51`        | Close price     |
| high      | float | `6228.77`        | Highest price   |
| low       | float | `6190.48`        | Lowest price    |
| vol       | float | `111`            | Trade volume    |

## Trade

### Security: TRADE

<aside class="notice">The interface in Trade requires API-key and signature verification for access.</aside>

### Create New Order

`POST https://futuresopenapi.xxx.com/fapi/v1/order`

Create a new single order.

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
POST https://futuresopenapi.xxx.com/fapi/v1/order

body
{
    "contractName": "E-BTC-USDT",
    "price": 65000.00,
    "volume": 1.00,
    "type": "LIMIT",
    "side": "BUY",
    "open": "OPEN",
    "positionType": 1,
    "clientOrderId": "111000111",
    "timeInForce": "IOC"
}
```

**Request Parameter**

| Parameter                               | Type   | Description                                                                                                                                                    |
| :---------------------------------------| :------| :--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| contractName<font color="red">\*</font> | string | `Uppercase` contract name E.g. `E-BTC-USDT`                                                                                                                    |
| price                                   | number | The number of orders placed has a precision limit. The precision is set by the administrator. When opening a position at market price, the unit here is value. |
| volume<font color="red">\*</font>       | number | Order price. This field is required for limit orders. There is a precision limit. The precision is set by the administrator.                                   |
| type<font color="red">\*</font>         | string | Order type : `LIMIT/MARKET`                                                                                                                                    |
| side<font color="red">\*</font>         | string | Order side: `BUY/SELL`                                                                                                                                         |
| open<font color="red">\*</font>         | string | Position side: `OPEN/CLOSE`                                                                                                                                    |
| positionType<font color="red">\*</font> | number | Position type: `1:Cross Margin/2:Isolated Margin`                                                                                                              |
| timeInForce                             | string | `IOC, FOK, POST_ONLY`                                                                                                                                          |
| clientOrderId                           | string | Client order ID, a string less than 32 characters in length                                                                                                    |

> response example

```json
{
    "orderId": 256609229205684228
}
```

**Response Parameter**

| Parameter | Type   | Example              | Description |
| :---------| :------| :--------------------| :-----------|
| orderId   | string | `256609229205684228` | Order ID    |

### Create Conditional Order

`POST https://futuresopenapi.xxx.com/fapi/v1/conditionOrder`

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

> request example

```http
POST https://futuresopenapi.xxx.com/fapi/v1/conditionOrder

body
{
    "contractName": "E-BTC-USDT"
}
```

**Request Parameter**

| Parameter     | Type   | Description                                                                                                                                                 |
| :-------------| :------| :-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| triggerType   | string | Type of conditions, 1: `stop loss`, 2: `take profit`, 3: `chase the rise`, 4: `kill the fall`                                                               |
| triggerPrice  | string | Trigger price                                                                                                                                               |
| clientOrderId | string | Client order identification, a string less than 32 characters in length                                                                                     |
| positionType  | number | Position type: 1. `Cross Margin`, 2. `Isolated Margin`                                                                                                      |
| open          | string | Position side: `OPEN/CLOSE`                                                                                                                                 |
| side          | string | Orde side: `BUY/SELL`                                                                                                                                       |
| type          | string | Order type: `LIMIT/MARKET`                                                                                                                                  |
| contractName  | string | `Uppercase` contract name E.g. `E-BTC-USDT`                                                                                                                 |
| price         | number | The order price has precision limits, and the precision is set by the administrator.                                                                        |
| volume        | number | The order quantity. When opening a position at market price, the unit here is value. There is a precision limit. The precision is set by the administrator. |

> response example

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

If this interface (/fapi/v1/conditionOrder) return does not meet expectations, please contact the technical team and we will provide you with relevant assistance.

### Cancel Order

`POST https://futuresopenapi.xxx.com/fapi/v1/cancel`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                               | Type   | Description                                 |
| :---------------------------------------| :------| :-------------------------------------------|
| contractName<font color="red">\*</font> | string | `Uppercase` contract name E.g. `E-BTC-USDT` |
| orderId<font color="red">\*</font>      | string | Order ID                                    |

> response example

```json
{
    "orderId": "256609229205684228"
}
```

### Cancel Trigger Order

`POST https://futuresopenapi.xxx.com/fapi/v1/cancel_trigger_order`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                               | Type   | Description                                 |
| :---------------------------------------| :------| :-------------------------------------------|
| contractName<font color="red">\*</font> | string | `Uppercase` contract name E.g. `E-BTC-USDT` |
| orderId<font color="red">\*</font>      | string | Order ID                                    |
| clientOrderId                           | string | Client unique identifier, default is 0      |

> response example

```json
{
    "orderId": "256609229205684228"
}
```

### Order Details

`GET https://futuresopenapi.xxx.com/fapi/v1/order`

**Request Parameter**

| Parameter                                | Type   | Description                                 |
| :----------------------------------------| :------| :-------------------------------------------|
| contractName<font color="red">\*</font>  | string | `Uppercase` contract name E.g. `E-BTC-USDT` |
| orderId<font color="red">\*</font>       | string | Order ID                                    |
| clientOrderId<font color="red">\*</font> | string | Client unique identifier, default is 0      |

> response example

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

**Response Parameter**

| Parameter    | Type    | Example                  | Description                                                                                                                                                                                 |
| :------------| :-------| :------------------------| :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| orderId      | long    | `2006628907041292645`    | Order ID (system generated)                                                                                                                                                                 |
| contractName | string  | `E-BTC-USDT`             | `Uppercase` contract name E.g. `E-BTC-USDT`                                                                                                                                                 |
| price        | float   | `67000.0000000000000000` | Order price                                                                                                                                                                                 |
| origQty      | float   | `2.0000000000000000`     | Order volume                                                                                                                                                                                |
| executedQty  | float   | `0`                      | Filled volume                                                                                                                                                                               |
| avgPrice     | float   | `0`                      | Average filled price                                                                                                                                                                        |
| status       | string  | `NEW`                    | Order status. Possible values are`NEW` (new order, no execution), `PARTIALLY_FILLED` (partial execution), `FILLED` (fully executed), `CANCELED` (canceled), and `REJECTED` (order rejected) |
| side         | string  | `BUY`                    | Order side: `BUY` (buy long) and `SELL` (sell short)                                                                                                                                        |
| action       | string  | `OPEN`                   | `OPEN/CLOSE`                                                                                                                                                                                |
| transactTime | long    | `1704967622000`          | Order creation time                                                                                                                                                                         |
| type         | string  | `LIMIT`                  | Order type: `LIMIT/MARKET`                                                                                                                                                                  |
| timeInForce  | integer | `1`                      | Effective method of conditional orders: 1: `limit`, 2: `market`, 3: `IOC`, 4: `FOK`, 5: `POST\_ONLY`                                                                                        |
| fills        | array   |                          | Transaction record                                                                                                                                                                          |

### Current Order Information

`GET https://futuresopenapi.xxx.com/fapi/v1/openOrders`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                               | Type   | Description                                 |
| :---------------------------------------| :------| :-------------------------------------------|
| contractName<font color="red">\*</font> | string | `Uppercase` contract name E.g. `E-BTC-USDT` |

> response example

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

Response Parameter

| Parameter       | Type   | Example                     | Description                                                                                                                                                   |
| :------------| :------| :------------------------| :------------------------------------------------------------------------------------------------------------------------------------------------------|
| orderId      | long   | `259396989397942275`     | Order ID(system generated)                                                                                                                                     |
| contractName | string | `E-BTC-USDT`             | `Uppercase` contract name E.g. `E-BTC-USDT`                                                                                                                                         |
| price        | float  | `72000.0000000000000000` | Order price                                                                                                                                               |
| origQty      | float  | `1.0000000000000000`     | Order volume                                                                                                                                               |
| executedQty  | float  | `0.5`                    | The number of orders already executed                                                                                                                                       |
| avgPrice     | float  | `71990.0`                | The average price of executed orders                                                                                                                                 |
| type         | string | `LIMIT`                  | Order type: `LIMIT` and `MARKET`                                                                                           |
| side         | string | `BUY`                    | Order side: `BUY` and `SELL`                                                                                  |
| status       | string | `NEW`                    | Order status. Possible values are`NEW` (new order, no execution), `PARTIALLY_FILLED` (partial execution), `FILLED` (fully executed), `CANCELED` (canceled), and `REJECTED` (order rejected) |
| action       | string | `OPEN`                   | `OPEN/CLOSE`                                                                                                                                           |
| transactTime | long   | `1607702400000`          | Order creation time                                                                                                                                         |

### Historical Order Records

`POST https://futuresopenapi.xxx.com/fapi/v1/orderHistorical`

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                               | Type   | Description                               |
| :---------------------------------------| :------| :-----------------------------------------|
| contractName<font color="red">\*</font> | string | Uppercase contract name E.g. `E-BTC-USDT` |
| limit                                   | string | default: 100; maximum: 100                |
| fromId                                  | long   | Start searching from this record          |

> response example

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

If this interface (/fapi/v1/orderHistorical) return does not meet expectations, please contact the technical team and we will provide you with relevant assistance.

### PnL Records

`POST https://futuresopenapi.xxx.com/fapi/v1/profitHistorical`

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                               | Type   | Description                               |
| :---------------------------------------| :------| :-----------------------------------------|
| contractName<font color="red">\*</font> | string | Uppercase contract name E.g. `E-BTC-USDT` |
| limit                                   | string | default: 100; maximum: 100                |
| fromId                                  | long   | Start searching from this record          |

> response example

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

If this interface (/fapi/v1/orderHistorical) return does not meet expectations, please contact the technical team and we will provide you with relevant assistance.

### Trading Record

`GET https://futuresopenapi.xxx.com/fapi/v1/myTrades`

**Rate Limit: 20 times/2s**

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                               | Type   | Description                                 |
| :---------------------------------------| :------| :-------------------------------------------|
| contractName<font color="red">\*</font> | string | `Uppercase` contract name E.g. `E-BTC-USDT` |
| limit                                   | string | default: 100; maximum: 100                  |
| fromId                                  | long   | Start retrieval from this tradeId           |

> response example

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

**Response Parameter**

| Parameter    | Type    | Example               | Description                                     |
| :------------| :-------| :---------------------| :-----------------------------------------------|
| tradeId      | number  | `1528`                | Trade ID                                        |
| bidId        | long    | `1874564572563538130` | Buy side order ID                               |
| askId        | long    | `1954072405852309104` | Sell side order ID                              |
| bidUserId    | integer | `10034`               | Buy side user ID                                |
| askUserId    | integer | `10378`               | Sell side user ID                               |
| price        | float   | `10.0`                | Filled price                                    |
| qty          | float   | `3`                   | Filled volume                                   |
| amount       | float   | `30.0`                | Filled amount                                   |
| time         | number  | `1499865549590`       | Trade timestamp                                 |
| fee          | number  | `0.001`               | Trade fee                                       |
| side         | string  | `BUY`                 | Order side:  `BUY/SELL`                         |
| contractName | string  | `E-BTC-USDT`          | `Uppercase` contract name E.g. `E-BTC-USDT`     |
| isMaker      | boolean | `true`                | Maker or Taker(true: `Maker`, false: `Taker`)   |
| isBuyer      | boolean | `true`                | Buyer or Seller(true: `buyer`, false: `seller`) |

### Change Position Mode

`POST https://futuresopenapi.xxx.com/fapi/v1/edit_user_position_model`

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                                | Type    | Description                                                   |
| :----------------------------------------| :-------| :-------------------------------------------------------------|
| contractName<font color="red">\*</font>  | string  | `Uppercase` contract name E.g. `E-BTC-USDT`                   |
| positionModel<font color="red">\*</font> | integer | The model of position(1: `Net position`, 2: `Hedge position`) |

> response example

```json
{
    "code": "0",
    "msg": "success",
    "data": null
}
```

### Change Margin Mode

`POST https://futuresopenapi.xxx.com/fapi/v1/edit_user_margin_model`

**Request Headers**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

**Request Parameter**

| Parameter                                | Type    | Description                                                   |
| :----------------------------------------| :-------| :-------------------------------------------------------------|
| contractName<font color="red">\*</font>  | string  | `Uppercase` contract name E.g. `E-BTC-USDT`                   |
| positionModel<font color="red">\*</font> | integer | The model of position(1: `Net position`, 2: `Hedge position`) |

> response example

```json
{ 
    "code": "0", 
    "msg": "success", 
    "data": null 
}
```

### Change Leverage

`POST` `https://futuresopenapi.xxx.com/fapi/v1/edit_lever`

**Request Header**

| Parameter                              | Type    | Description    |
| :--------------------------------------| :-------| :--------------|
| X-CH-SIGN<font color="red">\*</font>   | string  | Signature      |
| X-CH-APIKEY<font color="red">\*</font> | string  | User's API-key |
| X-CH-TS<font color="red">\*</font>     | integer | Timestamp      |

# Websocket

## Overview

Websocket is a new HTML5 Protocol. It achieves full-duplex data transmission between the client and the server, allowing data to be transferred effectively in both directions. With just only one handshake, the connection between the client and the server is established. The server will then be able to push data to the client according to preset rules. Its advantages include:

* The WebSocket request header for data transmission between client and server is approximately 2 bytes only.
* Either the client or server can initiate a data transmission.
* As there is no need to create and delete TCP connection repeatedly, it saves resources for both bandwidth and server.

<aside class="notice">We highly recommend that developers use the WebSocket API for retrieving market data and order book depth.</aside>

## Ws Information

* Basic spot market data site: <wss://ws.xxx.yyy/kline-api/ws>, Replace xxx.yyy with the exchange's main domain.
* Basic futures market data site: <wss://futuresws.xxx.yyy/kline-api/ws>, Replace xxx.yyy with the exchange's main domain.
* The returned data will be binary compressed except the heartbeat data (the user needs to decompress through Gzip algorithm).

### Heartbeat

To maintain a valid and stable connection, it is recommended to perform the following steps:

1. After receiving a message, the user sets a timer for N seconds, where N is less than 30.

2. If the timer is triggered (no new messages are received within N seconds), send the string 'ping'.

3. Expect a text string 'pong' as a response. If no response is received within N seconds, raise an error or reconnect.

> response example

```json
{
    "pong": 15359750
}
```

### Demo

[Websocket Demo](https://github.com/exchange2021/openapidemo/blob/master/src/main/java/com/ws/WsTest.java)



## Command Format

| event   | channel                       | description                                |
| :-------| :-----------------------------| :------------------------------------------|
| `sub`   | `market_$symbol_depth_step0`  | `Subscribe to depth`                       |
| `unsub` | `market_$symbol_depth_step0`  | `Unsubscribe from depth`                   |
| `sub`   | `market_$symbol_trade_ticker` | `Subscribe to real-time trade`             |
| `unsub` | `market_$symbol_trade_ticker` | `Unsubscribe from real-time trade`         |
| `sub`   | `market_$symbol_ticker`       | `Subscribe to 24h market data`             |
| `unsub` | `market_$symbol_ticker`       | `Unsubscribe from 24h market data`         |
| `sub`   | `market_$symbol_kline_1min`   | `Subscribe to 1min k-line information`     |
| `req`   | `market_$symbol_kline_1month` | `Request 1 month historical k-line record` |


## Subscription

### Subscribe Full Depth

> sub example

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_depth_step0", // $symbol E.g. Spot: btcusdt, Futures: e_btcusdt
        "cb_id": "1" // Business ID is not required
    }
}
```

> response example

```json
{
    "channel": "market_btcusdt_depth_step0",
    "ts": 1506584998239,
    "tick": {
        "asks": [ //asks
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
        "bids": [ //buys
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

### Subscribe to Real Time Trade

> sub example

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_trade_ticker", // $symbol E.g. Spot: btcusdt, Futures: e_btcusdt
        "cb_id": "1" // Business ID is not required
    }
}
```

> response example

```json
{
    "channel": "market_$symbol_trade_ticker",
    "ts": 1506584998239, // request time
    "tick": {
        "id": 12121, // maximum trade ID in the data
        "ts": 1506584998239, // maximum time in the data
        "data": [
            {
                "side": "buy", // trade side
                "price": 32.233, // price
                "vol": 232, // volume
                "amount": 323, // total amount
                "ds": "2017-09-1023: 12: 21"
            }
        ]
    }
}
```
### Subscribe to K-Line Market

> sub example

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_kline_[1min/5min/15min/30min/60min/1day/1week/1month]", // $symbol E.g. btcusdt
        "cb_id": "1" // Business ID is not required
    }
}
```

> response example

```json
{
    "channel": "market_$symbol_kline_1min", // 1min is for 1 minute
    "ts": 1506584998239, // request time
    "tick": {
        "id": 1506602880, // k-line start time
        "vol": 1212.12211, // trade volume
        "open": 2233.22, // open price
        "close": 1221.11, // close price
        "high": 22322.22, // high price
        "low": 2321.22 // low price
    }
}
```

### Subscribe to Market Tickers

> sub example

```json
{
    "event": "sub",
    "params": {
        "channel": "market_$symbol_ticker", // $symbol E.g. Spot: btcusdt, Futures: e_btcusdt
        "cb_id": "1" // Business ID is not required
    }
}
```

> response example

```json
{
    "channel": "market_$symbol_ticker",
    "ts": 1506584998239, // request time
    "tick": {
        "amount": 123.1221, // trade amount
        "vol": 1212.12211, // trade volume
        "open": 2233.22, // open price
        "close": 1221.11, // close price
        "high": 22322.22, // high price
        "low": 2321.22, // low price
        "rose": -0.2922, // increase
    }
}
```

### Request K-Line History Data

> sub example

```json
{
    "event": "req",
    "params": {
        "channel": "market_$symbol_kline_[1min/5min/15min/30min/60min/1day/1week/1month]",
        "cb_id": "1",
        "endIdx": "1506602880", // Return pageSize data before endIdx Not required
        "pageSize": 100 // Not required
    }
}
```

> response example

```json
{
    "event_rep": "rep",
    "channel": "market_$symbol_kline_5min",
    "cb_id": "return along the same path",
    "ts": 1506584998239, // request time
    "data": [ // up to 300 pieces
        {
            "id": 1506602880, // k-line start time
            "amount": 123.1221, // trade amount
            "vol": 1212.12211, // trade volume
            "open": 2233.22, // open price
            "close": 1221.11, // close price
            "high": 22322.22, // high price
            "low": 2321.22 // low price
        },
        {
            "id": 1506602880, // k-line start time
            "amount": 123.1221, // trade amount
            "vol": 1212.12211, // trade volume
            "open": 2233.22, // open price
            "close": 1221.11, // close price
            "high": 22322.22, // high price
            "low": 2321.22 // low price
        }
    ]
}
```

### Request History Trade

> sub example

```json
{
    "event": "req",
    "params": {
        "channel": "market_$symbol_trade_ticker", // $symbol E.g. Spot: btcusdt, Futures: e_btcusdt
        "cb_id": "1" // Business ID is not required
    }
}
```

> response example

```json
{
    "event_rep": "rep",
    "channel": "market_$symbol_trade_ticker",
    "cb_id": "return along the same path",
    "ts": 1506584998239,
    "status": "ok",
    "data": [
        {
            "side": "buy", // trade side, buy or sell
            "price": 32.233, // price
            "vol": 232, // volume
            "amount": 323 // total amount
        },
        {
            "side": "buy", // trade side, buy or sell
            "price": 32.233, // price
            "vol": 232, // volume
            "amount": 323 // total amount
        }
    ]
}
```

# Official SDK

## Example of signature

### Java

```java
/**
 * Generate sign
 **/
private String toSign(String timestamp, String method, String requestPath,
                             String queryString, String body, String secretKey) throws Exception {
    // signature string
    String preHash = preHash(timestamp, method, requestPath, queryString, body);
    byte[] secretKeyBytes = secretKey.getBytes("UTF-8");
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, "HmacSHA256");
    Mac mac = (Mac) MAC.clone();
    mac.init(secretKeySpec);
    return Hex.encodeHexString(mac.doFinal(preHash.getBytes("UTF-8")));
}

/**
 * signature string
 **/
private String preHash(String timestamp, String method, String requestPath, String queryString, String body) {
                                 
    StringBuilder preHash = new StringBuilder();
    preHash.append(timestamp);
    preHash.append(method.toUpperCase());
    preHash.append(requestPath);
    if (org.apache.commons.lang3.StringUtils.isNotEmpty(queryString)) {
        preHash.append("?").append(queryString);
    }
    if (org.apache.commons.lang3.StringUtils.isNotEmpty(body)) {
        preHash.append(body);
    }
    return preHash.toString();
}

/**
 * queryString
 **/
private String queryString(ServerHttpRequest request) {
    String url = request.getURI().toString();
    String queryString = "";
    if (url.contains("?")) {
        queryString = url.substring(url.lastIndexOf("?") + 1);
    }
    return queryString;
}

```

## Example of create order

### Java

```java
OkHttpClient client = new OkHttpClient().newBuilder()
.build();
MediaType mediaType = MediaType.parse("application/json");
RequestBody body = RequestBody.create(mediaType, "{\"symbol\":\"BTCUSDT\",\"volume\":1,\"side\":\"BUY\",\"type\":\"LIMIT\",\"price\":10000,\"newClientOrderId\":\"\",\"recvWindow\":5000}");
Request request = new Request.Builder()
.url("https://openapi.xxx.com")
.method("POST", body)
.addHeader("X-CH-APIKEY", "Your API key")
.addHeader("X-CH-TS", "1596543296058")
.addHeader("Content-Type", "application/json")
.addHeader("X-CH-SIGN", "encrypt sign")
.build();
Response response = client.newCall(request).execute();
```

### Go

```go
package main
import (
"fmt"
"strings"
"net/http"
"io/ioutil"
)
func main() {
  url := "https://openapi.xxx.com"
  method := "POST"
  payload := strings.NewReader("{\"symbol\":\"BTCUSDT\",\"volume\":1,\"side\":\"BUY\",\"type\":\"LIMIT\",\"price\":10000,\"newClientOrderId\":\"\",\"recvWindow\":5000}")
  client := &http.Client {
}
  req, err := http.NewRequest(method, url, payload)
if err != nil {
    fmt.Println(err)
}
  req.Header.Add("X-CH-APIKEY", "Your API key")
  req.Header.Add("X-CH-TS", "1596543881257")
  req.Header.Add("Content-Type", "application/json")
  req.Header.Add("X-CH-SIGN", "encrypt sign")
  res, err := client.Do(req)
  defer res.Body.Close()
  body, err := ioutil.ReadAll(res.Body)
  fmt.Println(string(body))
}
```

### Python

```python
import requests
url = "https://openapi.xxx.com"
payload = "{\"symbol\":\"BTCUSDT\",\"volume\":1,\"side\":\"BUY\",\"type\":\"LIMIT\",\"price\":10000,\"newClientOrderId\":\"\",\"recvWindow\":5000}"
headers = {
'X-CH-APIKEY': 'Your API key',
'X-CH-TS': '1596543881257',
'Content-Type': 'application/json',
'X-CH-SIGN': 'encrypt sign'
}
response = requests.request("POST", url, headers=headers, data = payload)
print(response.text.encode('utf8'))
```

### PHP

```php
<?php
require_once 'HTTP/Request2.php';
$request = new HTTP_Request2();
$request->setUrl('https://openapi.xxx.com');
$request->setMethod(HTTP_Request2::METHOD_POST);
$request->setConfig(array(
'follow_redirects' => TRUE
));
$request->setHeader(array(
'X-CH-APIKEY' => 'Your API key',
'X-CH-TS' => '1596543881257',
'Content-Type' => 'application/json',
'X-CH-SIGN' => 'encrypt sign'
));
$request->setBody('{"symbol":"BTCUSDT","volume":1,"side":"BUY","type":"LIMIT","price":10000,"newClientOrderId":"","recvWindow":5000}');
try {
  $response = $request->send();
if ($response->getStatus() == 200) {
    echo $response->getBody();
}
else {
    echo 'Unexpected HTTP status: ' . $response->getStatus() . ' ' .
    $response->getReasonPhrase();
}
}
catch(HTTP_Request2_Exception $e) {
  echo 'Error: ' . $e->getMessage();
}
```

### Node.js

```javascript--node
var request = require('request');
var options = {
'method': 'POST',
'url': 'https://openapi.xxx.com',
'headers': {
'X-CH-APIKEY': 'Your API key',
'X-CH-TS': '1596543881257',
'Content-Type': 'application/json',
'X-CH-SIGN': 'encrypt sign'
},
  body: JSON.stringify({"symbol":"BTCUSDT","volume":1,"side":"BUY","type":"LIMIT","price":10000,"newClientOrderId":"","recvWindow":5000})
};
request(options, function (error, response) {
if (error) throw new Error(error);
  console.log(response.body);
});
```

# FAQ

## What is the maximum difference between the timestamp parameter of the request interface and the arrival time of the server?

When the server receives the request, it will judge the timestamp in the request. If it is sent before 5000 milliseconds, the request will be considered invalid. This time window value can be customized by sending the optional parameter `recvWindow`.

## The request header "X-CH-TS" cannot be empty. How to solve it?

First, it is recommended to print out the `X-CH-TS`, and check whether the `X-CH-TS` is empty when there is an exception, and it is recommended to optimize your code and judge whether the `X-CH-TS` is empty before each request.

## Why does authentication always return invalid signatures?

You can print out the request header information and the string before the signature, with the following points:

* Compare your request header with the following request header example one by one.

```json
Content-Type: application/json
X-CH-APIKEY: 44c541a1-****-****-****-10fe390df2
X-CH-SIGN: ssseLeefrffraoEQ3yI9qEtI1CZ82ikZ4xSG5Kj8gnl3uw=
X-CH-TS: 1574327555669
```

* Confirm whether the API-key is configured correctly in the program.
* Ensure the string before signing follows the standard format, with all elements in the correct order. You can use the example below to compare with your string before signing:

> GET example

```http
1588591856950GET/sapi/v1/account
```

> POST example

```http
1588591856950POST/sapi/v1/order/test{"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"}
```

## The calling interface prompts** ILLEGAL_CONTENT_TYPE (-1017). What is the reason?

We recommend attaching Content-Type to all request headers and setting it to application/json.

## Is there a limit to the frequency of API calls per second?

There are restrictions. For details, see the access frequency restrictions for each interface in the document.

## What is the limit on API access frequency？

Personal data is restricted according to **API-key**, and public data is restricted according to **ip**. It should be noted that if the user requests public data and passes in valid personal information, it is restricted according to **API-key**.

## What is the cause of HTTP status code 429?

The request interface exceeds the access frequency limit. It is recommended to reduce the access frequency.

## Will the IP be blocked if the API call interface reports that the access frequency is exceeded? How long is it blocked?

Normally not. If it is blocked, please reduce the frequency of access.

## Why is WebSocker disconnected?

* Without adding a heartbeat, the WebSocket connection requires the client to return to pong to ensure the stability of the connection.
* The pong message sent by the client is caused by network reasons, but the server does not receive it, or other network reasons may also cause automatic disconnection.
* It is recommended that you have a robust WebSocket disconnect and reconnect mechanism to ensure automatic reconnection if the heartbeat (ping/pong) connection is unexpectedly lost.

## Why does the user request interface report an error Time Out?

The network cannot connect to the server. It is recommended that you check whether the network is smooth.

## How to get all the currency pairs on the platform?

You obtain them via coin's `/sapi/v1/symbols` interface.

## Is there a limit on the number of batch orders/cancellations?

Yes, the batch interface will limit 10 orders.

## What is newClientOrderId and what does it do?

* newClientOrderId is your customized order number, which can be used to identify your order. After the order is placed, you can make newClientOrderId call the "Order Information" interface to view the order status.
* You need to ensure that this ID is not repeated, and we will not prompt for re-relocation. If there is a repetition, you can only cancel or query the latest piece of data when canceling and querying the order.

## How to get the latest transaction price?

You can get ticker information, last is the latest transaction price.

## Will there be a negative growth in the 24-hour trading volume in the ticker interface?

Yes, it is possible. Since the 24-hour trading volume is based on a rolling 24-hour window ( (the size of the translation window is 24 hours), the accumulated volume in the next window may be smaller than the previous one, resulting in negative growth.