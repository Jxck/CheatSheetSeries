# Session Management Cheat Sheet

## Introduction

**Web Authentication, Session Management, and Access Control**:

A web session is a sequence of network HTTP request and response transactions associated with the same user. Modern and complex web applications require the retaining of information or status about each user for the duration of multiple requests. Therefore, sessions provide the ability to establish variables - such as access rights and localization settings - which will apply to each and every interaction a user has with the web application for the duration of the session.

ウェブ Session は、同じユーザーに関連するネットワーク HTTP リクエストとレスポンスのトランザクションのシーケンスです。最近の複雑なウェブアプリケーションでは、複数のリクエストの間、各ユーザーの情報やステータスを保持することが必要です。したがって、 Session は、アクセス権やローカライゼーション設定などの変数を設定する機能を提供し、 Session の期間中、ユーザーがウェブアプリケーションと行うすべての対話に適用されます。

Web applications can create sessions to keep track of anonymous users after the very first user request. An example would be maintaining the user language preference. Additionally, web applications will make use of sessions once the user has authenticated. This ensures the ability to identify the user on any subsequent requests as well as being able to apply security access controls, authorized access to the user private data, and to increase the usability of the application. Therefore, current web applications can provide session capabilities both pre and post authentication.

Web アプリケーションは、最初のユーザーリクエストの後、匿名ユーザーを追跡するために Session を作成することができます。例えば、ユーザーの言語設定を維持するような場合です。さらに、ウェブアプリケーションは、ユーザーが認証されると、 Session を使用します。これにより、その後のリクエストでユーザーを特定できるようになり、セキュリティアクセス制御、ユーザーのプライベートデータへのアクセス許可、アプリケーションの使いやすさを向上させることができます。したがって、現在のウェブアプリケーションは、認証前と認証後の両方で Session 機能を提供することができます。

Once an authenticated session has been established, the session ID (or token) is temporarily equivalent to the strongest authentication method used by the application, such as username and password, passphrases, one-time passwords (OTP), client-based digital certificates, smartcards, or biometrics (such as fingerprint or eye retina). See the OWASP [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md).

認証された Session が確立されると、 Session ID(またはトークン)は、ユーザー名とパスワード、パスフレーズ、ワンタイムパスワード(OTP)、クライアントベースのデジタル証明書、スマートカード、バイオメトリクス(指紋や目の網膜など)など、アプリケーションが使用する最強の認証方法と一時的に同等となります。 OWASP [Authentication Cheat Sheet](Authentication_Cheat_Sheet.md) をご参照ください。

HTTP is a stateless protocol ([RFC2616](https://www.ietf.org/rfc/rfc2616.txt) section 5), where each request and response pair is independent of other web interactions. Therefore, in order to introduce the concept of a session, it is required to implement session management capabilities that link both the authentication and access control (or authorization) modules commonly available in web applications:

HTTP はステートレスプロトコル([RFC2616](https://www.ietf.org/rfc/rfc2616.txt) section 5)であり、各リクエストとレスポンスのペアは他のウェブインタラクションから独立している。したがって、 Session の概念を導入するためには、ウェブアプリケーションで一般的に利用できる認証モジュールとアクセス制御(または認可)モジュールの両方を連携させた Session 管理機能を実装する必要がある:

![SessionDiagram](../assets/Session_Management_Cheat_Sheet_Diagram.png)

The session ID or token binds the user authentication credentials (in the form of a user session) to the user HTTP traffic and the appropriate access controls enforced by the web application. The complexity of these three components (authentication, session management, and access control) in modern web applications, plus the fact that its implementation and binding resides on the web developer's hands (as web development frameworks do not provide strict relationships between these modules), makes the implementation of a secure session management module very challenging.

Session ID やトークンは、ユーザー認証の資格情報(ユーザー Session の形)を、ユーザーの HTTP トラフィックと、ウェブアプリケーションが実施する適切なアクセス制御と結びつける。最近のウェブアプリケーションでは、これら 3 つのコンポーネント(認証、 Session 管理、アクセス制御)が複雑であり、さらにその実装と結合がウェブ開発者の手中にあるという事実(ウェブ開発フレームワークがこれらのモジュール間の厳格な関係を提供しないため)により、安全な Session 管理モジュールの実装は非常に困難です。

The disclosure, capture, prediction, brute force, or fixation of the session ID will lead to session hijacking (or sidejacking) attacks, where an attacker is able to fully impersonate a victim user in the web application. Attackers can perform two types of session hijacking attacks, targeted or generic. In a targeted attack, the attacker's goal is to impersonate a specific (or privileged) web application victim user. For generic attacks, the attacker's goal is to impersonate (or get access as) any valid or legitimate user in the web application.

Session ID の disclosure(盗聴)、 capture(奪取)、 prediction(予測)、 brute force(総当たり)、 fixation(固定)は、攻撃者がウェブアプリケーションで被害者ユーザーに完全になりすますことができる Session Hijacking(または Sidejacking)攻撃につながる。攻撃者は、標的型攻撃と汎用型攻撃の 2 種類の Session Hijacking 攻撃を行うことができます。標的型攻撃では、攻撃者の目標は、特定の(または特権を持つ)Web アプリケーションの被害者ユーザーになりすますことです。一般的な攻撃では、攻撃者の目標は、 Web アプリケーションの有効な、または正当なユーザーになりすます(または、そのユーザーとしてアクセスする)ことです。


## Session ID Properties

In order to keep the authenticated state and track the users progress within the web application, applications provide users with a **session identifier** (session ID or token) that is assigned at session creation time, and is shared and exchanged by the user and the web application for the duration of the session (it is sent on every HTTP request). The session ID is a `name=value` pair.

認証された状態を維持し、ウェブアプリケーション内でユーザーの進捗状況を追跡するために、アプリケーションはユーザーに**Session 識別子**(Session ID またはトークン)を提供します。 Session ID は Session 作成時に割り当てられ、ユーザーとウェブアプリケーションが Session の期間中共有し交換します(すべての HTTP リクエストで送信される)。 Session ID は、`name=value`のペアである。

With the goal of implementing secure session IDs, the generation of identifiers (IDs or tokens) must meet the following properties.

セキュアな Session ID の実装を目標に、識別子(ID またはトークン)の生成は、以下の特性を満たす必要がある。


### Session ID Name Fingerprinting

The name used by the session ID should not be extremely descriptive nor offer unnecessary details about the purpose and meaning of the ID.

Session ID が使用する名前は、極端に説明的であったり、 ID の目的や意味について不必要な詳細を提供するものであってはなりません。

The session ID names used by the most common web application development frameworks [can be easily fingerprinted](https://wiki.owasp.org/index.php/Category:OWASP_Cookies_Database), such as `PHPSESSID` (PHP), `JSESSIONID` (J2EE), `CFID` & `CFTOKEN` (ColdFusion), `ASP.NET_SessionId` (ASP .NET), etc. Therefore, the session ID name can disclose the technologies and programming languages used by the web application.

最も一般的な Web アプリケーション開発フレームワークで使用される Session ID 名は、[簡単に指紋を取ることができる](https://wiki.owasp.org/index.php/Category:OWASP_Cookies_Database)。例えば、`PHPSESSID`(PHP)、`JSESSIONID`(J2EE)、`CFID` & `CFTOKEN` (ColdFusion), `ASP.NET_SessionId` (ASP .NET) などの名前が挙げられる。したがって、 Session ID 名は、 Web アプリケーションで使用されている技術やプログラミング言語を開示することができます。

It is recommended to change the default session ID name of the web development framework to a generic name, such as `id`.

Web 開発フレームワークのデフォルトの Session ID 名を、`id`などの一般的な名前に変更することをお勧めします。


### Session ID Length

The session ID must be long enough to prevent brute force attacks, where an attacker can go through the whole range of ID values and verify the existence of valid sessions.

Session ID は、攻撃者が ID 値の全範囲を調べて有効な Session の存在を確認するブルートフォースアタックを防ぐために十分な長さでなければなりません。

The session ID length must be at least `128 bits (16 bytes)`.

Session ID の長さは最低でも`128 ビット(16 バイト)`でなければなりません。

**NOTE**:

- The session ID length of 128 bits is provided as a reference based on the assumptions made on the next section _Session ID Entropy_. However, this number should not be considered as an absolute minimum value, as other implementation factors might influence its strength.
- For example, there are well-known implementations, such as [Microsoft ASP.NET session IDs](https://docs.microsoft.com/en-us/dotnet/api/system.web.sessionstate.sessionidmanager?redirectedfrom=MSDN&view=netframework-4.7.2): "_The ASP .NET session identifier is a randomly generated number encoded into a 24-character string consisting of lowercase characters from a to z and numbers from 0 to 5_".
- It can provide a very good effective entropy, and as a result, can be considered long enough to avoid guessing or brute force attacks.

- Session ID の長さ 128 ビットは、次のセクション_Session ID エントロピー_ の仮定に基づく参考として提供される。しかし、この数値は絶対的な最小値として考慮されるべきではなく、他の実装要因がその強さに影響を与えるかもしれないからです。
- 例えば、[Microsoft ASP.NET session ID](https://docs.microsoft.com/en-us/dotnet/api/system.web.sessionstate.sessionidmanager?redirectedfrom=MSDN&view=netframework-4.7.2) のようなよく知られた実装がある: "_The ASP .NET の session identifier は a から z の小文字と 0 から 5 までの数字からなる 24 文字の文字列にエンコードされたランダムに生成された数字です_"。
- これは非常に優れた実効エントロピーを提供でき、その結果、推測やブルートフォース攻撃を避けるのに十分な長さと考えることができる。


### Session ID Entropy

The session ID must be unpredictable (random enough) to prevent guessing attacks, where an attacker is able to guess or predict the ID of a valid session through statistical analysis techniques. For this purpose, a good [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) (Cryptographically Secure Pseudorandom Number Generator) must be used.

Session ID は、攻撃者が統計的分析技術によって有効な Session の ID を推測または予測することができる推測攻撃を防ぐために、予測不可能(十分にランダム)でなければなりません。この目的のためには、優れた[CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator)(Cryptographically Secure Pseudorandom Number Generator)を使用する必要があります。

The session ID value must provide at least `64 bits` of entropy (if a good [PRNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) is used, this value is estimated to be half the length of the session ID).

Session ID の値は、少なくとも 64 ビットのエントロピーを提供しなければならない(優れた[PRNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)が使用される場合、この値は Session ID の長さの半分になると推定される)。

Additionally, a random session ID is not enough; it must also be unique to avoid duplicated IDs. A random session ID must not already exist in the current session ID space.

さらに、ランダムな Session ID だけでは不十分で、 ID の重複を避けるためにユニークである必要があります。ランダムな Session ID は、現在の Session ID スペースに既に存在してはならない。

**NOTE**:

- The session ID entropy is really affected by other external and difficult to measure factors, such as the number of concurrent active sessions the web application commonly has, the absolute session expiration timeout, the amount of session ID guesses per second the attacker can make and the target web application can support, etc.
- If a session ID with an entropy of `64 bits` is used, it will take an attacker at least 292 years to successfully guess a valid session ID, assuming the attacker can try 10,000 guesses per second with 100,000 valid simultaneous sessions available in the web application.
- More information [here](https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length).

- Session ID のエントロピーは、ウェブアプリケーションが一般的に持つ同時アクティブ Session 数、絶対的な Session 有効期限タイムアウト、攻撃者が行える毎秒の Session ID 推測量とターゲットウェブアプリケーションがサポートできる量など、他の外部要因と測定困難な要因に実際に影響される。
- エントロピーの値が 64 ビットの Session ID を使用した場合、攻撃者が 1 秒間に 10,000 回の Session ID の推測を行い、ウェブアプリケーションで 10 万回の有効な同時 Session を利用できると仮定すると、攻撃者が有効な Session ID の推測に成功するまで少なくとも 292 年かかる。
- 詳細は[こちら](https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length)。


### Session ID Content (or Value)

The session ID content (or value) must be meaningless to prevent information disclosure attacks, where an attacker is able to decode the contents of the ID and extract details of the user, the session, or the inner workings of the web application.

攻撃者が ID の内容を解読して、ユーザーや Session 、 Web アプリケーションの内部構造を引き出す情報漏洩攻撃を防ぐため、 Session ID の内容(または値)は無意味でなければなりません。

The session ID must simply be an identifier on the client side, and its value must never include sensitive information (or [PII](https://en.wikipedia.org/wiki/Personally_identifiable_information)).

Session ID は、単にクライアント側の識別子でなければならず、その値に機密情報(または[PII](https://en.wikipedia.org/wiki/Personally_identifiable_information))が含まれてはならない。

The meaning and business or application logic associated with the session ID must be stored on the server side, and specifically, in session objects or in a session management database or repository.

Session ID に関連する意味とビジネスまたはアプリケーションロジックは、サーバー側、具体的には Session オブジェクトまたは Session 管理データベースまたはリポジトリに格納されなければならない。

The stored information can include the client IP address, User-Agent, e-mail, username, user ID, role, privilege level, access rights, language preferences, account ID, current state, last login, session timeouts, and other internal session details. If the session objects and properties contain sensitive information, such as credit card numbers, it is required to duly encrypt and protect the session management repository.

保存される情報には、クライアントの IP アドレス、 User-Agent 、電子メール、ユーザー名、ユーザー ID 、役割、特権レベル、アクセス権、言語設定、アカウント ID 、現在の状態、最終ログイン、 Session タイムアウト、その他の内部 Session 詳細が含まれることがあります。 Session オブジェクトやプロパティにクレジットカード番号などの機密情報が含まれている場合は、 Session 管理リポジトリを正規に暗号化して保護する必要があります。

It is recommended to use the session ID created by your language or framework. If you need to create your own sessionID, use a cryptographically secure pseudorandom number generator (CSPRNG) with a size of at least 128 bits and ensure that each sessionID is unique.

言語やフレームワークによって作成された Session ID を使用することをお勧めします。独自の Session ID を作成する必要がある場合は、 128 ビット以上の暗号化された疑似乱数生成器(CSPRNG)を使用し、各 Session ID がユニークであることを確認してください。


## Session Management Implementation

The session management implementation defines the exchange mechanism that will be used between the user and the web application to share and continuously exchange the session ID. There are multiple mechanisms available in HTTP to maintain session state within web applications, such as cookies (standard HTTP header), URL parameters (URL rewriting - [RFC2396](https://www.ietf.org/rfc/rfc2396.txt)), URL arguments on GET requests, body arguments on POST requests, such as hidden form fields (HTML forms), or proprietary HTTP headers.

Session 管理の実装では、ユーザーとウェブアプリケーションの間で Session ID を共有し、継続的に交換するための交換機構を定義します。 Web アプリケーション内で Session 状態を維持するために HTTP で利用できる仕組みは、 Cookie(標準 HTTP ヘッダー)、 URL パラメータ(URL 書き換え - [RFC2396](https://www.ietf.org/rfc/rfc2396.txt) )、 GET リクエストの URL 引数、隠しフォームフィールド(HTML フォーム)などの POST リクエストのボディ引数、または独自の HTTP ヘッダーなど複数存在します。

The preferred session ID exchange mechanism should allow defining advanced token properties, such as the token expiration date and time, or granular usage constraints. This is one of the reasons why cookies (RFCs [2109](https://www.ietf.org/rfc/rfc2109.txt) & [2965](https://www.ietf.org/rfc/rfc2965.txt) & [6265](https://www.ietf.org/rfc/rfc6265.txt)) are one of the most extensively used session ID exchange mechanisms, offering advanced capabilities not available in other methods.

望ましい Session ID 交換機構は、トークンの有効期限や時間などの高度なトークン特性や、きめ細かい使用制約を定義できるようにすべきです。これは、 Cookie(RFC [2109](https://www.ietf.org/rfc/rfc2109.txt) & [2965](https://www.ietf.org/rfc/rfc2965.txt) & [6265](https://www.ietf.org/rfc/rfc6265.txt) )が、他の方法では利用できない高度な機能を提供し、最も広範囲に使用されている Session ID 交換メカニズムの一つである理由の一つです。

The usage of specific session ID exchange mechanisms, such as those where the ID is included in the URL, might disclose the session ID (in web links and logs, web browser history and bookmarks, the Referer header or search engines), as well as facilitate other attacks, such as the manipulation of the ID or [session fixation attacks](http://www.acrossecurity.com/papers/session_fixation.pdf).

URL に ID が含まれるような特定の Session ID 交換の仕組みを利用すると、 Session ID が(Web リンクやログ、 Web ブラウザの履歴やブックマーク、 Referer ヘッダや検索エンジンで)開示されたり、 ID の操作や [Session Fixation Attacks](http://www.acrossecurity.com/papers/session_fixation.pdf)などの攻撃を容易にする恐れがあります。


### Built-in Session Management Implementations

Web development frameworks, such as J2EE, ASP .NET, PHP, and others, provide their own session management features and associated implementation. It is recommended to use these built-in frameworks versus building a home made one from scratch, as they are used worldwide on multiple web environments and have been tested by the web application security and development communities over time.

J2EE 、 ASP .NET 、 PHP などの Web 開発フレームワークは、独自の Session 管理機能と関連する実装を提供しています。これらのフレームワークは、複数のウェブ環境で世界中で使用されており、ウェブアプリケーションのセキュリティと開発コミュニティによって長期にわたってテストされているため、ゼロから自作するのではなく、これらの組み込みフレームワークを使用することが推奨されます。

However, be advised that these frameworks have also presented vulnerabilities and weaknesses in the past, so it is always recommended to use the latest version available, that potentially fixes all the well-known vulnerabilities, as well as review and change the default configuration to enhance its security by following the recommendations described along this document.

しかし、これらのフレームワークは、過去に脆弱性や弱点も指摘されているため、よく知られている脆弱性をすべて修正した最新バージョンを使用し、本書に記載されている推奨事項に従って、セキュリティを強化するためにデフォルト設定を見直し、変更することが常に推奨されますことをご承知ください。

The storage capabilities or repository used by the session management mechanism to temporarily save the session IDs must be secure, protecting the session IDs against local or remote accidental disclosure or unauthorized access.

Session 管理機構が Session ID を一時的に保存するために使用するストレージ機能またはリポジトリは、ローカルまたはリモートの偶発的な開示または不正アクセスから Session ID を保護する、安全でなければなりません。


### Used vs. Accepted Session ID Exchange Mechanisms

A web application should make use of cookies for session ID exchange management. If a user submits a session ID through a different exchange mechanism, such as a URL parameter, the web application should avoid accepting it as part of a defensive strategy to stop session fixation.

ウェブアプリケーションは、 Session ID の交換管理のために Cookie を利用する必要があります。ユーザが URL パラメータのような別の交換メカニズムを通じて Session ID を提出する場合、 Web アプリケーションは、 Session の固定化を阻止するための防御戦略の一環として、それを受け入れることを避けるべきである。

**NOTE**:

- Even if a web application makes use of cookies as its default session ID exchange mechanism, it might accept other exchange mechanisms too.
- It is therefore required to confirm via thorough testing all the different mechanisms currently accepted by the web application when processing and managing session IDs, and limit the accepted session ID tracking mechanisms to just cookies.
- In the past, some web applications used URL parameters, or even switched from cookies to URL parameters (via automatic URL rewriting), if certain conditions are met (for example, the identification of web clients without support for cookies or not accepting cookies due to user privacy concerns).

- ウェブアプリケーションがデフォルトの Session ID 交換メカニズムとして Cookie を使用している場合でも、他の交換メカニズムも受け入れる可能性があります。
- したがって、 Session ID を処理し管理する際に、ウェブアプリケーションが現在受け入れているすべての異なるメカニズムを徹底的なテストを通じて確認し、受け入れられている Session ID 追跡メカニズムを Cookie だけに限定することが必要です。
- 過去には、一部のウェブアプリケーションが URL パラメータを使用したり、特定の条件(例えば、 Cookie を サポートしていないウェブクライアントの識別や、ユーザのプライバシーに関する懸念から Cookie を受け入れないなど)を 満たす場合には、(URL の自動書き換えによって)Cookie から URL パラメータに切り替えることもありました。


### Transport Layer Security

In order to protect the session ID exchange from active eavesdropping and passive disclosure in the network traffic, it is essential to use an encrypted HTTPS (TLS) connection for the entire web session, not only for the authentication process where the user credentials are exchanged. This may be mitigated by [HTTP Strict Transport Security (HSTS)](HTTP_Strict_Transport_Security_Cheat_Sheet.md) for a client that supports it.

Session ID の交換をネットワークトラフィックの能動的な盗聴や受動的な開示から保護するためには、ユーザー認証情報を交換する認証プロセスだけでなく、 Web Session 全体で暗号化された HTTPS(TLS)接続を使用することが不可欠である。これは、[HTTP Strict Transport Security (HSTS)](HTTP_Strict_Transport_Security_Cheat_Sheet.md) をサポートしているクライアントであれば、緩和されるかもしれません。

Additionally, the `Secure` [cookie attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies) must be used to ensure the session ID is only exchanged through an encrypted channel. The usage of an encrypted communication channel also protects the session against some session fixation attacks where the attacker is able to intercept and manipulate the web traffic to inject (or fix) the session ID on the victim's web browser (see [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-Slides.pdf) and [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-WP.pdf)).

さらに、`Secure` [Cookie 属性](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)を使用して、 Session ID が暗号化された通信路を通じてのみ交換されるようにする必要があります。暗号化された通信路の使用は、攻撃者がウェブトラフィックを傍受して操作し、被害者のウェブブラウザに Session ID を注入(または固定)することができるいくつかの Session 固定化攻撃から Session を保護します( [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-Slides.pdf) と [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-WP.pdf) を参照)。

The following set of best practices are focused on protecting the session ID (specifically when cookies are used) and helping with the integration of HTTPS within the web application:

以下のベストプラクティスは、 Session ID の保護(特に Cookie を使用する場合)と、 Web アプリケーション内の HTTPS の統合を支援することに重点を置いています:

- Do not switch a given session from HTTP to HTTPS, or vice-versa, as this will disclose the session ID in the clear through the network.
  - When redirecting to HTTPS, ensure that the cookie is set or regenerated **after** the redirect has occurred.
- Do not mix encrypted and unencrypted contents (HTML pages, images, CSS, JavaScript files, etc) in the same page, or from the same domain.
- Where possible, avoid offering public unencrypted contents and private encrypted contents from the same host. Where insecure content is required, consider hosting this on a separate insecure domain.
- Implement [HTTP Strict Transport Security (HSTS)](HTTP_Strict_Transport_Security_Cheat_Sheet.md) to enforce HTTPS connections.

- ネットワークを通じて Session ID が明らかになるため、ある Session を HTTP から HTTPS に、またはその逆に切り替えないでくだ さい。
  - HTTPS にリダイレクトする場合は、リダイレクトが行われた後に Cookie が設定または再生成されるようにする。
- 暗号化されたコンテンツと暗号化されていないコンテンツ(HTML ページ、画像、 CSS 、 JavaScript ファイルなど)を同じページ、または同じドメインで混在させないこと。
- 可能な限り、同じホストから、公開されている非暗号化コンテンツと、非公開の暗号化コンテンツを提供することは避けてください。安全でないコンテンツが必要な場合は、安全でない別のドメインでホストすることを検討する。
- HTTP Strict Transport Security (HSTS)](HTTP_Strict_Transport_Security_Cheat_Sheet.md) を導入して、 HTTPS 接続を強制する。

www.DeepL.com/Translator(無料版)で翻訳しました。

See the OWASP [Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md) for more general guidance on implementing TLS securely.

TLS を安全に実装するための一般的なガイダンスについては、 OWASP [Transport Layer Protection Cheat Sheet](Transport_Layer_Protection_Cheat_Sheet.md) をご覧ください。

It is important to emphasize that TLS does not protect against session ID prediction, brute force, client-side tampering or fixation; however, it does provide effective protection against an attacker intercepting or stealing session IDs through a man in the middle attack.

TLS は Session ID の予測、ブルートフォース、クライアントサイドの改ざん、フィクセーションから保護しないことを強調することが重要です。しかし、攻撃者が中間者攻撃によって Session ID を傍受したり盗んだりすることに対して、効果的な保護を提供します。


## Cookies

The session ID exchange mechanism based on cookies provides multiple security features in the form of cookie attributes that can be used to protect the exchange of the session ID:

Cookie に基づく Session ID の交換機構は、 Cookie の属性という形で複数のセキュリティ機能を提供し、 Session ID の交換を保護するために使用することができます:


### Secure Attribute

The `Secure` cookie attribute instructs web browsers to only send the cookie through an encrypted HTTPS (SSL/TLS) connection. This session protection mechanism is mandatory to prevent the disclosure of the session ID through MitM (Man-in-the-Middle) attacks. It ensures that an attacker cannot simply capture the session ID from web browser traffic.

Secure」 Cookie 属性は、暗号化された HTTPS(SSL/TLS)接続を通じてのみ Cookie を送信するよう、ウェブブラウザに指示します。この Session 保護メカニズムは、 MitM(Man-in-the-Middle)攻撃による Session ID の漏洩を防ぐために必須です。攻撃者がウェブブラウザのトラフィックから Session ID を単純に取得できないようにするためです。

Forcing the web application to only use HTTPS for its communication (even when port TCP/80, HTTP, is closed in the web application host) does not protect against session ID disclosure if the `Secure` cookie has not been set - the web browser can be deceived to disclose the session ID over an unencrypted HTTP connection. The attacker can intercept and manipulate the victim user traffic and inject an HTTP unencrypted reference to the web application that will force the web browser to submit the session ID in the clear.

Web アプリケーションの通信に HTTPS のみを使用するように強制しても(Web アプリケーションのホストで TCP/80 ポート、 HTTP が閉じられていても)、`Secure`Cookie が設定されていない場合は Session ID の漏洩から保護されません - Web ブラウザは暗号化されていない HTTP 接続を介して Session ID を開示するように騙すことができます。攻撃者は、被害者のユーザートラフィックを傍受して操作し、ウェブブラウザに Session ID を平文で送信させる HTTP 非暗号化参照をウェブアプリケーションに注入することができます。

See also: [SecureFlag](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)


### HttpOnly Attribute

The `HttpOnly` cookie attribute instructs web browsers not to allow scripts (e.g. JavaScript or VBscript) an ability to access the cookies via the DOM document.cookie object. This session ID protection is mandatory to prevent session ID stealing through XSS attacks. However, if an XSS attack is combined with a CSRF attack, the requests sent to the web application will include the session cookie, as the browser always includes the cookies when sending requests. The `HttpOnly` cookie only protects the confidentiality of the cookie; the attacker cannot use it offline, outside of the context of an XSS attack.

HttpOnly`Cookie 属性は、 DOM の document.cookie オブジェクトを介してスクリプト(JavaScript や VBscript など)が Cookie にアクセスする能力をウェブブラウザに許可しないよう指示します。この Session ID 保護は、 XSS 攻撃による Session ID の盗用を防ぐために必須です。しかし、 XSS 攻撃と CSRF 攻撃が組み合わさった場合、ブラウザはリクエストを送信する際に必ず Cookie を含めるため、ウェブアプリケーションに送信されるリクエストは Session Cookie を含むことになります。 HttpOnly`Cookie は Cookie の機密性を保護するだけで、攻撃者は XSS 攻撃の文脈以外ではオフラインで Cookie を使用することはできない。

See the OWASP [XSS (Cross Site Scripting) Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md).

OWASP [XSS (Cross Site Scripting) Prevention Cheat Sheet](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) をご参照ください。

See also: [HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies)


### SameSite Attribute

SameSite defines a cookie attribute preventing browsers from sending a SameSite flagged cookie with cross-site requests. The main goal is to mitigate the risk of cross-origin information leakage, and provides some protection against cross-site request forgery attacks.

SameSite は、ブラウザがクロスサイトリクエストで SameSite フラグ付き Cookie を送信しないようにする Cookie 属性を定義しています。主な目的は、クロスオリジン情報漏洩のリスクを軽減することであり、クロスサイト・リクエスト・フォージェリ攻撃に対するある程度の保護を提供します。

See also: [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies)


### Domain and Path Attributes

The [`Domain` cookie attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives) instructs web browsers to only send the cookie to the specified domain and all subdomains. If the attribute is not set, by default the cookie will only be sent to the origin server. The [`Path` cookie attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives) instructs web browsers to only send the cookie to the specified directory or subdirectories (or paths or resources) within the web application. If the attribute is not set, by default the cookie will only be sent for the directory (or path) of the resource requested and setting the cookie.

[`Domain` Cookie 属性](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives)は、指定されたドメインとすべてのサブドメインにのみ Cookie を送信するようにウェブブラウザに指示する。この属性が設定されていない場合、デフォルトでは Cookie はオリジン・サーバーにのみ送信されます。 [`Path` Cookie 属性](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives)は、ウェブアプリケーション内の指定されたディレクトリやサブディレクトリ(あるいはパスやリソース)にのみ Cookie を送信するようにウェブブラウザに指示します。この属性が設定されていない場合、デフォルトでは、 Cookie は要求されたリソースのディレクトリ(またはパス)に対してのみ送信され、 Cookie を設定することになります。

It is recommended to use a narrow or restricted scope for these two attributes. In this way, the `Domain` attribute should not be set (restricting the cookie just to the origin server) and the `Path` attribute should be set as restrictive as possible to the web application path that makes use of the session ID.

これらの 2 つの属性には、狭い範囲または制限された範囲を使用することが推奨されます。この方法では、`Domain`属性は設定すべきではなく(Cookie をオリジン・サーバーだけに制限する)、`Path`属性は Session ID を利用するウェブ・アプリケーション・パスにできるだけ制限的に設定すべきです。

Setting the `Domain` attribute to a too permissive value, such as `example.com` allows an attacker to launch attacks on the session IDs between different hosts and web applications belonging to the same domain, known as cross-subdomain cookies. For example, vulnerabilities in `www.example.com` might allow an attacker to get access to the session IDs from `secure.example.com`.

`Domain` 属性に `example.com` のような寛容すぎる値を設定すると、攻撃者はクロスサブドメイン Cookie として知られる、同じドメインに属する異なるホストとウェブアプリケーション間の Session ID に対する攻撃を開始することができます。例えば、`www.example.com`の脆弱性により、攻撃者は`secure.example.com`の Session ID にアクセスすることができるかもしれません。

Additionally, it is recommended not to mix web applications of different security levels on the same domain. Vulnerabilities in one of the web applications would allow an attacker to set the session ID for a different web application on the same domain by using a permissive `Domain` attribute (such as `example.com`) which is a technique that can be used in [session fixation attacks](http://www.acrossecurity.com/papers/session_fixation.pdf).

さらに、同じドメイン上に異なるセキュリティレベルのウェブアプリケーションを混在させないことが推奨されます。 Web アプリケーションの 1 つに脆弱性があると、攻撃者は、[Session 固定化攻撃](http://www.acrossecurity.com/papers/session_fixation.pdf)で使用できるテクニックである寛容な`Domain`属性(`example.com`など)を使用して、同じドメイン上の別の Web アプリケーションの Session ID を設定することができます。

Although the `Path` attribute allows the isolation of session IDs between different web applications using different paths on the same host, it is highly recommended not to run different web applications (especially from different security levels or scopes) on the same host. Other methods can be used by these applications to access the session IDs, such as the `document.cookie` object. Also, any web application can set cookies for any path on that host.

`Path`属性は、同じホスト上で異なるパスを使用する異なるウェブアプリケーション間で Session ID を分離することを可能にしますが、同じホスト上で異なるウェブアプリケーション(特に異なるセキュリティレベルまたはスコープ)を実行しないことが強く推奨されます。これらのアプリケーションが Session ID にアクセスするには、`document.cookie`オブジェクトのような他の方法を使用することができます。また、どのウェブアプリケーションも、そのホスト上のどのパスに対しても Cookie を設定することができます。

Cookies are vulnerable to DNS spoofing/hijacking/poisoning attacks, where an attacker can manipulate the DNS resolution to force the web browser to disclose the session ID for a given host or domain.

Cookie は、 DNS スプーフィング/ハイジャック/ポイズニング攻撃に対して脆弱です。攻撃者は、 DNS 解決を操作して、ウェブブラウザに特定のホストまたはドメインの Session ID を開示させることができます。


### Expire and Max-Age Attributes

Session management mechanisms based on cookies can make use of two types of cookies, non-persistent (or session) cookies, and persistent cookies. If a cookie presents the [`Max-Age`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives) (that has preference over `Expires`) or [`Expires`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives) attributes, it will be considered a persistent cookie and will be stored on disk by the web browser based until the expiration time.

Cookie に基づく Session 管理機構は、非永続的な(あるいは Session)Cookie と永続的な Cookie の 2 種類の Cookie を利用することができます。 Cookie が [`Max-Age`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives) (`Expires`よりも優先される) または [`Expires`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives) 属性を提示する場合、それは持続的 Cookie とみなされ、有効期限が切れるまでウェブブラウザによってディスク上に保存されます。

Typically, session management capabilities to track users after authentication make use of non-persistent cookies. This forces the session to disappear from the client if the current web browser instance is closed. Therefore, it is highly recommended to use non-persistent cookies for session management purposes, so that the session ID does not remain on the web client cache for long periods of time, from where an attacker can obtain it.

一般的に、認証後にユーザーを追跡する Session 管理機能は、非永続的な Cookie を使用します。このため、現在のウェブブラウザのインスタンスが閉じられると、 Session は強制的にクライアントから消滅する。したがって、 Session 管理の目的で非永続的な Cookie を使用することが強く推奨され、 Session ID がウェブクライアントのキャッシュに長時間残り、そこから攻撃者が取得することができないようにします。

- Ensure that sensitive information is not compromised by ensuring that it is not persistent, encrypting it, and storing it only for the duration of the need
- Ensure that unauthorized activities cannot take place via cookie manipulation
- Ensure secure flag is set to prevent accidental transmission over the wire in a non-secure manner
- Determine if all state transitions in the application code properly check for the cookies and enforce their use
- Ensure entire cookie should be encrypted if sensitive data is persisted in the cookie
- Define all cookies being used by the application, their name and why they are needed

- 機密情報は、永続的でないこと、暗号化すること、必要な期間だけ保存することで、漏洩しないようにすること。
- Cookie の操作によって不正な行為ができないようにすること。
- 非セキュアな方法で誤って有線送信されることを防ぐため、セキュアフラグを設定すること
- アプリケーションコードのすべての状態遷移が、 Cookie を適切にチェックし、その使用を強制しているかどうかを判断する。
- 機密データが Cookie に保存される場合、 Cookie 全体を暗号化することを保証する。
- アプリケーションで使用されるすべての Cookie を定義し、その名前と必要な理由を説明します。


## HTML5 Web Storage API

The Web Hypertext Application Technology Working Group (WHATWG) describes the HTML5 Web Storage APIs, `localStorage` and `sessionStorage`, as mechanisms for storing name-value pairs client-side.

Web Hypertext Application Technology Working Group (WHATWG) は、 HTML5 Web Storage API の `localStorage` と `sessionStorage` を、クライアントサイドで名前と値のペアを保存するメカニズムとして記述しています。

Unlike HTTP cookies, the contents of `localStorage` and `sessionStorage` are not automatically shared within requests or responses by the browser and are used for storing data client-side.

HTTP Cookie とは異なり、`localStorage`と`sessionStorage`の内容は、ブラウザがリクエストやレスポンスの中で自動的に共有するものではなく、クライアントサイドでデータを保存するために使用されます。


### The localStorage API

#### Scope

Data stored using the `localStorage` API is accessible by pages which are loaded from the same origin, which is defined as the scheme (`https://`), host (`example.com`), port (`443`) and domain/realm (`example.com`).

`localStorage` API を使用して保存されたデータは、同じオリジンから読み込まれたページからアクセスできます。このオリジンは、スキーム(`https://`)、ホスト(`example.com`)、ポート(`443`)、ドメイン/レルム(`example.com`)として定義されています。

This provides similar access to this data as would be achieved by using the `secure` flag on a cookie, meaning that data stored from `https` could not be retrieved via `http`. Due to potential concurrent access from separate windows/threads, data stored using `localStorage` may be susceptible to shared access issues (such as race-conditions) and should be considered non-locking ([Web Storage API Spec](https://html.spec.whatwg.org/multipage/webstorage.html#the-localstorage-attribute)).

これは、 Cookie の `secure` フラグを使用した場合と同様のアクセス方法であり、`https` から保存したデータを `http` 経由で取得することができないことを意味します。別のウィンドウやスレッドから同時にアクセスする可能性があるため、`localStorage`を使用して保存されたデータは、共有アクセスの問題(レース条件など)の影響を受けやすく、ロックされていないと考えるべきである([Web Storage API Spec](https://html.spec.whatwg.org/multipage/webstorage.html#the-localstorage-attribute))。


#### Duration

Data stored using the `localStorage` API is persisted across browsing sessions, extending the timeframe in which it may be accessible to other system users.

`localStorage`API を使用して保存されたデータは、閲覧 Session を越えて永続化されるため、他のシステムユーザーがアクセスできる期間が延長される可能性があります。


#### Offline Access

The standards do not require `localStorage` data to be encrypted-at-rest, meaning it may be possible to directly access this data from disk.

この規格では、`localStorage`のデータを暗号化して保存する必要はなく、ディスクからこのデータに直接アクセスできる可能性があることを意味します。


#### Use Case

WHATWG suggests the use of `localStorage` for data that needs to be accessed across windows or tabs, across multiple sessions, and where large (multi-megabyte) volumes of data may need to be stored for performance reasons.

WHATWG では、ウィンドウやタブをまたいでアクセスする必要があるデータ、複数の Session にまたがるデータ、パフォーマンス上の理由から大容量(数メガバイト)のデータを保存する必要がある場合、`localStorage`を使用することを提案します。


### The sessionStorage API

#### Scope

The `sessionStorage` API stores data within the window context from which it was called, meaning that Tab 1 cannot access data which was stored from Tab 2.

`sessionStorage`API は、呼び出されたウィンドウコンテキスト内にデータを保存します。つまり、タブ 1 はタブ 2 から保存されたデータにアクセスすることができません。

Also, like the `localStorage` API, data stored using the `sessionStorage` API is accessible by pages which are loaded from the same origin, which is defined as the scheme (`https://`), host (`example.com`), port (`443`) and domain/realm (`example.com`).

また、`localStorage` API と同様に、`sessionStorage` API を使用して保存されたデータは、同じオリジンから読み込まれたページからアクセス可能です。このオリジンは、スキーム (`https://`)、ホスト (`example.com`) 、ポート (`443`)、ドメイン/レルム (`example.com`) として定義されます。

This provides similar access to this data as would be achieved by using the `secure` flag on a cookie, meaning that data stored from `https` could not be retrieved via `http`.

これは、 Cookie の `secure` フラグを使用した場合と同様に、このデータへのアクセスを提供するもので、`https` から保存されたデータを `http` で取得することはできません。


#### Duration

The `sessionStorage` API only stores data for the duration of the current browsing session. Once the tab is closed, that data is no longer retrievable. This does not necessarily prevent access, should a browser tab be reused or left open. Data may also persist in memory until a garbage collection event.

`sessionStorage`API は、現在のブラウジング Session の間だけデータを保存する。タブを閉じると、そのデータはもはや取り出すことができない。ただし、ブラウザのタブが再利用されたり、開いたままになったりした場合のアクセスは必ずしも妨げられない。また、ガベージコレクションイベントが発生するまで、データはメモリ内に留まることもあります。


#### Offline Access

The standards do not require `sessionStorage` data to be encrypted-at-rest, meaning it may be possible to directly access this data from disk.

この規格では、`sessionStorage`のデータを暗号化して保存することを要求していないため、ディスクからこのデータに直接アクセスできる可能性があります。


#### Use Case

WHATWG suggests the use of `sessionStorage` for data that is relevant for one-instance of a workflow, such as details for a ticket booking, but where multiple workflows could be performed in other tabs concurrently. The window/tab bound nature will keep the data from leaking between workflows in separate tabs.

WHATWG は、チケット予約の詳細のようなワークフローの 1 インスタンスに関連するデータで、他のタブで複数のワークフローを同時に実行できるようなデータには、`sessionStorage`を使用することを提案します。ウィンドウやタブに拘束されるため、別々のタブにあるワークフロー間でデータが漏れることがない。


### References

- [Web Storage APIs](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API/Using_the_Web_Storage_API)
- [LocalStorage API](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)
- [SessionStorage API](https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage)
- [WHATWG Web Storage Spec](https://html.spec.whatwg.org/multipage/webstorage.html#webstorage)


## Web Workers

Web Workers run JavaScript code in a global context separate from the one of the current window. A communication channel with the main execution window exists, which is called `MessageChannel`.

Web Workers は、カレントウィンドウのコンテキストとは別のグローバルコンテキストで JavaScript コードを実行する。メイン実行ウィンドウとの通信チャネルが存在し、これは `MessageChannel` と呼ばれる。


### Use Case

Web Workers are an alternative for browser storage of (session) secrets when storage persistence across page refresh is not a requirement. For Web Workers to provide secure browser storage, any code that requires the secret should exist within the Web Worker and the secret should never be transmitted to the main window context.

Web Workers は、ページ更新時のストレージの永続性が要求されない場合に、(Session)シークレットのブラウザストレージの代替となるものです。 Web Workers が安全なブラウザストレージを提供するためには、秘密を必要とするすべてのコードが Web Worker 内に存在し、秘密がメインウィンドウのコンテキストに送信されることがないようにする必要があります。

Storing secrets within the memory of a Web Worker offers the same security guarantees as an HttpOnly cookie: the confidentiality of the secret is protected. Still, an XSS attack can be used to send messages to the Web Worker to perform an operation that requires the secret. The Web Worker will return the result of the operation to the main execution thread.

Web Worker のメモリ内に秘密を保存することは、 HttpOnly Cookie と同じセキュリティ保証を提供します:秘密の機密性が保護されます。それでも、 XSS 攻撃を利用して、 Web Worker にメッセージを送り、秘密を必要とする操作を実行させることは可能です。 Web Worker は、操作の結果をメイン実行スレッドに返します。

The advantage of a Web Worker implementation compared to an HttpOnly cookie is that a Web Worker allows for some isolated JavaScript code to access the secret; an HttpOnly cookie is not accessible to any JavaScript. If the frontend JavaScript code requires access to the secret, the Web Worker implementation is the only browser storage option that preserves the secret confidentiality.

HttpOnly Cookie と比較した Web Worker 実装の利点は、 Web Worker が一部の孤立した JavaScript コードに秘密へのアクセスを許可することです; HttpOnly Cookie はどんな JavaScript にもアクセスできません。 HttpOnly Cookie はどの JavaScript にもアクセスできません。フロントエンドの JavaScript コードが秘密へのアクセスを必要とする場合、 Web Worker の実装は秘密の機密性を維持する唯一のブラウザストレージオプションです。


## Session ID Life Cycle

### Session ID Generation and Verification: Permissive and Strict Session Management

There are two types of session management mechanisms for web applications, permissive and strict, related to session fixation vulnerabilities. The permissive mechanism allows the web application to initially accept any session ID value set by the user as valid, creating a new session for it, while the strict mechanism enforces that the web application will only accept session ID values that have been previously generated by the web application.

Session 固定化脆弱性に関連する Web アプリケーションの Session 管理機構には、寛容な機構と厳格な機構の 2 種類がある。寛容なメカニズムでは、 Web アプリケーションは、ユーザーが設定した Session ID 値を有効なものとして最初に受け入れ、そのために新しい Session を作成することができ、厳格なメカニズムでは、 Web アプリケーションが以前に生成した Session ID 値のみを受け入れることが強制されます。

The session tokens should be handled by the web server if possible or generated via a cryptographically secure random number generator.

Session ・トークンは、可能であればウェブ・サーバーが処理するか、暗号化された安全な乱数生成器を介して生成する必要があります。

Although the most common mechanism in use today is the strict one (more secure), [PHP defaults to permissive](https://wiki.php.net/rfc/session-use-strict-mode). Developers must ensure that the web application does not use a permissive mechanism under certain circumstances. Web applications should never accept a session ID they have never generated, and in case of receiving one, they should generate and offer the user a new valid session ID. Additionally, this scenario should be detected as a suspicious activity and an alert should be generated.

今日、最も一般的に使用されている機構は厳格なもの(より安全)ですが、 [PHP のデフォルトは permissive](https://wiki.php.net/rfc/session-use-strict-mode)です。開発者は、特定の状況下でウェブアプリケーションが permissive メカニズムを使用しないようにする必要があります。ウェブアプリケーションは、生成したことのない Session ID を受け入れてはいけません。また、 Session ID を受け取った場合は、新しい有効な Session ID を生成してユーザーに提供しなければなりません。さらに、このシナリオは疑わしい活動として検出され、アラートが生成される必要があります。


### Manage Session ID as Any Other User Input

Session IDs must be considered untrusted, as any other user input processed by the web application, and they must be thoroughly validated and verified. Depending on the session management mechanism used, the session ID will be received in a GET or POST parameter, in the URL or in an HTTP header (e.g. cookies). If web applications do not validate and filter out invalid session ID values before processing them, they can potentially be used to exploit other web vulnerabilities, such as SQL injection if the session IDs are stored on a relational database, or persistent XSS if the session IDs are stored and reflected back afterwards by the web application.

Session ID は、ウェブアプリケーションが処理する他のユーザ入力と同様に、信頼できないものと考え、徹底的に検証し確認する必要があります。使用される Session 管理メカニズムに応じて、 Session ID は GET または POST パラメータ、 URL 、または HTTP ヘッダー(例:Cookie)で受け取られることになります。ウェブアプリケーションが無効な Session ID 値を処理する前に検証およびフィルタリングを行わない場合、 Session ID がリレーショナルデータベースに保存されている場合は SQL インジェクション、 Session ID が保存されウェブアプリケーションによって後から反映される場合は永続的 XSS など、他のウェブ脆弱性を悪用する可能性があるため、 Session ID は使用できません。


### Renew the Session ID After Any Privilege Level Change

The session ID must be renewed or regenerated by the web application after any privilege level change within the associated user session. The most common scenario where the session ID regeneration is mandatory is during the authentication process, as the privilege level of the user changes from the unauthenticated (or anonymous) state to the authenticated state though in some cases still not yet the authorized state. Common scenarios to consider include; password changes, permission changes, or switching from a regular user role to an administrator role within the web application. For all sensitive pages of the web application, any previous session IDs must be ignored, only the current session ID must be assigned to every new request received for the protected resource, and the old or previous session ID must be destroyed.

Session ID は、関連するユーザー Session 内で特権レベルが変更されると、 Web アプリケーションによって更新または再生成される必要があります。 Session ID の再生成が必須となる最も一般的なシナリオは、認証プロセス中で、ユーザーの特権レベルが未認証(または匿名)状態から認証状態(場合によっては、まだ認証状態ではない)に変化するときです。よくあるシナリオとしては、パスワードの変更、権限の変更、ウェブアプリケーション内の一般ユーザーから管理者ロールに切り替えた場合などが考えられます。 Web アプリケーションのすべての機密ページでは、以前の Session ID は無視され、保護されたリソースに対して受け取った新しいリクエストには現在の Session ID のみが割り当てられ、古いまたは以前の Session ID は破棄されなければならない。

The most common web development frameworks provide session functions and methods to renew the session ID, such as `request.getSession(true)` & `HttpSession.invalidate()` (J2EE), `Session.Abandon()` & `Response.Cookies.Add(new...)` (ASP .NET), or `session_start()` & `session_regenerate_id(true)` (PHP).

一般的な Web 開発フレームワークでは、`request.getSession(true)` & `HttpSession.invalidate()` (J2EE), `Session.Abandon()` & `Response.Cookies.Add(new...)` (ASP .NET) や `session_start()` & `session_regenerate_id(true)` (PHP) など Session 関数や Session ID 更新メソッドは、提供されています。

The session ID regeneration is mandatory to prevent [session fixation attacks](http://www.acrossecurity.com/papers/session_fixation.pdf), where an attacker sets the session ID on the victim user's web browser instead of gathering the victim's session ID, as in most of the other session-based attacks, and independently of using HTTP or HTTPS. This protection mitigates the impact of other web-based vulnerabilities that can also be used to launch session fixation attacks, such as HTTP response splitting or XSS (see [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-Slides.pdf) and [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-WP.pdf)).

Session ID の再生は、[Session 固定化攻撃](http://www.acrossecurity.com/papers/session_fixation.pdf)を防ぐために必須です。この攻撃は、他の Session ベースの攻撃のほとんどと同様に、 HTTP や HTTPS の使用とは無関係に、被害者の Session ID を集める代わりに、攻撃者が被害者のユーザーの Web ブラウザに Session ID を設定します。この保護機能は、 HTTP レスポンスの分割や XSS など、 Session 固定化攻撃に利用できる他の Web ベースの脆弱性の影響を緩和します([こちら](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-Slides.pdf)、[こちら](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-WP.pdf)を参照)。

A complementary recommendation is to use a different session ID or token name (or set of session IDs) pre and post authentication, so that the web application can keep track of anonymous users and authenticated users without the risk of exposing or binding the user session between both states.

補完的な推奨事項として、認証前と認証後で異なる Session ID またはトークン名(または Session ID のセット)を使用することで、ウェブアプリケーションが匿名ユーザーと認証済みユーザーを追跡できるようにし、両方の状態間でユーザー Session を公開または結合するリスクはありません。


### Considerations When Using Multiple Cookies

If the web application uses cookies as the session ID exchange mechanism, and multiple cookies are set for a given session, the web application must verify all cookies (and enforce relationships between them) before allowing access to the user session.

ウェブアプリケーションが Session ID 交換メカニズムとして Cookie を使用し、与えられた Session に複数の Cookie が設定されている場合、ウェブアプリケーションはユーザー Session へのアクセスを許可する前にすべての Cookie を検証(および Cookie 間の関係を強制)しなければなりません。

It is very common for web applications to set a user cookie pre-authentication over HTTP to keep track of unauthenticated (or anonymous) users. Once the user authenticates in the web application, a new post-authentication secure cookie is set over HTTPS, and a binding between both cookies and the user session is established. If the web application does not verify both cookies for authenticated sessions, an attacker can make use of the pre-authentication unprotected cookie to get access to the authenticated user session (see [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-Slides.pdf) and [here](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-WP.pdf)).

ウェブアプリケーションでは、認証されていない(あるいは匿名の)ユーザーを追跡するために、 HTTP 経由で事前 認証のユーザー Cookie を設定することが非常に一般的です。ユーザがウェブ・アプリケーションで認証されると、新しい認証後の安全な Cookie が HTTPS 経由で設定され、両方の Cookie とユーザ・ Session の間の結合が確立され ます。ウェブ・アプリケーションが認証された Session の両方の Cookie を検証しない場合、攻撃者は認証前の保護されていない Cookie を利用して、認証されたユーザ・ Session にアクセスすることができます([ここ](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-Slides.pdf)と [ここ](https://media.blackhat.com/bh-eu-11/Raul_Siles/BlackHat_EU_2011_Siles_SAP_Session-WP.pdf)を参照)。

Web applications should try to avoid the same cookie name for different paths or domain scopes within the same web application, as this increases the complexity of the solution and potentially introduces scoping issues.

ウェブアプリケーションは、同じウェブアプリケーション内の異なるパスやドメインスコープに対して同じ Cookie 名を使用することを避けるようにすべきです。これはソリューションの複雑さを増し、スコープの問題を引き起こす可能性があるからです。


## Session Expiration

In order to minimize the time period an attacker can launch attacks over active sessions and hijack them, it is mandatory to set expiration timeouts for every session, establishing the amount of time a session will remain active. Insufficient session expiration by the web application increases the exposure of other session-based attacks, as for the attacker to be able to reuse a valid session ID and hijack the associated session, it must still be active.

攻撃者がアクティブな Session に対して攻撃を開始し、 Session を乗っ取ることができる期間を最小化するために、すべての Session に有効期限を設定し、 Session がアクティブであり続ける時間を確立することが必須です。攻撃者が有効な Session ID を再利用して関連する Session を乗っ取るには、その Session がまだ有効でなければならないため、ウェブアプリケーションによる不十分な Session 満了は、他の Session ベースの攻撃の露出を増加させる。

The shorter the session interval is, the lesser the time an attacker has to use the valid session ID. The session expiration timeout values must be set accordingly with the purpose and nature of the web application, and balance security and usability, so that the user can comfortably complete the operations within the web application without his session frequently expiring.

Session 間隔が短ければ短いほど、攻撃者が有効な Session ID を使用できる時間が短くなります。 Session の有効期限は、 Web アプリケーションの目的や性質に応じて設定する必要があり、ユーザーが頻繁に Session が切れることなく、 Web アプリケーション内で快適に操作を完了できるように、セキュリティとユーザビリティのバランスをとる必要があります。

Both the idle and absolute timeout values are highly dependent on how critical the web application and its data are. Common idle timeouts ranges are 2-5 minutes for high-value applications and 15-30 minutes for low risk applications. Absolute timeouts depend on how long a user usually uses the application. If the application is intended to be used by an office worker for a full day, an appropriate absolute timeout range could be between 4 and 8 hours.

アイドルタイムアウトと絶対タイムアウトの値は、 Web アプリケーションとそのデータがどの程度重要であるかに大きく依存します。一般的なアイドルタイムアウトの範囲は、高価値のアプリケーションでは 2 ～ 5 分、低リスクのアプリケーションでは 15 ～ 30 分です。絶対タイムアウトは、ユーザーが通常アプリケーションを使用する時間によって決まります。アプリケーションがオフィスワーカーによって一日中使用されることを意図している場合、適切な絶対的タイムアウトの範囲は 4 ～ 8 時間の間となります。

When a session expires, the web application must take active actions to invalidate the session on both sides, client and server. The latter is the most relevant and mandatory from a security perspective.

Session の有効期限が切れると、ウェブアプリケーションは、クライアントとサーバーの両側で Session を無効にするための能動的な行動を取らなければなりません。後者は、セキュリティの観点から最も関連性が高く、必須である。

For most session exchange mechanisms, client side actions to invalidate the session ID are based on clearing out the token value. For example, to invalidate a cookie it is recommended to provide an empty (or invalid) value for the session ID, and set the `Expires` (or `Max-Age`) attribute to a date from the past (in case a persistent cookie is being used): `Set-Cookie: id=; Expires=Friday, 17-May-03 18:45:00 GMT`

ほとんどの Session 交換メカニズムでは、 Session ID を無効にするためのクライアント側のアクションは、トークン値をクリアすることに基づいています。例えば、 Cookie を無効にするには、 Session ID に空の(あるいは無効な)値を与え、`Expires`(あるいは `Max-Age`)属性を過去の日付に設定することが推奨されます(永続的な Cookie が使用されている場合など): `Set-Cookie: id=; Expires=Friday, 17-May-03 18:45:00 GMT`

In order to close and invalidate the session on the server side, it is mandatory for the web application to take active actions when the session expires, or the user actively logs out, by using the functions and methods offered by the session management mechanisms, such as `HttpSession.invalidate()` (J2EE), `Session.Abandon()` (ASP .NET) or `session_destroy()/unset()` (PHP).

サーバ側で Session を閉じたり無効にしたりするためには、 Web アプリケーションは、 Session の有効期限が切れたり、ユーザが積極的にログアウトしたときに、 Session 管理機構が提供する関数やメソッド、例えば `HttpSession.invalidate()` (J2EE), `Session.Abandon()` (ASP .NET) または `session_destroy()/unset()` (PHP) を用いて、能動的に行動しなければならない。


### Automatic Session Expiration

#### Idle Timeout

All sessions should implement an idle or inactivity timeout. This timeout defines the amount of time a session will remain active in case there is no activity in the session, closing and invalidating the session upon the defined idle period since the last HTTP request received by the web application for a given session ID.

すべての Session は、アイドルまたは非アクティブのタイムアウトを実装する必要があります。このタイムアウトは、 Session にアクティビティがない場合に、 Session がアクティブな状態を維持する時間を定義するもので、与えられた Session ID に対してウェブアプリケーションが最後に受け取った HTTP リクエストから定義されたアイドル時間経過後に Session を閉じ、無効にする。

The idle timeout limits the chances an attacker has to guess and use a valid session ID from another user. However, if the attacker is able to hijack a given session, the idle timeout does not limit the attacker's actions, as they can generate activity on the session periodically to keep the session active for longer periods of time.

アイドルタイムアウトは、攻撃者が他のユーザーから有効な Session ID を推測して使用する機会を制限するものである。しかし、攻撃者が特定の Session を乗っ取ることができた場合、アイドルタイムアウトは攻撃者の行動を制限するものではなく、定期的に Session にアクティビティを発生させて、より長い時間 Session をアクティブにしておくことができます。

Session timeout management and expiration must be enforced server-side. If the client is used to enforce the session timeout, for example using the session token or other client parameters to track time references (e.g. number of minutes since login time), an attacker could manipulate these to extend the session duration.

Session タイムアウトの管理と期限切れは、サーバーサイドで実施する必要があります。例えば、 Session トークンや他のクライアントパラメータを使用して時間参照(ログイン時間からの分数など)を追跡するなど、クライアントが Session タイムアウトを強制するために使用されている場合、攻撃者はこれらを操作して Session 期間を延長することができます。


#### Absolute Timeout

All sessions should implement an absolute timeout, regardless of session activity. This timeout defines the maximum amount of time a session can be active, closing and invalidating the session upon the defined absolute period since the given session was initially created by the web application. After invalidating the session, the user is forced to (re)authenticate again in the web application and establish a new session.

すべての Session は、 Session のアクティビティに関係なく、絶対的なタイムアウトを実装する必要があります。このタイムアウトは、 Session がアクティブになる最大時間を定義し、与えられた Session が最初に Web アプリケーションによって作成されてから定義された絶対的な期間に応じて Session を閉じ、無効にします。 Session を無効にした後、ユーザーはウェブアプリケーションで再度認証し、新しい Session を確立することを余儀なくされる。

The absolute session limits the amount of time an attacker can use a hijacked session and impersonate the victim user.

絶対 Session は、攻撃者が乗っ取った Session を使用し、被害者ユーザーになりすますことができる時間を制限します。


#### Renewal Timeout

Alternatively, the web application can implement an additional renewal timeout after which the session ID is automatically renewed, in the middle of the user session, and independently of the session activity and, therefore, of the idle timeout.

あるいは、ウェブアプリケーションは、 Session ID が自動的に更新された後に、ユーザ Session の途中で、 Session のアクティビティとは無関係に、したがって、アイドルタイムアウトとは無関係に、追加の更新タイムアウトを実装することができる。

After a specific amount of time since the session was initially created, the web application can regenerate a new ID for the user session and try to set it, or renew it, on the client. The previous session ID value would still be valid for some time, accommodating a safety interval, before the client is aware of the new ID and starts using it. At that time, when the client switches to the new ID inside the current session, the application invalidates the previous ID.

Session が最初に作成されてから特定の時間が経過すると、 Web アプリケーションはユーザー Session の新しい ID を再生成し、クライアントでそれを設定または更新しようとすることができます。クライアントが新しい ID を認識し、それを使い始めるまで、安全間隔を考慮して、以前の Session ID の値はまだ有効であろう。そのとき、クライアントが現在の Session 内で新しい ID に切り替えると、アプリケーションは以前の ID を無効にする。

This scenario minimizes the amount of time a given session ID value, potentially obtained by an attacker, can be reused to hijack the user session, even when the victim user session is still active. The user session remains alive and open on the legitimate client, although its associated session ID value is transparently renewed periodically during the session duration, every time the renewal timeout expires. Therefore, the renewal timeout complements the idle and absolute timeouts, specially when the absolute timeout value extends significantly over time (e.g. it is an application requirement to keep the user sessions open for long periods of time).

このシナリオでは、攻撃者が入手した可能性のある Session ID 値が、犠牲となったユーザー Session がまだアクティブであっても、ユーザー Session をハイジャックするために再利用できる時間を最小限に抑えることができます。 Session ID は、 Session 期間中、更新タイムアウトが切れるたびに透過的に更新されるが、ユーザー Session は、正当なクライアント上で生きて開いているままである。したがって、更新タイムアウトは、アイドルタイムアウトと絶対タイムアウトを補完し、特に絶対タイムアウト値が時間と共に大幅に拡張される場合(例えば、ユーザ Session を長期間にわたってオープンにしておくことがアプリケーション要件である)。

Depending on the implementation, potentially there could be a race condition where the attacker with a still valid previous session ID sends a request before the victim user, right after the renewal timeout has just expired, and obtains first the value for the renewed session ID. At least in this scenario, the victim user might be aware of the attack as her session will be suddenly terminated because her associated session ID is not valid anymore.

実装によっては、まだ有効な以前の Session ID を持つ攻撃者が、更新のタイムアウトが切れた直後に被害者ユーザーにリクエストを送り、更新された Session ID の値を最初に取得するという競合状態が発生する可能性がある。少なくともこのシナリオでは、関連する Session ID がもう有効でないため、彼女の Session が突然終了するため、被害者ユーザーは攻撃に気づくかもしれない。


### Manual Session Expiration

Web applications should provide mechanisms that allow security aware users to actively close their session once they have finished using the web application.

ウェブアプリケーションは、セキュリティを意識するユーザーがウェブアプリケーションの使用を終えたら、積極的に Session を閉じることができるメカニズムを提供する必要があります。


#### Logout Button

Web applications must provide a visible and easily accessible logout (logoff, exit, or close session) button that is available on the web application header or menu and reachable from every web application resource and page, so that the user can manually close the session at any time. As described in _Session_Expiration_ section, the web application must invalidate the session at least on server side.

ウェブアプリケーションは、ユーザーがいつでも手動で Session を閉じることができるように、ウェブアプリケーションのヘッダーやメニューから利用でき、すべてのウェブアプリケーションのリソースやページから到達可能な、可視で簡単にアクセスできるログアウト(ログオフ、終了、または Session を閉じる)ボタンを提供しなければなりません。 Session の有効期限」で説明したように、ウェブアプリケーションは少なくともサーバー側で Session を無効化しなければなりません。

**NOTE**: Unfortunately, not all web applications facilitate users to close their current session. Thus, client-side enhancements allow conscientious users to protect their sessions by helping to close them diligently.

**注意**:残念ながら、すべてのウェブアプリケーションで、ユーザーが現在の Session を閉じることができるわけではありません。したがって、クライアント側の機能強化により、良心的なユーザーは、 Session を熱心に閉じることを支援することによって、 Session を保護することができます。


### Web Content Caching

Even after the session has been closed, it might be possible to access the private or sensitive data exchanged within the session through the web browser cache. Therefore, web applications must use restrictive cache directives for all the web traffic exchanged through HTTP and HTTPS, such as the [`Cache-Control`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control) and [`Pragma`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma) HTTP headers, and/or equivalent META tags on all or (at least) sensitive web pages.

Session が終了した後でも、 Web ブラウザのキャッシュを通じて、 Session 内でやり取りされた個人情報や機密データにアクセスできる可能性があります。したがって、ウェブアプリケーションは、 HTTP と HTTPS を通じて交換されるすべてのウェブトラフィックに対して、[`Cache-Control`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)と[`Pragma`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma) HTTP ヘッダーや、すべてのウェブページまたは(少なくとも)機密のウェブページの同等の META タグなどの制限付きキャッシュディレクティブを使用しなければなりません。

Independently of the cache policy defined by the web application, if caching web application contents is allowed, the session IDs must never be cached, so it is highly recommended to use the `Cache-Control: no-cache="Set-Cookie, Set-Cookie2"` directive, to allow web clients to cache everything except the session ID (see [here](https://stackoverflow.com/a/41352418)).

Web アプリケーションで定義されたキャッシュポリシーとは関係なく、 Web アプリケーションのコンテンツのキャッシュを許可する場合、 Session ID は絶対にキャッシュしてはいけません。そのため、`Cache-Control: no-cache="Set-Cookie, Set-Cookie2"` 指令を使用して、 Web クライアントが Session ID 以外のすべてをキャッシュすることを強く推奨します([こちら](https://stackoverflow.com/a/41352418) 参照)。


## Additional Client-Side Defenses for Session Management

Web applications can complement the previously described session management defenses with additional countermeasures on the client side. Client-side protections, typically in the form of JavaScript checks and verifications, are not bullet proof and can easily be defeated by a skilled attacker, but can introduce another layer of defense that has to be bypassed by intruders.

ウェブアプリケーションは、クライアント側の追加対策で、先に述べた Session 管理の防御を補完することができます。クライアント側の保護は、典型的には JavaScript のチェックと検証の形で、弾丸のように強いものではなく、熟練した攻撃者に よって簡単に破られる可能性がありますが、侵入者が迂回しなければならない別の防御層を導入することができます。


### Initial Login Timeout

Web applications can use JavaScript code in the login page to evaluate and measure the amount of time since the page was loaded and a session ID was granted. If a login attempt is tried after a specific amount of time, the client code can notify the user that the maximum amount of time to log in has passed and reload the login page, hence retrieving a new session ID.

Web アプリケーションでは、ログインページの JavaScript コードを使用して、ページが読み込まれ、 Session ID が付与されてからの時間を評価・測定することができます。特定の時間経過後にログインを試みた場合、クライアントコードは、ログインの最大時間が経過したことをユーザーに通知し、ログインページを再読み込みして、新しい Session ID を取得することができます。

This extra protection mechanism tries to force the renewal of the session ID pre-authentication, avoiding scenarios where a previously used (or manually set) session ID is reused by the next victim using the same computer, for example, in session fixation attacks.

この特別な保護メカニズムは、 Session ID を認証前に強制的に更新しようとするもので、 Session 固定化攻撃などで、以前に使用した(または手動で設定した)Session ID が、同じコンピュータを使用する次の被害者に再利用されるシナリオを回避する。


### Force Session Logout On Web Browser Window Close Events

Web applications can use JavaScript code to capture all the web browser tab or window close (or even back) events and take the appropriate actions to close the current session before closing the web browser, emulating that the user has manually closed the session via the logout button.

ウェブアプリケーションは、 JavaScript のコードを使用して、ウェブブラウザのタブやウィンドウを閉じる(あるいは戻る)イベントをすべて取得し、ウェブブラウザを閉じる前に現在の Session を閉じるための適切なアクションを行い、ユーザーがログアウトボタンで Session を手動で閉じたことをエミュレートすることができます。


### Disable Web Browser Cross-Tab Sessions

Web applications can use JavaScript code once the user has logged in and a session has been established to force the user to re-authenticate if a new web browser tab or window is opened against the same web application. The web application does not want to allow multiple web browser tabs or windows to share the same session. Therefore, the application tries to force the web browser to not share the same session ID simultaneously between them.

Web アプリケーションでは、ユーザーがログインして Session が確立されると、 JavaScript のコードを使用して、同じ Web アプリケーションに対して新しい Web ブラウザのタブまたはウィンドウを開くと、ユーザーに再認証を強制することができます。ウェブアプリケーションは、複数のウェブブラウザタブまたはウィンドウが同じ Session を共有することを望んでいません。そのため、アプリケーションは、 Web ブラウザ間で同じ Session ID を同時に共有しないように強制しようとします。

**NOTE**: This mechanism cannot be implemented if the session ID is exchanged through cookies, as cookies are shared by all web browser tabs/windows.

**NOTE**:Cookie はすべてのウェブブラウザのタブやウィンドウで共有されるため、 Cookie を通じて Session ID を交換する場合は、このメカニズムを実装することはできません。


### Automatic Client Logout

JavaScript code can be used by the web application in all (or critical) pages to automatically logout client sessions after the idle timeout expires, for example, by redirecting the user to the logout page (the same resource used by the logout button mentioned previously).

JavaScript のコードは、すべての(または重要な)ページで Web アプリケーションが使用し、アイドルタイムアウトが終了した後に、例えば、ログアウトページ(前述のログアウトボタンが使用するのと同じリソース)にユーザーをリダイレクトすることによって、クライアント Session を自動的にログアウトすることができます。

The benefit of enhancing the server-side idle timeout functionality with client-side code is that the user can see that the session has finished due to inactivity, or even can be notified in advance that the session is about to expire through a count down timer and warning messages. This user-friendly approach helps to avoid loss of work in web pages that require extensive input data due to server-side silently expired sessions.

サーバーサイドのアイドルタイムアウト機能をクライアントサイドのコードで拡張する利点は、ユーザーが非アクティブによる Session の終了を確認できること、あるいはカウントダウンタイマーや警告メッセージによって Session が期限切れになることを事前に通知することができることです。このユーザーフレンドリーなアプローチは、サーバーサイドの無言の期限切れ Session による、膨大な入力データを必要とするウェブページの作業ロスを回避するのに役立ちます。


## Session Attacks Detection

### Session ID Guessing and Brute Force Detection

If an attacker tries to guess or brute force a valid session ID, they need to launch multiple sequential requests against the target web application using different session IDs from a single (or set of) IP address(es). Additionally, if an attacker tries to analyze the predictability of the session ID (e.g. using statistical analysis), they need to launch multiple sequential requests from a single (or set of) IP address(es) against the target web application to gather new valid session IDs.

攻撃者が有効な Session ID を推測しようとしたり、総当たりしようとしたりする場合、単一の(あるいは一連の)IP アドレスから異なる Session ID を使用してターゲットウェブアプリケーションに対して複数の連続したリクエストを開始する必要があります。さらに、攻撃者が Session ID の予測可能性を分析しようとする場合(例えば、統計分析を使用する)、ターゲットウェブアプリケーションに対して、単一の(または一連の)IP アドレスから複数の連続したリクエストを開始し、新しい有効な Session ID を収集する必要があります。

Web applications must be able to detect both scenarios based on the number of attempts to gather (or use) different session IDs and alert and/or block the offending IP address(es).

ウェブアプリケーションは、異なる Session ID を収集(または使用)しようとする試行回数に基づいて両方のシナリオを検出し、問題のある IP アドレスに警告および/またはブロックを行うことができなければなりません。


### Detecting Session ID Anomalies

Web applications should focus on detecting anomalies associated to the session ID, such as its manipulation. The OWASP [AppSensor Project](https://owasp.org/www-project-appsensor/) provides a framework and methodology to implement built-in intrusion detection capabilities within web applications focused on the detection of anomalies and unexpected behaviors, in the form of detection points and response actions. Instead of using external protection layers, sometimes the business logic details and advanced intelligence are only available from inside the web application, where it is possible to establish multiple session related detection points, such as when an existing cookie is modified or deleted, a new cookie is added, the session ID from another user is reused, or when the user location or User-Agent changes in the middle of a session.

ウェブアプリケーションは、 Session ID の操作のような Session ID に関連する異常の検出に焦点を当てるべきです。 OWASP [AppSensor Project](https://owasp.org/www-project-appsensor/) は、ウェブアプリケーションに組み込みの侵入検知機能を実装するためのフレーム ワークと方法論を提供し、検知ポイントと応答アクションの形で、異常と予期せぬ行動の検知に焦点をあてています。外部の保護層を使用する代わりに、時にはビジネスロジックの詳細や高度なインテリジェンスがウェブアプリケーションの内部からしか利用できない場合があります。そこで、既存の Cookie が変更または削除されたとき、新しい Cookie が追加されたとき、他のユーザーの Session ID が再利用されたとき、 Session の途中でユーザーの場所やユーザーエージェントが変わったときなど、複数の Session 関連の検出ポイントを確立することが可能です。


### Binding the Session ID to Other User Properties

With the goal of detecting (and, in some scenarios, protecting against) user misbehaviors and session hijacking, it is highly recommended to bind the session ID to other user or client properties, such as the client IP address, User-Agent, or client-based digital certificate. If the web application detects any change or anomaly between these different properties in the middle of an established session, this is a very good indicator of session manipulation and hijacking attempts, and this simple fact can be used to alert and/or terminate the suspicious session.

ユーザーの不正行為や Session ハイジャックを検出する(そして、シナリオによっては防御する)目的で、 Session ID を他のユーザーまたはクライアントのプロパティ(クライアント IP アドレス、ユーザーエージェント、クライアントベースのデジタル証明書など)にバインドすることが強く推奨されます。もしウェブアプリケーションが、確立された Session の途中で、これらの異なるプロパティ間の変化や異常を検出した場合、これは Session 操作やハイジャックの試みの非常に良い指標となり、この単純な事実を利用して、疑わしい Session を警告したり終了したりすることができます。

Although these properties cannot be used by web applications to trustingly defend against session attacks, they significantly increase the web application detection (and protection) capabilities. However, a skilled attacker can bypass these controls by reusing the same IP address assigned to the victim user by sharing the same network (very common in NAT environments, like Wi-Fi hotspots) or by using the same outbound web proxy (very common in corporate environments), or by manually modifying his User-Agent to look exactly as the victim users does.

これらの特性は、ウェブアプリケーションが Session 攻撃に対して信頼できる防御をするために使用することはできませんが、 ウェブアプリケーションの検出(および防御)能力を大幅に向上させます。しかし、熟練した攻撃者は、同じネットワークを共有することによって被害者ユーザに割り当てられた同じ IP アドレスを再利用したり(Wi-Fi ホットスポットのような NAT 環境では非常に一般的)、同じアウトバウンドウェブプロキシを使用したり(企業環境では非常に一般的)、自分のユーザエージェントを被害者ユーザと同じに見えるように手動で変更することによって、これらのコントロールを回避することができます。


### Logging Sessions Life Cycle: Monitoring Creation, Usage, and Destruction of Session IDs

Web applications should increase their logging capabilities by including information regarding the full life cycle of sessions. In particular, it is recommended to record session related events, such as the creation, renewal, and destruction of session IDs, as well as details about its usage within login and logout operations, privilege level changes within the session, timeout expiration, invalid session activities (when detected), and critical business operations during the session.

ウェブアプリケーションは、 Session の全ライフサイクルに関する情報を含めることで、ロギング機能を強化する必要があります。特に、 Session ID の作成、更新、破棄などの Session 関連イベントや、ログインやログアウト操作での使用状況、 Session 内での特権レベルの変更、タイムアウトの期限切れ、無効な Session 活動(検出時)、 Session 中の重要なビジネスオペレーションなどの詳細を記録することが推奨されます。

The log details might include a timestamp, source IP address, web target resource requested (and involved in a session operation), HTTP headers (including the User-Agent and Referer), GET and POST parameters, error codes and messages, username (or user ID), plus the session ID (cookies, URL, GET, POST...).

ログの詳細には、タイムスタンプ、送信元 IP アドレス、要求された(および Session 操作に関与した)Web ターゲットリソース、 HTTP ヘッダー(User-Agent および Referer を含む)、 GET および POST パラメータ、エラーコードおよびメッセージ、ユーザー名(またはユーザー ID)、さらに Session ID(Cookie 、 URL 、 GET 、 POST など)。

Sensitive data like the session ID should not be included in the logs in order to protect the session logs against session ID local or remote disclosure or unauthorized access. However, some kind of session-specific information must be logged in order to correlate log entries to specific sessions. It is recommended to log a salted-hash of the session ID instead of the session ID itself in order to allow for session-specific log correlation without exposing the session ID.

Session ID のローカルまたはリモートでの開示や不正アクセスから Session ログを保護するために、 Session ID のような機密データをログに含めるべきではない。しかし、ログエントリーを特定の Session に関連付けるために、ある種の Session 固有の情報をログに記録する必要があります。 Session ID を公開せずに Session 固有のログ相関を可能にするために、 Session ID 自体の代わりに Session ID の塩漬けハッシュをログに記録することが推奨されます。

In particular, web applications must thoroughly protect administrative interfaces that allow to manage all the current active sessions. Frequently these are used by support personnel to solve session related issues, or even general issues, by impersonating the user and looking at the web application as the user does.

特に、ウェブアプリケーションは、現在有効な Session をすべて管理できる管理インタフェースを徹底的に保護しな ければなりません。これらは、ユーザーになりすまし、ユーザーと同じようにウェブアプリケーションを見ることによって、 Session に関連する問題、あるいは一般的な問題を解決するために、サポート担当者が頻繁に使用します。

The session logs become one of the main web application intrusion detection data sources, and can also be used by intrusion protection systems to automatically terminate sessions and/or disable user accounts when (one or many) attacks are detected. If active protections are implemented, these defensive actions must be logged too.

Session ログは、ウェブアプリケーション侵入検知の主要なデータソースの 1 つとなり、侵入防御システムによって、(1 つまたは多数の)攻撃が検知されたときに、 Session を自動的に終了させたり、ユーザーアカウントを無効にしたりするために使用することもできます。アクティブな保護が実装されている場合、これらの防御動作もログに記録する必要があります。


### Simultaneous Session Logons

It is the web application design decision to determine if multiple simultaneous logons from the same user are allowed from the same or from different client IP addresses. If the web application does not want to allow simultaneous session logons, it must take effective actions after each new authentication event, implicitly terminating the previously available session, or asking the user (through the old, new or both sessions) about the session that must remain active.

同じクライアント IP アドレスから、または異なるクライアント IP アドレスから、同じユーザーによる複数の同時ログオンを許可するかどうかを決定するのは、 Web アプリケーションの設計上の決定事項です。 Session の同時ログオンを許可しない場合、 Web アプリケーションは新しい認証イベントの後に効果的なアクションを取る必要があり、以前に利用可能だった Session を暗黙のうちに終了させるか、(古い、新しい、または両方の Session を通して)アクティブなままでなければならない Session についてユーザーに尋ねる。

It is recommended for web applications to add user capabilities that allow checking the details of active sessions at any time, monitor and alert the user about concurrent logons, provide user features to remotely terminate sessions manually, and track account activity history (logbook) by recording multiple client details such as IP address, User-Agent, login date and time, idle time, etc.

Web アプリケーションでは、アクティブな Session の詳細をいつでも確認できるユーザー機能を追加すること、同時ログオンについて監視し警告すること、 Session をリモートで手動終了させるユーザー機能を提供すること、 IP アドレス、ユーザーエージェント、ログイン日時、アイドル時間などの複数のクライアント情報を記録してアカウントの活動履歴(ログブック)を追跡することが推奨されます。


## Session Management WAF Protections

There are situations where the web application source code is not available or cannot be modified, or when the changes required to implement the multiple security recommendations and best practices detailed above imply a full redesign of the web application architecture, and therefore, cannot be easily implemented in the short term.

ウェブアプリケーションのソースコードが入手できない、または修正できない、あるいは、上記で詳述した複数のセキュリティ勧告やベストプラクティスを実施するために必要な変更が、ウェブアプリケーションのアーキテクチャの完全な再設計を意味し、したがって短期間で容易に実施できない状況もある。

In these scenarios, or to complement the web application defenses, and with the goal of keeping the web application as secure as possible, it is recommended to use external protections such as Web Application Firewalls (WAFs) that can mitigate the session management threats already described.

このようなシナリオでは、あるいはウェブアプリケーションの防御を補完し、ウェブアプリケーションを可能な限り安全に保つことを目的として、すでに説明した Session 管理の脅威を軽減できるウェブアプリケーションファイアウォール(WAF)などの外部保護を使用することが推奨されます。

Web Application Firewalls offer detection and protection capabilities against session based attacks. On the one hand, it is trivial for WAFs to enforce the usage of security attributes on cookies, such as the `Secure` and `HttpOnly` flags, applying basic rewriting rules on the `Set-Cookie` header for all the web application responses that set a new cookie.

ウェブアプリケーションファイアウォールは、 Session ベースの攻撃に対する検出と保護の機能を提供します。一方、 WAF が `Secure` や `HttpOnly` フラグのような Cookie のセキュリティ属性の使用を強制するのは簡単で、新しい Cookie を設定するすべてのウェブアプリケーションの応答に対して `Set-Cookie` ヘッダーの基本的な書き換え規則を適用します。

On the other hand, more advanced capabilities can be implemented to allow the WAF to keep track of sessions, and the corresponding session IDs, and apply all kind of protections against session fixation (by renewing the session ID on the client-side when privilege changes are detected), enforcing sticky sessions (by verifying the relationship between the session ID and other client properties, like the IP address or User-Agent), or managing session expiration (by forcing both the client and the web application to finalize the session).

一方、より高度な機能を実装することで、 WAF が Session と対応する Session ID を追跡し、 Session の固定化(特権の変更が検出された場合にクライアント側で Session ID を更新する)、スティッキー Session(Session ID と IP アドレスやユーザーエージェントなど他のクライアントプロパティの関係を検証する)、 Session 満了(クライアントとウェブアプリケーションの両方で Session を終了させる)を防止するあらゆる保護を適用できるようになります。

The open-source ModSecurity WAF, plus the OWASP [Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/), provide capabilities to detect and apply security cookie attributes, countermeasures against session fixation attacks, and session tracking features to enforce sticky sessions.

オープンソースの ModSecurity WAF に加え、 OWASP [Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/)により、セキュリティ Cookie 属性の検出と適用、 Session 固定化攻撃への対策、スティッキー Session を強制する Session トラッキング機能などを提供します。