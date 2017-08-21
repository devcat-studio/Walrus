# Walrus (:3 っ)っ

**Walrus**, the Web Authentication Library for Relatively Unusual Situations, is a library for handling the password-based authentication primarily targeted for the web. Being named as "unusual", this library is useful only when:

- You want the end-to-end encryption without dealing with a complex architecture (e.g. certificate management can be difficult for internal servers); or

- You need a fallback scenario for the lower authentication and encryption layers being weakened for various reasons.

**All standard security measures like [TLS], [strict transport security][HSTS] and [public key pinning][HPKP] still apply**, primarily because in the web the trusted identity of the server can be established only by certificates (and thus the man-in-the-middle attack can be avoided). Still this library provides some additional layer when they are weakened; for example, the non-targeted MITM environment over the TLS is quite common and Walrus can be used in that situation.

[TLS]: https://en.wikipedia.org/wiki/Transport_Layer_Security
[HSTS]: https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
[HPKP]: https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning

In addition to the authentication process, it provides a simple mechanism for the secure password storage based on [scrypt]. Its client-side component also includes a copy of [tweetnacl-js], a JavaScript port of [TweetNaCl] cryptography library, combined with the [more-entropy] library to provide the strong entropy source in any case. So the standalone version of Walrus can also function as a general cryptographic library bundle.

[scrypt]: https://github.com/Tarsnap/scrypt
[tweetnacl-js]: https://github.com/dchest/tweetnacl-js
[TweetNaCl]: http://tweetnacl.cr.yp.to/
[more-entropy]: https://github.com/keybase/more-entropy

## Usage

In the server side, build the entire solution (produces both static and dynamic libraries) and run the [`Walrus.Sample.Python`](Walrus.Sample.Python/) directory to see the usage and demonstration. It has been tested on Python 3.6, but the binding is a proof of concept and the library itself is in C. The actual API description is available as comments to [`walrus.h`](Walrus/walrus.h), currently only in Korean.

In the client side, build the [`Walrus.TypeScript`](Walrus.TypeScript/) project (you will need TypeScript 2.3 or later, Visual Studio usage is optional) to get the nicely packaged [`Walrus.standalone.min.js`](Walrus.TypeScript/bin/Walrus.standalone.min.js).

The library is inherently platform-independent, but there is no non-Windows build support at this moment. Your mileage may vary.

