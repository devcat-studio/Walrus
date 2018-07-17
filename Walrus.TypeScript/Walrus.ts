namespace Walrus {
    // 이 선언이 앞에 있어야 한다! 안 그러면 WebAuth가 볼 방법이 없다.
    var withRandomGenerator: (realm: Uint8Array, cb: (gen: RandomGenerator) => void) => void;

    //-------------------------------------------------------------------------
    export class WebAuth {
        realm: Uint8Array;
        serverPublicKey: Uint8Array;
        clientPublicKey: Uint8Array;
        clientSecretKey: Uint8Array;
        withRandomGenerator: (realm: Uint8Array, cb: (gen: RandomGenerator) => void) => void;

        constructor(params: string) {
            sanityCheck();

            let obj;
            try {
                obj = decodeParams(params);
            } catch (_) {
                throw new Error('bad parameters');
            }
            if (!obj) {
                throw new Error('bad parameters');
            }
            ({ realm: this.realm, serverPublicKey: this.serverPublicKey } = obj);

            // RNG는 실제로 콜백을 받을 수 있는 메소드가 나오기 전까지는 초기화가 지연된다.
            // 일단 초기화가 되면 있는 RandomGenerator를 계속 쓰도록 한다.
            this.withRandomGenerator = (realm, cb) => {
                withRandomGenerator(realm, gen => {
                    this.withRandomGenerator = (_, cb) => cb(gen);

                    // 이제 RNG를 쓸 수 있으니 키를 생성한다.
                    ({ publicKey: this.clientPublicKey, secretKey: this.clientSecretKey } = nacl.box.keyPair());

                    cb(gen);
                });
            };
        }

        makeSecret(userId: string, password: string, resolve: (secret: string) => void) {
            let id = utf8ToTypedArray(userId);
            let pw = utf8ToTypedArray(password);
            this.withRandomGenerator(this.realm, gen => {
                // h <- H(password, SILVERVINE_CLIENT || realm || userId)
                const SILVERVINE_CLIENT = [83, 105, 108, 118, 101, 114, 118, 105, 110, 101, 67, 108, 105, 101, 110, 116];
                let k = new Uint8Array(SILVERVINE_CLIENT.length + this.realm.length + id.length);
                k.set(SILVERVINE_CLIENT);
                k.set(this.realm, SILVERVINE_CLIENT.length);
                k.set(id, SILVERVINE_CLIENT.length + this.realm.length);
                let h = hmac(k, pw);

                let nonce = gen(nacl.box.nonceLength);
                let encrypted = nacl.box(h, nonce, this.serverPublicKey, this.clientSecretKey);

                let secret = new Uint8Array(6 + nacl.box.publicKeyLength * 2 + nacl.box.nonceLength + encrypted.length);
                secret.set([0x59, 0xa9, 0x6b, 0xba, 0xc4, 0xb5]);
                secret.set(this.serverPublicKey, 6);
                secret.set(this.clientPublicKey, 6 + nacl.box.publicKeyLength);
                secret.set(nonce, 6 + nacl.box.publicKeyLength * 2);
                secret.set(encrypted, 6 + nacl.box.publicKeyLength * 2 + nacl.box.nonceLength);
                return resolve(typedArrayToBase64(secret));
            });
        }

        decodeResultAsByteArray(result: string, resolve: (output: Uint8Array) => void, reject: (reason: any) => void) {
            let fail = () => reject(new Error('bad authentication result'));

            let obj;
            try {
                obj = decodeResult(result);
            } catch (e) {
                return fail();
            }
            if (!obj) {
                return fail();
            }

            let decrypted = nacl.box.open(obj.output, obj.nonce, this.serverPublicKey, this.clientSecretKey);
            if (!decrypted) {
                return fail();
            }
            return resolve(decrypted);
        }

        decodeResultAsString(result: string, resolve: (output: string) => void, reject: (reason: any) => void) {
            return this.decodeResultAsByteArray(result, output => {
                let string;
                try {
                    string = typedArrayToUtf8(output);
                } catch (e) {
                    return reject(e);
                }
                return resolve(string);
            }, reject);
        }
    }

    //-------------------------------------------------------------------------
    // 환경이 제대로 설정되어 있는지 확인하고 동작 테스트를 겸한다
    function sanityCheck() {
        if (typeof atob !== 'function') {
            throw new Error('missing environment support: atob');
        }
        if (typeof btoa !== 'function') {
            throw new Error('missing environment support: btoa');
        }
        if (typeof Uint8Array !== 'function') {
            throw new Error('missing environment support: Uint8Array');
        }
        if (typeof Generator !== 'function') {
            throw new Error('missing dependency: more-entropy');
        }
        if (typeof nacl !== 'object') {
            throw new Error('missing dependency: tweetnacl-js');
        }

        typedArrayTest();
        hmacTest();
    }

    function assertEq(a: string, b: string, why?: string): void;
    function assertEq(a: number, b: number, why?: string): void;
    function assertEq(a: Uint8Array | Array<number>, b: Uint8Array | Array<number>, why?: string): void;
    function assertEq(a: any, b: any, why?: string) {
        function equals(a: any, b: any): boolean {
            if (typeof a !== typeof b) return false;
            if (typeof a === 'object') {
                // 배열이어야 한다.
                return arrayEq(a, b);
            } else {
                return a === b;
            }
        }
        if (!equals(a, b)) {
            throw new Error('assertion failed' + (why ? ': ' + why : ''));
        }
    }

    function expectError(cb: () => void): void {
        try {
            cb();
        } catch (e) {
            return;
        }
        throw new Error('expected error, nothing happened');
    }

    //-------------------------------------------------------------------------
    function arrayEq(a: Uint8Array | Array<number>, b: Uint8Array | Array<number>): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; ++i) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    function readU32(a: Uint8Array | Array<number>, i: number): number {
        return (a[i] << 24) | (a[i + 1] << 16) | (a[i + 2] << 8) | a[i + 3];
    }

    function utf8ToTypedArray(s: string): Uint8Array {
        let out = [], p = 0;
        for (let i = 0; i < s.length; i++) {
            let c = s.charCodeAt(i), c2;
            if (c < 0x80) {
                out[p++] = c;
            } else if (c < 0x800) {
                out[p++] = (c >> 6) | 0xc0;
                out[p++] = (c & 0x3f) | 0x80;
            } else if ((c & 0xfc00) == 0xd800 && i + 1 < s.length && ((c2 = s.charCodeAt(i + 1)) & 0xfc00) == 0xdc00) {
                c = 0x10000 + ((c & 0x03ff) << 10) + (c2 & 0x03ff);
                ++i;
                out[p++] = (c >> 18) | 0xf0;
                out[p++] = ((c >> 12) & 0x3f) | 0x80;
                out[p++] = ((c >> 6) & 0x3f) | 0x80;
                out[p++] = (c & 0x3f) | 0x80;
            } else {
                out[p++] = (c >> 12) | 0xe0;
                out[p++] = ((c >> 6) & 0x3f) | 0x80;
                out[p++] = (c & 0x3f) | 0x80;
            }
        }
        return new Uint8Array(out);
    }

    function typedArrayToUtf8(a: Uint8Array | Array<number>): string {
        let out = [], p = 0;
        for (let i = 0; i < a.length;) {
            let c = a[i++], c2, c3, c4;
            if (c < 0x80) {
                out[p++] = c;
            } else if (c < 0xc2) {
                throw 'invalid UTF-8';
            } else if (c < 0xe0) {
                if (i + 1 > a.length || ((c2 = a[i++]) & 0xc0) != 0x80) throw 'invalid UTF-8';
                out[p++] = ((c & 0x1f) << 6) | (c2 & 0x3f);
            } else if (c < 0xf0) {
                if (i + 2 > a.length || ((c2 = a[i++]) & 0xc0) != 0x80 || ((c3 = a[i++]) & 0xc0) != 0x80) throw 'invalid UTF-8';
                c = ((c & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f);
                if (c < 0x800 || (0xd800 <= c && c < 0xe000)) throw 'invalid UTF-8';
                out[p++] = c;
            } else if (c < 0xf5) {
                if (i + 3 > a.length || ((c2 = a[i++]) & 0xc0) != 0x80 || ((c3 = a[i++]) & 0xc0) != 0x80 || ((c4 = a[i++]) & 0xc0) != 0x80) throw 'invalid UTF-8';
                c = (((c & 0x07) << 18) | ((c2 & 0x3f) << 12) | ((c3 & 0x3f) << 6) | (c4 & 0x3f)) - 0x10000;
                if (c < 0 || c >= 0x100000) throw 'invalid UTF-8';
                out[p++] = 0xd800 + (c >> 10);
                out[p++] = 0xdc00 + (c & 0x03ff);
            } else {
                throw 'invalid UTF-8';
            }
        }
        return String.fromCharCode.apply(null, out);
    }

    function typedArrayToBase64(a: Uint8Array | Array<number>): string {
        return btoa(String.fromCharCode.apply(null, a));
    }

    function base64ToTypedArray(s: string): Uint8Array {
        // 우스울 수 있겠지만 atob의 오류 처리는 우리가 원하는 것만큼 빡세지 않다.
        // 정규식으로 잘못된 패딩, 공백 등을 모두 잡아 낸다.
        if (!s.match(/^(?:[0-9A-Za-z+/]{4})*(?:[0-9A-Za-z+/][AQgw]==|[0-9A-Za-z+/]{2}[048AEIMQUYcgkosw]=)?$/)) {
            throw new Error('bad base64 input');
        }

        let b = atob(s);
        let buf = new Uint8Array(b.length);
        for (let i = 0; i < b.length; ++i) {
            buf[i] = b.charCodeAt(i);
        }
        return buf;
    }

    function typedArrayTest() {
        let doubleCheckUtf8 = (utf8: Array<number>, s: string) => {
            assertEq(typedArrayToUtf8(new Uint8Array(utf8)), s);
            assertEq(utf8ToTypedArray(s), utf8);
        };

        doubleCheckUtf8([94, 95, 94], '^_^');
        doubleCheckUtf8([127], '\x7f');
        doubleCheckUtf8([194, 128], '\x80');
        doubleCheckUtf8([209, 129, 208, 190, 209, 128, 208, 190, 208, 186, 32, 208, 180, 208, 178, 208, 176], 'сорок два');
        doubleCheckUtf8([223, 191], '\u07ff');
        doubleCheckUtf8([224, 160, 128], '\u0800');
        doubleCheckUtf8([236, 149, 136, 235, 133, 149, 63], '안녕?');
        doubleCheckUtf8([239, 191, 191], String.fromCharCode(0xffff)); // 일부 브라우저(특히 IE)에서 리터럴에 나오는 U+FFFE/F를 U+FFFD로 치환함
        doubleCheckUtf8([240, 144, 128, 128], '\ud800\udc00');
        doubleCheckUtf8([240, 159, 146, 169], '💩');
        doubleCheckUtf8([244, 143, 191, 191], '\udbff\udfff');

        assertEq(utf8ToTypedArray('\udc00\ud800'), [237, 176, 128, 237, 160, 128]); // 깨진 서로게이트는 잘못된 UTF-8로 나옴

        let expectErrorTestsUtf8 = [
            [0x80],
            [0xbf],
            [0xc0],
            [0xc1],
            [0xc2],
            [0xc2, 0x7f],
            [0xc2, 0xc0],
            [0xdf],
            [0xe0],
            [0xe0, 0x80],
            [0xe0, 0x80, 0x80],
            [0xe0, 0x9f, 0xbf],
            [0xe1],
            [0xe1, 0x80],
            [0xe1, 0x7f, 0x80],
            [0xe1, 0xc0, 0x80],
            [0xe1, 0x80, 0x7f],
            [0xe1, 0x80, 0xc0],
            [0xed, 0xa0, 0x80], // 서로게이트 시작
            [0xed, 0xbf, 0xbf], // 서로게이트 끝
            [0xef],
            [0xef, 0xbf],
            [0xf0],
            [0xf0, 0x80],
            [0xf0, 0x80, 0x80],
            [0xf0, 0x80, 0x80, 0x80],
            [0xf0, 0x8f, 0xbf, 0xbf],
            [0xf1],
            [0xf1, 0x80],
            [0xf1, 0x80, 0x80],
            [0xf1, 0x7f, 0x80, 0x80],
            [0xf1, 0xc0, 0x80, 0x80],
            [0xf1, 0x80, 0x7f, 0x80],
            [0xf1, 0x80, 0xc0, 0x80],
            [0xf1, 0x80, 0x80, 0x7f],
            [0xf1, 0x80, 0x80, 0xc0],
            [0xf4],
            [0xf4, 0x8f],
            [0xf4, 0x8f, 0xbf],
            [0xf4, 0x90, 0x80, 0x80],
            [0xf5],
            [0xff],
        ];
        for (let test of expectErrorTestsUtf8) {
            expectError(() => typedArrayToUtf8(test));
        }

        let doubleCheckBase64 = (arr: Array<number>, base64: string) => {
            assertEq(typedArrayToBase64(new Uint8Array(arr)), base64);
            assertEq(base64ToTypedArray(base64), arr);
        };
        doubleCheckBase64([], '');
        doubleCheckBase64([1], 'AQ==');
        doubleCheckBase64([42], 'Kg==');
        doubleCheckBase64([0, 255], 'AP8=');
        doubleCheckBase64([255, 0], '/wA=');
        doubleCheckBase64([0, 255, 0], 'AP8A');
        doubleCheckBase64([255, 0, 255], '/wD/');
        doubleCheckBase64([12, 34, 56], 'DCI4');
        doubleCheckBase64([12, 34, 56, 78], 'DCI4Tg==');
        doubleCheckBase64([12, 34, 56, 78, 90], 'DCI4Tlo=');
        doubleCheckBase64([251, 239, 190, 251, 239, 190], '++++++++');
        doubleCheckBase64([255, 255, 255, 255, 255, 255], '////////');

        let expectErrorTestsBase64 = [
            '!',
            'A',
            'B',
            'AB',
            'AP',
            'AAB',
            'AAD',
            'AAD',
            '====',
            'A===',
            'B===',
            'AB==',
            'AP==',
            'AAB=',
            'AAD=',
            'AAD=',
            'AAAA====',
            'AP8=/wA=',
            'AP 8',
            'AP 8=',
        ];
        for (let test of expectErrorTestsBase64) {
            expectError(() => base64ToTypedArray(test));
        }
    }

    //-------------------------------------------------------------------------
    // HMAC-SHA512 (프로토콜 및 HMAC-DRBG 용으로 사용)
    function hmac(k: Uint8Array, m: Uint8Array): Uint8Array {
        const BLOCKSIZE = 1024 / 8;
        if (k.length > BLOCKSIZE) {
            k = nacl.hash(k);
        }
        let inner = new Uint8Array(BLOCKSIZE + m.length);
        let outer = new Uint8Array(BLOCKSIZE + nacl.hash.hashLength);
        for (let i = 0; i < BLOCKSIZE; ++i) {
            let ki = k[i] || 0;
            inner[i] = 0x36 ^ ki;
            outer[i] = 0x5c ^ ki;
        }
        inner.set(m, BLOCKSIZE);
        outer.set(nacl.hash(inner), BLOCKSIZE);
        return nacl.hash(outer);
    }

    // RFC 4868에서 가져온 테스트 벡터 (근데 AUTH512-4에 오류 있음... errata 참고)
    function hmacTest() {
        function chk(k: string, m: string, h: string) {
            assertEq(hmac(base64ToTypedArray(k), base64ToTypedArray(m)), base64ToTypedArray(h));
        }

        chk('CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==',
            'SGkgVGhlcmU=',
            'Y37cbgHc5+Z0KplFGq6C3yPaPpJDnlkOQ+dhsz6RD7isKHjr1YA/bwth285eJR/4eJpHIsG+Za6kX9Rk6J+PWw==');
        chk('SmVmZUplZmVKZWZlSmVmZUplZmVKZWZlSmVmZUplZmVKZWZlSmVmZUplZmVKZWZlSmVmZUplZmVKZWZlSmVmZQ==',
            'd2hhdCBkbyB5YSB3YW50IGZvciBub3RoaW5nPw==',
            'yzcJF66KfOKM/R2PRwXWFBwXOyqTYsFd8jXfslGxVFRqozSun7mvwhhJMthpXjl7+g/7k0Zs/M6q44yDO326OA==');
        chk('qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqg==',
            '3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0=',
            'Lues14NiTKk5hxDz7gWuQbn5sFEMh+SeWGzJv5YXM9hiPHtVzr78zwLVWBrMHJ1fsf9ood5FUJ++TamkM5ImVQ==');
        chk('AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QA==',
            'zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0=',
            'XmaI5aPa7IJsoy6uoiTv9ecAYolHRw4TrQEwJWG6sQi4xIy8a4B9z72FBSGmhbq8fq5KKi5mDcDoa5MdZVA/0g==');
    }

    //-------------------------------------------------------------------------
    const RESEED_INTERVAL: number = 0x1000000000000;

    class HmacDrbg {
        k: Uint8Array;
        v: Uint8Array;
        counter: number;

        constructor(seed: Uint8Array) {
            this.k = new Uint8Array(nacl.hash.hashLength);
            this.v = new Uint8Array(nacl.hash.hashLength);
            for (let i = 0; i < nacl.hash.hashLength; ++i) {
                this.k[i] = 0x00;
                this.v[i] = 0x01;
            }
            this.reseed(seed);
        }

        private update(input?: Uint8Array): void {
            let vpad = new Uint8Array(this.v.length + 1 + (input ? input.length : 0));
            vpad.set(this.v, 0);
            vpad[this.v.length] = 0x00;
            if (input) {
                vpad.set(input, this.v.length + 1);
            }

            this.k = hmac(this.k, vpad);
            this.v = hmac(this.k, this.v);
            if (input) {
                vpad.set(this.v, 0);
                vpad[this.v.length] = 0x01;
                this.k = hmac(this.k, vpad);
                this.v = hmac(this.k, this.v);
            }
        }

        // SHA-512의 최대 security_strength는 256비트 = 32바이트인데
        // HMAC-DRBG는 최소 3/2 security_strength = 48바이트만큼의 엔트로피가 시드에 필요함
        // (무조건 엔트로피에서 나와야 하는 32바이트 + 엔트로피에서 나와도 되는 nonce 16바이트)
        static readonly MIN_SEED_LENGTH = 48;

        reseed(input: Uint8Array): void {
            if (input.length < HmacDrbg.MIN_SEED_LENGTH) {
                throw new Error('too small seed input');
            }

            this.update(input);
            this.counter = 1;
        }

        generate(length: number, input?: Uint8Array): Uint8Array {
            if (this.counter >= RESEED_INTERVAL) {
                throw new Error('reseed is required');
            }

            if (input) {
                this.update(input);
            }

            let buf = new Uint8Array(length);
            let limit = length - length % nacl.hash.hashLength;
            for (let i = 0; i < limit; i += nacl.hash.hashLength) {
                this.v = hmac(this.k, this.v);
                buf.set(this.v, i);
            }
            if (limit < length) {
                this.v = hmac(this.k, this.v);
                buf.set(this.v.subarray(0, length - limit), limit);
            }

            this.update(input);
            ++this.counter;
            return buf;
        }
    }

    //-------------------------------------------------------------------------
    export interface RandomGenerator {
        (nbytes: number): Uint8Array;
    }

    let cryptoImpl = (<any>window).crypto || (<any>window).msCrypto;
    if (cryptoImpl && cryptoImpl.getRandomValues) {
        // 지원하는 브라우저에서는 window.crypto.getRandomValues를 바로 쓴다.
        // TODO more-entropy도 함께 쓰는 게 좋을까?
        let getRandomValues = cryptoImpl.getRandomValues.bind(cryptoImpl);
        withRandomGenerator = (_, cb) => {
            cb(nbytes => {
                let buf = new Uint8Array(nbytes);
                getRandomValues(buf);
                return buf;
            });
        };
    } else {
        // 지원하지 않는 브라우저에서는 more-entropy 데이터를 시드로 쓴 RNG를 쓴다.
        withRandomGenerator = (realm, cb) => {
            let gen = new Generator();
            gen.generate(HmacDrbg.MIN_SEED_LENGTH * 8, bits => {
                // bits의 각 값에는 범위 제약이 없다. 따라서 이걸 무슨 바이트열로 바꾸지 않고,
                // bits의 문자열 표현 그 자체를 해시에 밀어 넣는다.
                // (MIN_SEED_LENGTH가 해시 출력보다 작으므로 한 번으로 충분하다.)
                let k = new Uint8Array(16 + realm.length); // "SilvervineRandom" || realm
                const SILVERVINE_RANDOM = [83, 105, 108, 118, 101, 114, 118, 105, 110, 101, 82, 97, 110, 100, 111, 109];
                k.set(SILVERVINE_RANDOM);
                k.set(realm, 16);

                let seed = new Uint8Array(hmac(k, utf8ToTypedArray(JSON.stringify(bits))), 0, HmacDrbg.MIN_SEED_LENGTH);
                let drbg = new HmacDrbg(seed);
                nacl.setPRNG((x, n) => x.set(drbg.generate(n)));
                cb(nbytes => drbg.generate(nbytes));
            });
        };
    }

    //-------------------------------------------------------------------------
    interface Params {
        realm: Uint8Array,
        serverPublicKey: Uint8Array,
    }

    function decodeParams(s: string): Params {
        let params = base64ToTypedArray(s);
        if (params.length < 10 + nacl.box.publicKeyLength) return null;
        if (!arrayEq(params.subarray(0, 6), [0x59, 0xa9, 0x6b, 0xba, 0xc3, 0xf5])) return null;
        let k = params.subarray(6, 6 + nacl.box.publicKeyLength);
        let rlen = readU32(params, 6 + nacl.box.publicKeyLength);
        let r = params.subarray(10 + nacl.box.publicKeyLength);
        if (r.length !== rlen) return null;
        return { realm: r, serverPublicKey: k };
    }

    interface Result {
        output: Uint8Array,
        nonce: Uint8Array,
    }

    function decodeResult(s: string): Result {
        let result = base64ToTypedArray(s);
        if (result.length < 6 + nacl.box.nonceLength + nacl.box.overheadLength) return null;
        if (!arrayEq(result.subarray(0, 6), [0x59, 0xa9, 0x6b, 0xba, 0xc4, 0x75])) return null;
        let n = result.subarray(6, 6 + nacl.box.nonceLength);
        let o = result.subarray(6 + nacl.box.nonceLength);
        return { output: o, nonce: n };
    }
}
