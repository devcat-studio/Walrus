declare namespace Walrus {
    class WebAuth {
        realm: Uint8Array;
        serverPublicKey: Uint8Array;
        clientPublicKey: Uint8Array;
        clientSecretKey: Uint8Array;
        withRandomGenerator: (realm: Uint8Array, cb: (gen: RandomGenerator) => void) => void;
        constructor(params: string);
        makeSecret(userId: string, password: string, resolve: (secret: string) => void): void;
        decodeResult(result: string, resolve: (output: any) => void, reject: (reason: any) => void): void;
    }
    interface RandomGenerator {
        (nbytes: number): Uint8Array;
    }
}
