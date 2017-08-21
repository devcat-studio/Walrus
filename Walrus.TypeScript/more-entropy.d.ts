// Type definitions for more-entropy

declare class Generator {
    constructor(opts?: Generator.Options);
    readonly running: boolean;
    readonly is_generating: boolean;
    generate(bits_wanted: number, cb: (bits: Array<number>) => void): void;
    stop(): void;
    resume(): void;
    reset(): void;
    count_unused_bits(): number;
}

declare namespace Generator {
    export interface Options {
        lazy_loop_delay?: number;
        loop_delay?: number;
        work_min?: number;
        auto_stop_bits?: number;
        max_bits_per_delta?: number;
        auto_stop?: boolean;
    }
}
