declare module 'fingerprintjs2' {
  interface Component {
    key: string;
    value: any;
  }

  export default class Fingerprint2 {
    static get(callback: (components: Component[]) => void): void;
    static get(options: any, callback: (components: Component[]) => void): void;
    static x64hash128(value: string, seed: number): string;
  }
}
