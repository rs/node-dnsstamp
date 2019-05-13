'use strict';

import * as URLSafeBase64 from "urlsafe-base64";

export namespace DNSStamp {
    export class Properties {
        dnssec = true;
        nolog = true;
        nofilter = true;

        constructor(init?: Partial<Properties>) {
            Object.assign(this, init);
        }

        toNumber(): number {
            return ((this.dnssec ? 1 : 0) << 0) | ((this.nolog ? 1 : 0) << 1) | ((this.nofilter ? 1 : 0) << 2);
        }
    }

    export interface Stamp {
        toString(): string;
    }

    export class DNSCrypt {
        props = new Properties();
        // pk is the DNSCrypt provider’s Ed25519 public key, as 32 raw bytes.
        pk = "";
        // providerName is the DNSCrypt provider name.
        providerName = "";

        constructor(readonly addr: string, init?: Partial<DNSCrypt>) {
            Object.assign(this, init);
        }

        public toString() {
            let props = this.props.toNumber();
            let addr = this.addr.split("").map(c => c.charCodeAt(0));

            let v = [0x01, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            v.push(addr.length, ...addr);
            let pk = Buffer.from(this.pk.replace(/[: \t]/g, ""), "hex");
            v.push(pk.length, ...pk);
            let providerName = this.providerName.split("").map(c => c.charCodeAt(0));
            v.push(providerName.length, ...providerName);
            return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
        }
    }

    export class DOH {
        props = new Properties();

        // hostname is the server host name which will also be used as a SNI name.
        // If the host name contains characters outside the URL-permitted range,
        // these characters should be sent as-is, without any extra encoding
        // (neither URL-encoded nor punycode).
        hostName = "";

        // hashi is the SHA256 digest of one of the TBS certificate found in the
        // validation chain, typically the certificate used to sign the resolver’s
        // certificate. Multiple hashes can be provided for seamless rotations.
        hash = "";

        // path is the absolute URI path, such as /.well-known/dns-query.
        path = "";

        constructor(readonly addr: string, init?: Partial<DOH>) {
            Object.assign(this, init);
        }

        public toString(): string {
            let props = this.props.toNumber();
            let addr = this.addr.split("").map(c => c.charCodeAt(0));
  
            let v = [0x02, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            v.push(addr.length, ...addr);
            let hash = Buffer.from(this.hash.replace(/[: \t]/g, ""), "hex");
            v.push(hash.length, ...hash);
            let hostName = this.hostName.split("").map(c => c.charCodeAt(0));
            v.push(hostName.length, ...hostName);
            let path = this.path.split("").map(c => c.charCodeAt(0));
            v.push(path.length, ...path);
            return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
        }
    }

    export function parse(stamp: string): Stamp {
        if (stamp.substr(0, 7) !== "sdns://") {
            throw new Error("invalid scheme");
        }
        let bin = URLSafeBase64.decode(stamp.substr(7));
        const props = new Properties({
            dnssec: !!((bin[1] >> 0) & 1),
            nolog: !!((bin[1] >> 1) & 1),
            nofilter: !!((bin[1] >> 2) & 1),
        });
        let i = 9;
        let addrLen = bin[i++];
        const addr = bin.slice(i, i + addrLen).toString("utf-8");
        i += addrLen;
        if (bin[0] === 0x01) {
            // DNSCrypt
            let pkLen = bin[i++];
            const pk = bin.slice(i, i + pkLen).toString("hex");
            i += pkLen;
            let providerNameLen = bin[i++];
            const providerName = bin.slice(i, i + providerNameLen).toString("utf-8");
            return new DNSCrypt(addr, { props, pk, providerName });
        } else if (bin[0] === 0x02) {
            // DoH
            const hashLen = bin[i++];
            const hash = bin.slice(i, i + hashLen).toString("hex");
            i += hashLen;
            const hostNameLen = bin[i++];
            const hostName = bin.slice(i, i + hostNameLen).toString("utf-8");
            i += hostNameLen;
            const pathLen = bin[i++];
            const path = bin.slice(i, i + pathLen).toString("utf-8");
            return new DOH(addr, { props, hash, hostName, path });
        }
        throw new Error("unsupported protocol: " + bin[0]);
    }
}