'use strict';

import * as URLSafeBase64 from "urlsafe-base64";

enum Protocol {
    DNSCrypt = 0x01,
    DOH,
    DOT,
    Plain,
    ODOH,
    AnonymizedRelay = 0x81,
    ODOHRelay = 0x85,
}

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

        // Creates a new DNSCrypt stamp.
        //
        // @param addr is the IP address, as a string, with a port number if the
        // server is not accessible over the standard port for the protocol
        // (443). IPv6 strings must be included in square brackets:
        // [fe80::6d6d:f72c:3ad:60b8]. Scopes are permitted.
        constructor(readonly addr: string, init?: Partial<DNSCrypt>) {
            Object.assign(this, init);
        }

        public toString() {
            let props = this.props.toNumber();
            let addr = this.addr.split("").map(c => c.charCodeAt(0));

            let v = [Protocol.DNSCrypt, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            v.push(addr.length, ...addr);
            let pk = Buffer.from(this.pk.replace(/[: \t]/g, ""), "hex");
            v.push(pk.length, ...pk);
            let providerName = this.providerName.split("").map(c => c.charCodeAt(0));
            v.push(providerName.length, ...providerName);
            return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
        }
    }

    export class ODOH {
        props = new Properties();

        // hostname is the server host name which will also be used as a SNI name.
        // If the host name contains characters outside the URL-permitted range,
        // these characters should be sent as-is, without any extra encoding
        // (neither URL-encoded nor punycode).
        hostName = "";

        // path is the absolute URI path, such as /.well-known/dns-query.
        path = "";

        // Creates a new Oblivious DNS over HTTPS stamp.
        //
        // @param addr is the IP address of the server.It can be an empty
        // string, or just a port number, represented with a preceding colon
        // (:443). In that case, the host name will be resolved to an IP address
        // using another resolver.
        constructor(init?: Partial<ODOH>) {
            Object.assign(this, init);
        }

        public toString(): string {
            let props = this.props.toNumber();

            let v = [Protocol.ODOH, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            let hostName = this.hostName.split("").map(c => c.charCodeAt(0));
            v.push(hostName.length, ...hostName);
            let path = this.path.split("").map(c => c.charCodeAt(0));
            v.push(path.length, ...path);
            return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
        }
    }

    export class DOH extends ODOH {
        // hashi is the SHA256 digest of one of the TBS certificate found in the
        // validation chain, typically the certificate used to sign the resolver’s
        // certificate. Multiple hashes can be provided for seamless rotations.
        hash = "";

        // Creates a new DNS over HTTPS stamp.
        //
        // @param addr is the IP address of the server.It can be an empty
        // string, or just a port number, represented with a preceding colon
        // (:443). In that case, the host name will be resolved to an IP address
        // using another resolver.
        constructor(readonly addr: string, init?: Partial<DOH>) {
            super(init);
            Object.assign(this, init);
        }

        public toString(): string {
            return this._toString(Protocol.DOH);
        }

        _toString (protocol: Protocol) {
            let props = this.props.toNumber();
            let addr = this.addr.split("").map(c => c.charCodeAt(0));

            let v = [protocol, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
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

    export class DOT {
        props = new Properties();

        // hostname hostname is the server host name which will also be used as
        // a SNI name.
        hostName = "";

        // hashi is the SHA256 digest of one of the TBS certificate found in the
        // validation chain, typically the certificate used to sign the resolver’s
        // certificate. Multiple hashes can be provided for seamless rotations.
        hash = "";

        // Creates a new DNS over TLS stamp.
        //
        // @param addr is the IP address of the server. It can be an empty
        // string, or just a port number. In that case, the host name will be
        // resolved to an IP address using another resolver. IPv6 strings must
        // be included in square brackets: [fe80::6d6d:f72c:3ad:60b8]. Scopes
        // are permitted.
        constructor(readonly addr: string, init?: Partial<DOT>) {
            Object.assign(this, init);
        }

        public toString(): string {
            let props = this.props.toNumber();
            let addr = this.addr.split("").map(c => c.charCodeAt(0));

            let v = [Protocol.DOT, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            v.push(addr.length, ...addr);
            let hash = Buffer.from(this.hash.replace(/[: \t]/g, ""), "hex");
            v.push(hash.length, ...hash);
            let hostName = this.hostName.split("").map(c => c.charCodeAt(0));
            v.push(hostName.length, ...hostName);
            return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
        }
    }

    export class Plain {
        props = new Properties();

        // Creates a new Plain DNS stamp.
        //
        // @param addr is the IP address of the server. It can be an empty
        // string, or just a port number. In that case, the host name will be
        // resolved to an IP address using another resolver. IPv6 strings must
        // be included in square brackets: [fe80::6d6d:f72c:3ad:60b8]. Scopes
        // are permitted.
        constructor(readonly addr: string, init?: Partial<Plain>) {
            Object.assign(this, init);
        }

        public toString(): string {
            let props = this.props.toNumber();
            let addr = this.addr.split("").map(c => c.charCodeAt(0));

            let v = [Protocol.Plain, props, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            v.push(addr.length, ...addr);
            return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
        }
    }

    export class AnonymizedRelay {
        addr: string;

        // Creates a new Plain DNS stamp.
        //
        // @param addr is the IP address of the server. It can be an empty
        // string, or just a port number. In that case, the host name will be
        // resolved to an IP address using another resolver. IPv6 strings must
        // be included in square brackets: [fe80::6d6d:f72c:3ad:60b8]. Scopes
        // are permitted.
        constructor(addr: string) {
            this.addr = addr;
        }

        public toString(): string {
            let addr = this.addr.split("").map(c => c.charCodeAt(0));

            let v = [Protocol.AnonymizedRelay];
            v.push(addr.length, ...addr);
            return `sdns://${URLSafeBase64.encode(Buffer.from(v))}`;
        }
    }

    export class ODOHRelay extends DOH {
        public toString(): string {
            return this._toString(Protocol.ODOHRelay);
        }
    }

    export function parse(stamp: string): Stamp {
        if (stamp.substr(0, 7) !== "sdns://") {
            throw new Error("invalid scheme");
        }
        let bin = URLSafeBase64.decode(stamp.substr(7));
        const type = bin[0];
        if (type === Protocol.AnonymizedRelay) {
            const addrLen = bin[1];
            const addr = bin.slice(2, 2 + addrLen).toString("utf-8");
            return new AnonymizedRelay(addr);
        }
        const props = new Properties({
            dnssec: !!((bin[1] >> 0) & 1),
            nolog: !!((bin[1] >> 1) & 1),
            nofilter: !!((bin[1] >> 2) & 1),
        });
        let i = 9;
        let addrLen = bin[i++];
        const addr = bin.slice(i, i + addrLen).toString("utf-8");
        i += addrLen;
        switch (type) {
            case Protocol.DNSCrypt: {
                let pkLen = bin[i++];
                const pk = bin.slice(i, i + pkLen).toString("hex");
                i += pkLen;
                let providerNameLen = bin[i++];
                const providerName = bin.slice(i, i + providerNameLen).toString("utf-8");
                return new DNSCrypt(addr, { props, pk, providerName });
            }
            case Protocol.DOH:
            case Protocol.ODOHRelay: {
                const hashLen = bin[i++];
                const hash = bin.slice(i, i + hashLen).toString("hex");
                i += hashLen;
                const hostNameLen = bin[i++];
                const hostName = bin.slice(i, i + hostNameLen).toString("utf-8");
                i += hostNameLen;
                const pathLen = bin[i++];
                const path = bin.slice(i, i + pathLen).toString("utf-8");
                if (type === Protocol.DOH) {
                    return new DOH(addr, { props, hash, hostName, path });
                } else {
                    return new ODOHRelay(addr, { props, hash, hostName, path });
                }
            }
            case Protocol.DOT: {
                const hashLen = bin[i++];
                const hash = bin.slice(i, i + hashLen).toString("hex");
                i += hashLen;
                const hostNameLen = bin[i++];
                const hostName = bin.slice(i, i + hostNameLen).toString("utf-8");
                i += hostNameLen;
                return new DOT(addr, { props, hash, hostName });
            }
            case Protocol.Plain: {
                return new Plain(addr, { props });
            }
            case Protocol.ODOH: {
                const pathLen = bin[i++];
                const path = bin.slice(i, i + pathLen).toString("utf-8");
                return new ODOH({ props, hostName: addr, path });
            }
        }

        throw new Error("unsupported protocol: " + bin[0]);
    }
}