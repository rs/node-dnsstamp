'use strict';

import * as chai from 'chai';
import { DNSStamp } from './stamp';

const expect = chai.expect;

interface test {
    name: string;
    sdns: string;
    obj: DNSStamp.Stamp;
}

const tests: { [s: string]: Array<test> } = {
    'DNSCrypt': [
        {
            name: 'default values',
            sdns: 'sdns://AQcAAAAAAAAAAAAA',
            obj: new DNSStamp.DNSCrypt('', {}),
        },
        {
            name: 'with addr',
            sdns: 'sdns://AQcAAAAAAAAAA2ZvbwAA',
            obj: new DNSStamp.DNSCrypt('foo', {}),
        },
        {
            name: 'with pk',
            sdns: 'sdns://AQcAAAAAAAAAAAPwC6QA',
            obj: new DNSStamp.DNSCrypt('', {
                pk: 'f00ba4',
            }),
        },
        {
            name: 'with provider',
            sdns: 'sdns://AQcAAAAAAAAAAAADZm9v',
            obj: new DNSStamp.DNSCrypt('', {
                providerName: 'foo',
            }),
        },
        {
            name: 'all props false',
            sdns: 'sdns://AQAAAAAAAAAAAAAA',
            obj: new DNSStamp.DNSCrypt('', {
                props: new DNSStamp.Properties({
                    nofilter: false,
                    nolog: false,
                    dnssec: false,
                }),
            }),
        },
    ],
    'DOH': [
        {
            name: 'default values',
            sdns: 'sdns://AgcAAAAAAAAAAAAAAA',
            obj: new DNSStamp.DOH('', {}),
        },
        {
            name: 'with addr',
            sdns: 'sdns://AgcAAAAAAAAAA2ZvbwAAAA',
            obj: new DNSStamp.DOH('foo', {}),
        },
        {
            name: 'with hostname',
            sdns: 'sdns://AgcAAAAAAAAAAAADZm9vAA',
            obj: new DNSStamp.DOH('', {
                hostName: 'foo',
            }),
        },
        {
            name: 'with hash',
            sdns: 'sdns://AgcAAAAAAAAAAAPwC6QAAA',
            obj: new DNSStamp.DOH('', {
                hash: 'f00ba4',
            }),
        },
        {
            name: 'with path',
            sdns: 'sdns://AgcAAAAAAAAAAAAABC9mb28',
            obj: new DNSStamp.DOH('', {
                path: '/foo',
            }),
        },
        {
            name: 'all props false',
            sdns: 'sdns://AgAAAAAAAAAAAAAAAA',
            obj: new DNSStamp.DOH('', {
                props: new DNSStamp.Properties({
                    nofilter: false,
                    nolog: false,
                    dnssec: false,
                }),
            }),
        },
    ],
    'DOT': [
        {
            name: 'default values',
            sdns: 'sdns://AwcAAAAAAAAAAAAA',
            obj: new DNSStamp.DOT('', {}),
        },
        {
            name: 'with addr',
            sdns: 'sdns://AwcAAAAAAAAAA2ZvbwAA',
            obj: new DNSStamp.DOT('foo', {}),
        },
        {
            name: 'with hostname',
            sdns: 'sdns://AwcAAAAAAAAAAAADZm9v',
            obj: new DNSStamp.DOT('', {
                hostName: 'foo',
            }),
        },
        {
            name: 'with hash',
            sdns: 'sdns://AwcAAAAAAAAAAAPwC6QA',
            obj: new DNSStamp.DOT('', {
                hash: 'f00ba4',
            }),
        },
        {
            name: 'all props false',
            sdns: 'sdns://AwAAAAAAAAAAAAAA',
            obj: new DNSStamp.DOT('', {
                props: new DNSStamp.Properties({
                    nofilter: false,
                    nolog: false,
                    dnssec: false,
                }),
            }),
        },
    ],
    'Plain': [
        {
            name: 'default values',
            sdns: 'sdns://BAcAAAAAAAAAAA',
            obj: new DNSStamp.Plain('', {}),
        },
        {
            name: 'with addr',
            sdns: 'sdns://BAcAAAAAAAAAA2Zvbw',
            obj: new DNSStamp.Plain('foo', {}),
        },
        {
            name: 'all props false',
            sdns: 'sdns://BAAAAAAAAAAAAA',
            obj: new DNSStamp.Plain('', {
                props: new DNSStamp.Properties({
                    nofilter: false,
                    nolog: false,
                    dnssec: false,
                }),
            }),
        },
    ],
    'ODOH': [
        {
            name: 'default values',
            sdns: 'sdns://BQcAAAAAAAAAAAA',
            obj: new DNSStamp.ODOH({
                hostName: '',
                path: ''
            })
        },
        {
            name: 'with hostName',
            sdns: 'sdns://BQcAAAAAAAAAA2ZvbwA',
            obj: new DNSStamp.ODOH({
                hostName: 'foo'
            })
        },
        {
            name: 'with path',
            sdns: 'sdns://BQcAAAAAAAAAAAQvZm9v',
            obj: new DNSStamp.ODOH({
                path: '/foo'
            })
        }
    ],
    'AnonymizedRelay': [
        {
            name: 'empty',
            sdns: 'sdns://gQA',
            obj: new DNSStamp.AnonymizedRelay('')
        },
        {
            name: 'with addr',
            sdns: 'sdns://gQNmb28',
            obj: new DNSStamp.AnonymizedRelay('foo')
        }
    ],
    'ODOHRelay': [
        {
            name: 'default values',
            sdns: 'sdns://hQcAAAAAAAAAAAAAAA',
            obj: new DNSStamp.ODOHRelay('', {}),
        },
        {
            name: 'with addr',
            sdns: 'sdns://hQcAAAAAAAAAA2ZvbwAAAA',
            obj: new DNSStamp.ODOHRelay('foo', {}),
        },
        {
            name: 'with hostname',
            sdns: 'sdns://hQcAAAAAAAAAAAADZm9vAA',
            obj: new DNSStamp.ODOHRelay('', {
                hostName: 'foo',
            }),
        },
        {
            name: 'with hash',
            sdns: 'sdns://hQcAAAAAAAAAAAPwC6QAAA',
            obj: new DNSStamp.ODOHRelay('', {
                hash: 'f00ba4',
            }),
        },
        {
            name: 'with path',
            sdns: 'sdns://hQcAAAAAAAAAAAAABC9mb28',
            obj: new DNSStamp.ODOHRelay('', {
                path: '/foo',
            }),
        },
        {
            name: 'all props false',
            sdns: 'sdns://hQAAAAAAAAAAAAAAAA',
            obj: new DNSStamp.ODOHRelay('', {
                props: new DNSStamp.Properties({
                    nofilter: false,
                    nolog: false,
                    dnssec: false,
                }),
            }),
        },
    ]
};

for (let cls in tests) {
    const testPairs = tests[cls];
    describe(cls, () => {
        describe('toString()', () => {
            testPairs.forEach(t => {
                it(t.name, () => {
                    expect(t.obj.toString()).to.be.equal(t.sdns);
                });
            });
        });
        describe('parse()', () => {
            testPairs.forEach(t => {
                it(t.name, () => {
                    expect(DNSStamp.parse(t.sdns)).to.be.deep.equal(t.obj);
                });
            });
        });
    });
}