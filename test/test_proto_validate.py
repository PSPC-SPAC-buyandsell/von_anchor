"""
Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from von_agent.proto.validate import validate

import pytest


GOOD = {
    'agent-nym-lookup': {
        'type': 'agent-nym-lookup',
        'data': {
            'agent-nym': {
                'did': 'abcd1234'
            }
        }
    },
    'agent-nym-send.proxy': {
        'type': 'agent-nym-send',
        'data': {
            'proxy-did': 'abcd1234',
            'agent-nym': {
                'did': 'abcd1234',
                'verkey': 'abcd234'
            }
        }
    },
    'agent-endpoint-lookup': {
        'type': 'agent-endpoint-lookup',
        'data': {
            'agent-endpoint': {
                'did': 'abcd1234'
            }
        }
    },
    'agent-endpoint-send.proxy': {
        'type': 'agent-endpoint-send',
        'data': {
            'proxy-did': 'abcd1234',
        }
    },
    'schema-lookup': {
        'type': 'schema-lookup',
        'data': {
            'schema': {
                'origin-did': 'abcd1234',
                'name': 'name',
                'version': '1.0'
            }
        }
    },
    'schema-send': {
        'type': 'schema-send',
        'data': {
            'schema': {
                'origin-did': 'abcd1234',
                'name': 'name',
                'version': '1.0'
            },
            'attr-names': [
                'attr0',
                'attr1',
                'attr2'
            ]
        }
    },
    'claim-def-send': {
        'type': 'claim-def-send',
        'data': {
            'schema': {
                'origin-did': 'abcd1234',
                'name': 'name',
                'version': '1.0'
            }
        }
    },
    'master-secret-set': {
        'type': 'master-secret-set',
        'data': {
            'label': 'abcd1234'
        }
    },
    'claim-hello.proxy': {
        'type': 'claim-hello',
        'data': {
            'proxy-did': 'abcd1234',
            'schema': {
                'origin-did': 'abcd1234',
                'name': 'name',
                'version': '1.0'
            },
            'issuer-did': 'abcd1234'
        }
    },
    'claim-create': {
        'type': 'claim-create',
        'data': {
            'claim-req': {
                'no': 'spec'
            },
            'claim-attrs': {
                'no': 'spec'
            }
        }
    },
    'claim-store.proxy': {
        'type': 'claim-store',
        'data': {
            'proxy-did': 'abcd1234',
            'claim': {
                'no': 'spec'
            }
        }
    },
    'claim-request.proxy.schemata.attr-match.pred-match.req-attrs': {
        'type': 'claim-request',
        'data': {
            'proxy-did': 'abcd1234',
            'schemata': [
                {
                    'origin-did': 'abcd1234',
                    'name': 'name',
                    'version': '1.0'
                },
                {
                    'origin-did': 'abcd1234',
                    'name': 'name',
                    'version': '1.1'
                }
            ],
            'claim-filter': {
                'attr-match': [
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.0'
                        },
                        'match': {
                            'attr0': 'value0',
                            'attr1': 'value1'
                        }
                    },
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.1'
                        },
                        'match': {
                            'attr0': 'value0',
                            'attr1': 'value1'
                        }
                    }
                ],
                'pred-match': [
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.0'
                        },
                        'match': [
                            {
                                'attr': 'attr0',
                                'pred-type': '>=',
                                'value': 0
                            },
                            {
                                'attr': 'attr1',
                                'pred-type': '>=',
                                'value': 1
                            }
                        ]
                    },
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.1'
                        },
                        'match': [
                            {
                                'attr': 'attr0',
                                'pred-type': '>=',
                                'value': 0
                            },
                            {
                                'attr': 'attr1',
                                'pred-type': '>=',
                                'value': 1
                            }
                        ]
                    }
                ]
            },
            'requested-attrs': [
                {
                    'schema': {
                        'origin-did': 'abcd1234',
                        'name': 'name',
                        'version': '1.0'
                    },
                    'names': [
                        'attr0',
                        'attr1'
                    ]
                }
            ]
        }
    },
    'claims-reset': {
        'type': 'claims-reset',
        'data': {
        }
    },
    'proof-request.proxy.schemata.attr-match.pred-match.req-attrs': {
        'type': 'proof-request',
        'data': {
            'proxy-did': 'abcd1234',
            'schemata': [
                {
                    'origin-did': 'abcd1234',
                    'name': 'name',
                    'version': '1.0'
                },
                {
                    'origin-did': 'abcd1234',
                    'name': 'name',
                    'version': '1.1'
                }
            ],
            'claim-filter': {
                'attr-match': [
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.0'
                        },
                        'match': {
                            'attr0': 'value0',
                            'attr1': 'value1'
                        }
                    },
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.1'
                        },
                        'match': {
                            'attr0': 'value0',
                            'attr1': 'value1'
                        }
                    }
                ],
                'pred-match': [
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.0'
                        },
                        'match': [
                            {
                                'attr': 'attr0',
                                'pred-type': '>=',
                                'value': 0
                            },
                            {
                                'attr': 'attr1',
                                'pred-type': '>=',
                                'value': 1
                            }
                        ]
                    },
                    {
                        'schema': {
                            'origin-did': 'abcd1234',
                            'name': 'name',
                            'version': '1.1'
                        },
                        'match': [
                            {
                                'attr': 'attr0',
                                'pred-type': '>=',
                                'value': 0
                            },
                            {
                                'attr': 'attr1',
                                'pred-type': '>=',
                                'value': 1
                            }
                        ]
                    }
                ]
            },
            'requested-attrs': [
                {
                    'schema': {
                        'origin-did': 'abcd1234',
                        'name': 'name',
                        'version': '1.0'
                    },
                    'names': [
                        'attr0',
                        'attr1'
                    ]
                }
            ]
        }
    },
    'proof-request-by-referent.proxy.schemata.req-attrs': {
        'type': 'proof-request-by-referent',
        'data': {
            'proxy-did': 'abcd1234',
            'schemata': [
                {
                    'origin-did': 'abcd1234',
                    'name': 'name',
                    'version': '1.0'
                },
                {
                    'origin-did': 'abcd1234',
                    'name': 'name',
                    'version': '1.1'
                }
            ],
            'referents': [
                'claim-0',
                'claim-1'
            ],
            'requested-attrs': [
                {
                    'schema': {
                        'origin-did': 'abcd1234',
                        'name': 'name',
                        'version': '1.0'
                    },
                    'names': [
                        'attr0',
                        'attr1'
                    ]
                }
            ]
        }
    },
    'verification-request.proxy': {
        'type': 'verification-request',
        'data': {
            'proxy-did': 'abcd1234',
            'proof-req': {
                'no': 'spec'
            },
            'proof': {
                'no': 'spec'
            }
        }
    }
}


BAD = {
    'bad-type': {
        'type': 'no-such-type',
        'data': {
        }
    },
    'no-data': {
        'type': 'claim-request'
    },
}


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_validate():
    for key in GOOD:
        message_type = GOOD[key]['type']
        print('\n\n== Validating good {} message'.format(message_type))
        validate(GOOD[key])
        if '.proxy' in key:
            proxy_did = GOOD[key]['data'].pop('proxy-did')
            print('\n\n== Validating good {} message without proxy-did'.format(message_type))
            validate(GOOD[key])
        if '.schemata' in key:
            schemata = GOOD[key]['data']['schemata']
            GOOD[key]['data']['schemata'] = []
            print('\n\n== Validating good {} message with empty schemata'.format(message_type))
            validate(GOOD[key])
            GOOD[key]['data']['schemata'] = schemata
        if '.attr-match' in key:
            match = GOOD[key]['data']['claim-filter']['attr-match']
            GOOD[key]['data']['claim-filter']['attr-match'] = []
            print('\n\n== Validating good {} message with empty attr-match'.format(message_type))
            validate(GOOD[key])
            GOOD[key]['data']['claim-filter']['attr-match'] = match
        if '.pred-match' in key:
            match = GOOD[key]['data']['claim-filter']['pred-match']
            GOOD[key]['data']['claim-filter']['pred-match'] = []
            print('\n\n== Validating good {} message with empty pred-match'.format(message_type))
            validate(GOOD[key])
            GOOD[key]['data']['claim-filter']['pred-match'] = match
        if '.req-attrs' in key:
            names = GOOD[key]['data']['requested-attrs'][0]['names']
            GOOD[key]['data']['requested-attrs'][0]['names'] = []
            print('\n\n== Validating good {} message with empty req-attrs.names'.format(message_type))
            validate(GOOD[key])
            GOOD[key]['data']['requested-attrs'][0]['names'] = names
            req_attrs = GOOD[key]['data']['requested-attrs']
            GOOD[key]['data']['requested-attrs'] = []
            print('\n\n== Validating good {} message with empty req-attrs'.format(message_type))
            validate(GOOD[key])
            GOOD[key]['data']['requested-attrs'] = req_attrs

        if len(GOOD[key]['data']) > 0:
            missing_attr = GOOD[key]['data'].popitem()[0]
            print('\n\n== Validating bad {} message missing {}'.format(message_type, missing_attr))
            try:
                validate(GOOD[key])
            except ValueError:
                pass

    for key in BAD:
        try:
            print('\n\n== Validating bad message, {}'.format(key))
            validate(BAD[key])
        except ValueError:
            pass
