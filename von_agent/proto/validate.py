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

from von_agent.error import JSONValidation, ProxyRelayConfig

import json
import jsonschema

PROTO_MSG_JSON_SCHEMA = {
    'agent-nym-lookup': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'agent-nym-lookup'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'agent-nym': {
                        'type': 'object',
                        'properties': {
                            'did': {
                                'type': 'string'
                            }
                        },
                        'required': ['did'],
                        'additionalProperties': False
                    }
                },
                'required': ['agent-nym'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'agent-nym-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'agent-nym-send'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'agent-nym': {
                        'type': 'object',
                        'properties': {
                            'did': {
                                'type': 'string'
                            },
                            'verkey': {
                                'type': 'string'
                            }
                        },
                        'required': ['did', 'verkey'],
                        'additionalProperties': False
                    }
                },
                'required': ['agent-nym'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'agent-endpoint-lookup': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'agent-endpoint-lookup'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'agent-endpoint': {
                        'type': 'object',
                        'properties': {
                            'did': {
                                'type': 'string'
                            }
                        },
                        'required': ['did'],
                        'additionalProperties': False
                    }
                },
                'required': ['agent-endpoint'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'agent-endpoint-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'agent-endpoint-send'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    }
                },
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'schema-lookup': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'schema-lookup'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'origin-did': {
                                'type': 'string'
                            },
                            'name': {
                                'type': 'string'
                            },
                            'version': {
                                'type': 'string'
                            },
                        },
                        'required': ['origin-did', 'name', 'version'],
                        'additionalProperties': False
                    },
                },
                'required': ['schema'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'schema-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'schema-send'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'origin-did': {
                                'type': 'string'
                            },
                            'name': {
                                'type': 'string'
                            },
                            'version': {
                                'type': 'string'
                            },
                        },
                        'required': ['origin-did', 'name', 'version'],
                        'additionalProperties': False
                    },
                    'attr-names': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        },
                        'minItems': 0
                    }
                },
                'required': ['schema', 'attr-names'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'claim-def-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'claim-def-send'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'origin-did': {
                                'type': 'string'
                            },
                            'name': {
                                'type': 'string'
                            },
                            'version': {
                                'type': 'string'
                            },
                        },
                        'required': ['origin-did', 'name', 'version'],
                        'additionalProperties': False
                    },
                },
                'required': ['schema'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'master-secret-set': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'master-secret-set'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'label': {
                        'type': 'string'
                    },
                },
                'required': ['label'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'claim-offer-create': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'claim-offer-create'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'origin-did': {
                                'type': 'string'
                            },
                            'name': {
                                'type': 'string'
                            },
                            'version': {
                                'type': 'string'
                            },
                        },
                        'required': ['origin-did', 'name', 'version'],
                        'additionalProperties': False
                    },
                    'holder-did': {
                        'type': 'string'
                    }
                },
                'required': ['schema', 'holder-did'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'claim-offer-store': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'claim-offer-store'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'claim-offer': {
                        'type': 'object',
                        'properties': {
                            'issuer_did': {
                                'type': 'string'
                            },
                            'nonce': {
                                'type': 'string'
                            },
                            'schema_key': {
                                'type': 'object',
                                'properties': {
                                    'did': {
                                        'type': 'string'
                                    },
                                    'name': {
                                        'type': 'string'
                                    },
                                    'version': {
                                        'type': 'string'
                                    }
                                },
                                'required': ['did', 'name', 'version'],
                                'additionalProperties': False
                            },
                            'key_correctness_proof': {
                                'type': 'object'
                            }
                        },
                        'required': ['issuer_did', 'nonce', 'schema_key', 'key_correctness_proof'],
                        'additionalProperties': False
                    }
                },
                'required': ['claim-offer'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'claim-create': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'claim-create'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'claim-req': {
                        'type': 'object'
                    },
                    'claim-attrs': {
                        'type': 'object'
                    }
                },
                'required': ['claim-req', 'claim-attrs'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'claim-store': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'claim-store'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'claim': {
                        'type': 'object'
                    },
                },
                'required': ['claim'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'claim-request': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'claim-request'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'schemata': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'origin-did': {
                                    'type': 'string'
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'version': {
                                    'type': 'string'
                                },
                            },
                            'required': ['origin-did', 'name', 'version'],
                            'additionalProperties': False
                        },
                        'minItems': 0
                    },
                    'claim-filter': {
                        'type': 'object',
                        'properties': {
                            'attr-match': {
                                'type': 'array',
                                'items': {
                                    'type': 'object',
                                    'properties': {
                                        'schema': {
                                            'type': 'object',
                                            'properties': {
                                                'origin-did': {
                                                    'type': 'string'
                                                },
                                                'name': {
                                                    'type': 'string'
                                                },
                                                'version': {
                                                    'type': 'string'
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version'],
                                            'additionalProperties': False
                                        },
                                        'match': {
                                            'type': 'object'
                                        }
                                    },
                                    'required': ['schema', 'match'],
                                    'additionalProperties': False
                                },
                                'minItems': 0
                            },
                            'pred-match': {
                                'type': 'array',
                                'items': {
                                    'type': 'object',
                                    'properties': {
                                        'schema': {
                                            'type': 'object',
                                            'properties': {
                                                'origin-did': {
                                                    'type': 'string'
                                                },
                                                'name': {
                                                    'type': 'string'
                                                },
                                                'version': {
                                                    'type': 'string'
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version'],
                                            'additionalProperties': False
                                        },
                                        'match': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'object',
                                                'properties': {
                                                    'attr': {
                                                        'type': 'string'
                                                    },
                                                    'pred-type': {
                                                        'type': 'string'
                                                    },
                                                    'value': {
                                                        'type': 'integer'
                                                    }
                                                },
                                                'required': ['attr', 'pred-type', 'value'],
                                                'additionalProperties': False
                                            },
                                            'minItems': 1
                                        }
                                    },
                                    'required': ['schema', 'match']
                                },
                                'minItems': 0
                            }
                        },
                        'required': ['attr-match', 'pred-match'],
                        'additionalProperties': False
                    },
                    'requested-attrs': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'origin-did': {
                                            'type': 'string'
                                        },
                                        'name': {
                                            'type': 'string'
                                        },
                                        'version': {
                                            'type': 'string'
                                        },
                                    },
                                    'required': ['origin-did', 'name', 'version'],
                                    'additionalProperties': False
                                },
                                'names': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    },
                                    'minItems': 0
                                },
                            },
                            'required': ['schema', 'names'],
                            'additionalProperties': False
                        },
                        'minItems': 0,
                    }
                },
                'required': ['schemata', 'claim-filter', 'requested-attrs'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'claims-reset': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'claims-reset'
            },
            'data': {
                'type': 'object'
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'proof-request': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'proof-request'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'schemata': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'origin-did': {
                                    'type': 'string'
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'version': {
                                    'type': 'string'
                                },
                            },
                            'required': ['origin-did', 'name', 'version'],
                            'additionalProperties': False
                        },
                        'minItems': 0
                    },
                    'claim-filter': {
                        'type': 'object',
                        'properties': {
                            'attr-match': {
                                'type': 'array',
                                'items': {
                                    'type': 'object',
                                    'properties': {
                                        'schema': {
                                            'type': 'object',
                                            'properties': {
                                                'origin-did': {
                                                    'type': 'string'
                                                },
                                                'name': {
                                                    'type': 'string'
                                                },
                                                'version': {
                                                    'type': 'string'
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version'],
                                            'additionalProperties': False
                                        },
                                        'match': {
                                            'type': 'object'
                                        }
                                    },
                                    'required': ['schema', 'match'],
                                    'additionalProperties': False
                                },
                                'minItems': 0
                            },
                            'pred-match': {
                                'type': 'array',
                                'items': {
                                    'type': 'object',
                                    'properties': {
                                        'schema': {
                                            'type': 'object',
                                            'properties': {
                                                'origin-did': {
                                                    'type': 'string'
                                                },
                                                'name': {
                                                    'type': 'string'
                                                },
                                                'version': {
                                                    'type': 'string'
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version'],
                                            'additionalProperties': False
                                        },
                                        'match': {
                                            'type': 'array',
                                            'items': {
                                                'type': 'object',
                                                'properties': {
                                                    'attr': {
                                                        'type': 'string'
                                                    },
                                                    'pred-type': {
                                                        'type': 'string'
                                                    },
                                                    'value': {
                                                        'type': 'integer'
                                                    }
                                                },
                                                'required': ['attr', 'pred-type', 'value'],
                                                'additionalProperties': False
                                            },
                                            'minItems': 1
                                        }
                                    },
                                    'required': ['schema', 'match'],
                                    'additionalProperties': False
                                },
                                'minItems': 0
                            }
                        },
                        'required': ['attr-match', 'pred-match'],
                        'additionalProperties': False
                    },
                    'requested-attrs': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'origin-did': {
                                            'type': 'string'
                                        },
                                        'name': {
                                            'type': 'string'
                                        },
                                        'version': {
                                            'type': 'string'
                                        },
                                    },
                                    'required': ['origin-did', 'name', 'version'],
                                    'additionalProperties': False
                                },
                                'names': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    },
                                    'minItems': 0
                                },
                            },
                            'required': ['schema', 'names']
                        },
                        'minItems': 0,
                    }
                },
                'required': ['schemata', 'claim-filter', 'requested-attrs'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'proof-request-by-referent': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'proof-request-by-referent'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'schemata': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'origin-did': {
                                    'type': 'string'
                                },
                                'name': {
                                    'type': 'string'
                                },
                                'version': {
                                    'type': 'string'
                                },
                            },
                            'required': ['origin-did', 'name', 'version'],
                            'additionalProperties': False
                        },
                        'minItems': 0
                    },
                    'referents': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        },
                        'minItems': 1
                    },
                    'requested-attrs': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'origin-did': {
                                            'type': 'string'
                                        },
                                        'name': {
                                            'type': 'string'
                                        },
                                        'version': {
                                            'type': 'string'
                                        },
                                    },
                                    'required': ['origin-did', 'name', 'version'],
                                    'additionalProperties': False
                                },
                                'names': {
                                    'type': 'array',
                                    'items': {
                                        'type': 'string'
                                    },
                                    'minItems': 0
                                },
                            },
                            'required': ['schema', 'names'],
                            'additionalProperties': False
                        },
                        'minItems': 0,
                    }
                },
                'required': ['schemata', 'referents', 'requested-attrs'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    },

    'verification-request': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'pattern': 'verification-request'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    },
                    'proof-req': {
                        'type': 'object'
                    },
                    'proof': {
                        'type': 'object'
                    },
                },
                'required': ['proof-req', 'proof'],
                'additionalProperties': False
            }
        },
        'required': ['type', 'data'],
        'additionalProperties': False
    }
}


def validate(form: dict, proxy_relay: bool = True) -> None:
    """
    Validate input form; raise JSONValidation on non-compliance or silently pass.

    :param form: input form decoded from json
    :param proxy_relay: whether proxy-did is a valid property within form['data']
    """

    if 'type' not in form:
        raise JSONValidation("Bad form: missing 'type' key")
    if form['type'] not in PROTO_MSG_JSON_SCHEMA:
        raise JSONValidation("Bad form: type '{}' unsupported".format(form['type']))
    try:
        if (not proxy_relay) and ('data' in form) and ('proxy-did' in form['data']):
            raise ProxyRelayConfig('Agent is not a proxy relay')
        jsonschema.validate(form, PROTO_MSG_JSON_SCHEMA[form['type']])
    except jsonschema.ValidationError as e:
        raise JSONValidation('JSON validation error: {}'.format(e.message))
    except jsonschema.SchemaError as e:
        raise JSONValidation('JSON schema error: {}'.format(e.message))
