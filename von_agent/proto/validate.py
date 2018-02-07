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

import json
import jsonschema

PROTO_MSG_JSON_SCHEMA = {
    'agent-nym-lookup': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'agent-nym': {
                        'type': 'object',
                        'properties': {
                            'did': {
                                'type': 'string',
                            }
                        },
                        'required': ['did']
                    }
                },
                'required': ['agent-nym']
            }
        },
        'required': ['type', 'data']
    },

    'agent-nym-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
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
                                'type': 'string',
                            },
                            'verkey': {
                                'type': 'string',
                            }
                        },
                        'required': ['did', 'verkey']
                    }
                },
                'required': ['agent-nym']
            }
        },
        'required': ['type', 'data']
    },

    'agent-endpoint-lookup': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'agent-endpoint': {
                        'type': 'object',
                        'properties': {
                            'did': {
                                'type': 'string',
                            }
                        },
                        'required': ['did']
                    }
                },
                'required': ['agent-endpoint']
            }
        },
        'required': ['type', 'data']
    },

    'agent-endpoint-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'proxy-did': {
                        'type': 'string'
                    }
                }
            }
        },
        'required': ['type', 'data']
    },

    'schema-lookup': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'origin-did': {
                                'type': 'string',
                            },
                            'name': {
                                'type': 'string',
                            },
                            'version': {
                                'type': 'string',
                            },
                        },
                        'required': ['origin-did', 'name', 'version']
                    },
                },
                'required': ['schema']
            }
        },
        'required': ['type', 'data']
    },

    'schema-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'origin-did': {
                                'type': 'string',
                            },
                            'name': {
                                'type': 'string',
                            },
                            'version': {
                                'type': 'string',
                            },
                        },
                        'required': ['origin-did', 'name', 'version']
                    },
                    'attr-names': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        },
                        'minItems': 0
                    }
                },
                'required': ['schema', 'attr-names']
            }
        },
        'required': ['type', 'data']
    },

    'claim-def-send': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'origin-did': {
                                'type': 'string',
                            },
                            'name': {
                                'type': 'string',
                            },
                            'version': {
                                'type': 'string',
                            },
                        },
                        'required': ['origin-did', 'name', 'version']
                    },
                },
                'required': ['schema']
            }
        },
        'required': ['type', 'data']
    },

    'master-secret-set': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'label': {
                        'type': 'string'
                    },
                },
                'required': ['label']
            }
        },
        'required': ['type', 'data']
    },

    'claim-hello': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
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
                                'type': 'string',
                            },
                            'name': {
                                'type': 'string',
                            },
                            'version': {
                                'type': 'string',
                            },
                        },
                        'required': ['origin-did', 'name', 'version']
                    },
                    'issuer-did': {
                        'type': 'string'
                    }
                },
                'required': ['schema', 'issuer-did']
            }
        },
        'required': ['type', 'data']
    },

    'claim-create': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object',
                'properties': {
                    'claim-req': {
                        'type': 'object'
                    },
                    'claim-attrs': {
                        'type': 'object'
                    }
                },
                'required': ['claim-req', 'claim-attrs']
            }
        },
        'required': ['type', 'data']
    },

    'claim-store': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
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
                'required': ['claim']
            }
        },
        'required': ['type', 'data']
    },

    'claim-request': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
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
                                    'type': 'string',
                                },
                                'name': {
                                    'type': 'string',
                                },
                                'version': {
                                    'type': 'string',
                                },
                            },
                            'required': ['origin-did', 'name', 'version']
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
                                                    'type': 'string',
                                                },
                                                'name': {
                                                    'type': 'string',
                                                },
                                                'version': {
                                                    'type': 'string',
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version']
                                        },
                                        'match': {
                                            'type': 'object'
                                        }
                                    },
                                    'required': ['schema', 'match']
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
                                                    'type': 'string',
                                                },
                                                'name': {
                                                    'type': 'string',
                                                },
                                                'version': {
                                                    'type': 'string',
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version']
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
                                                'required': ['attr', 'pred-type', 'value']
                                            },
                                            'minItems': 1
                                        }
                                    },
                                    'required': ['schema', 'match']
                                },
                                'minItems': 0
                            }
                        },
                        'required': ['attr-match', 'pred-match']
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
                                            'type': 'string',
                                        },
                                        'name': {
                                            'type': 'string',
                                        },
                                        'version': {
                                            'type': 'string',
                                        },
                                    },
                                    'required': ['origin-did', 'name', 'version']
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
                'required': ['schemata', 'claim-filter', 'requested-attrs']
            }
        },
        'required': ['type', 'data']
    },

    'claims-reset': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
            },
            'data': {
                'type': 'object'
            }
        },
        'required': ['type', 'data']
    },

    'proof-request': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
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
                                    'type': 'string',
                                },
                                'name': {
                                    'type': 'string',
                                },
                                'version': {
                                    'type': 'string',
                                },
                            },
                            'required': ['origin-did', 'name', 'version']
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
                                                    'type': 'string',
                                                },
                                                'name': {
                                                    'type': 'string',
                                                },
                                                'version': {
                                                    'type': 'string',
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version']
                                        },
                                        'match': {
                                            'type': 'object'
                                        }
                                    },
                                    'required': ['schema', 'match']
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
                                                    'type': 'string',
                                                },
                                                'name': {
                                                    'type': 'string',
                                                },
                                                'version': {
                                                    'type': 'string',
                                                },
                                            },
                                            'required': ['origin-did', 'name', 'version']
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
                                                'required': ['attr', 'pred-type', 'value']
                                            },
                                            'minItems': 1
                                        }
                                    },
                                    'required': ['schema', 'match']
                                },
                                'minItems': 0
                            }
                        },
                        'required': ['attr-match', 'pred-match']
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
                                            'type': 'string',
                                        },
                                        'name': {
                                            'type': 'string',
                                        },
                                        'version': {
                                            'type': 'string',
                                        },
                                    },
                                    'required': ['origin-did', 'name', 'version']
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
                'required': ['schemata', 'claim-filter', 'requested-attrs']
            }
        },
        'required': ['type', 'data']
    },

    'proof-request-by-referent': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
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
                                    'type': 'string',
                                },
                                'name': {
                                    'type': 'string',
                                },
                                'version': {
                                    'type': 'string',
                                },
                            },
                            'required': ['origin-did', 'name', 'version']
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
                                            'type': 'string',
                                        },
                                        'name': {
                                            'type': 'string',
                                        },
                                        'version': {
                                            'type': 'string',
                                        },
                                    },
                                    'required': ['origin-did', 'name', 'version']
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
                'required': ['schemata', 'referents', 'requested-attrs']
            }
        },
        'required': ['type', 'data']
    },

    'verification-request': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string'
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
                'required': ['proof-req', 'proof']
            }
        },
        'required': ['type', 'data']
    }
}


def validate(form: dict) -> None:
    """
    Validate input form; raise ValueError on non-compliance or silently pass.

    :param form: input form decoded from json
    """

    if 'type' not in form:
        raise ValueError("Bad form: missing 'type' key")
    if form['type'] not in PROTO_MSG_JSON_SCHEMA: 
        raise ValueError("Bad form: type '{}' unsupported".format(form['type']))
    try:
        jsonschema.validate(form, PROTO_MSG_JSON_SCHEMA[form['type']])
    except jsonschema.ValidationError as e:
        raise ValueError('JSON validation error: {}'.format(e.message))
    except jsonschema.SchemaError as e:
        raise ValueError('JSON schema error: {}'.format(e.message))
