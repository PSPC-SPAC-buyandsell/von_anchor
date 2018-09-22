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


import jsonschema

from von_anchor.error import JSONValidation


CONFIG_JSON_SCHEMA = {
    'wallet': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'auto-remove': {
                'type': 'boolean'
            }
        },
        'additionalProperties': True
    },
    'pool': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'auto-remove': {
                'type': 'boolean'
            },
            'protocol': {
                'type': 'string',
                'enum': ['1.3', '1.4', '1.5', '1.6']
            }
        },
        'additionalProperties': True
    },
    'holder-prover': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'parse-cache-on-open': {
                'type': 'boolean'
            },
            'archive-cache-on-close': {
                'type': 'boolean'
            }
        },
        'additionalProperties': False
    },
    'verifier': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'parse-cache-on-open': {
                'type': 'boolean'
            },
            'archive-on-close': {
                'type': 'object',
                'properties': {
                    'schema_id': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'uniqueItems': True
                        }
                    },
                    'cred_def_id': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'uniqueItems': True
                        }
                    },
                    'rev_reg_id': {
                        'type': 'array',
                        'items': {
                            'type': 'string',
                            'uniqueItems': True
                        }
                    }
                }
            }
        },
        'additionalProperties': False
    }
}


def validate_config(key: str, config: dict) -> None:
    """
    Call jsonschema validation to raise JSONValidation on non-compliance or silently pass.

    :param key: validation schema key of interest
    :param config: configuration dict to validate
    """

    try:
        jsonschema.validate(config, CONFIG_JSON_SCHEMA[key])
    except jsonschema.ValidationError as x_validation:
        raise JSONValidation('JSON validation error on {} configuration: {}'.format(key, x_validation.message))
    except jsonschema.SchemaError as x_schema:
        raise JSONValidation('JSON schema error on {} specification: {}'.format(key, x_schema.message))
