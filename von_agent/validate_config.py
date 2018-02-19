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

CONFIG_JSON_SCHEMA = {
    'wallet': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'auto-remove': {
                'type': 'boolean'
            }
        },
        'additionalProperties': False
    },

    'pool': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'auto-remove': {
                'type': 'boolean'
            }
        },
        'additionalProperties': False
    },

    'agent': {
        '$schema': 'http://json-schema.org/draft-04/schema',
        'type': 'object',
        'properties': {
            'endpoint': {
                'type': 'string',
                'pattern': '^.*://.*[^/]$'
            },
            'proxy-relay': {
                'type': 'boolean'
            }
        },
        'additionalProperties': False
    }
}


def validate_config(key: str, config: dict) -> None:
    """
    Call jsonschema validation to raise ValueError on non-compliance or silently pass.

    :param key: validation schema key of interest
    :param config: configuration dict to validate
    """

    try:
        jsonschema.validate(config, CONFIG_JSON_SCHEMA[key])
    except jsonschema.ValidationError as e:
        raise ValueError('JSON validation error: {}'.format(e.message))
    except jsonschema.SchemaError as e:
        raise ValueError('JSON schema error: {}'.format(e.message))
