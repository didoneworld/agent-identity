import json
from pathlib import Path


def _parse_simple_yaml(path: Path) -> dict:
    data = {}
    current_section = None
    current_subsection = None
    current_list_key = None
    for raw_line in path.read_text().splitlines():
        if not raw_line.strip() or raw_line.strip().startswith('#'):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(' '))
        line = raw_line.strip()
        if indent == 0:
            current_section = None
            current_subsection = None
            current_list_key = None
            if line.endswith(':'):
                key = line[:-1]
                data[key] = {}
                current_section = key
            else:
                key, value = line.split(': ', 1)
                data[key] = value.strip('"')
        elif indent == 2 and current_section:
            current_subsection = None
            current_list_key = None
            if line.endswith(':'):
                key = line[:-1]
                data[current_section][key] = {}
                current_subsection = key
            else:
                key, value = line.split(': ', 1)
                if value == '{}':
                    data[current_section][key] = {}
                else:
                    data[current_section][key] = value.strip('"')
        elif indent == 4 and current_section and current_subsection:
            current_list_key = None
            if line.startswith('- '):
                current_list_key = current_subsection
                existing = data[current_section].get(current_subsection)
                if isinstance(existing, dict):
                    existing = []
                    data[current_section][current_subsection] = existing
                elif existing is None:
                    existing = []
                    data[current_section][current_subsection] = existing
                existing.append(line[2:].strip('"'))
            elif line.endswith(':'):
                key = line[:-1]
                data[current_section][current_subsection][key] = {}
                current_list_key = key
            else:
                key, value = line.split(': ', 1)
                target = data[current_section][current_subsection]
                if isinstance(target, dict):
                    target[key] = None if value == 'null' else value.strip('"')
        elif indent == 6 and current_section and current_subsection:
            if line.startswith('- '):
                existing = data[current_section].setdefault(current_subsection, [])
                existing.append(line[2:].strip('"'))
            else:
                key, value = line.split(': ', 1)
                nested = data[current_section][current_subsection]
                if isinstance(nested, dict):
                    nested[key] = None if value == 'null' else value.strip('"')
    return data


def test_json_schema_declares_expected_protocol_version():
    schema_path = Path(__file__).resolve().parents[1] / 'schemas/json/agent-id-record.schema.json'
    schema = json.loads(schema_path.read_text())
    assert schema['properties']['agent_id_protocol_version']['const'] == '0.2.0'
    assert len(schema['allOf']) == 4
    assert schema['properties']['authorization']['properties']['delegation_proof_formats']['minItems'] == 1


def test_json_schema_encodes_delegation_guards():
    schema_path = Path(__file__).resolve().parents[1] / 'schemas/json/agent-id-record.schema.json'
    schema = json.loads(schema_path.read_text())
    delegated_rule = schema['allOf'][1]['then']['properties']
    assert delegated_rule['authorization']['properties']['subject_context']['enum'] == [
        'on_behalf_of_user',
        'on_behalf_of_team',
        'multi_party',
    ]
    assert delegated_rule['governance']['properties']['identity_chain_preserved']['const'] is True


def test_did_web_example_uses_did_web():
    example_path = Path(__file__).resolve().parents[1] / 'examples/did-methods/did-web-agent.yaml'
    data = _parse_simple_yaml(example_path)
    assert data['agent']['did'].startswith('did:web:')
    assert data['authorization']['mode'] == 'delegated'
    assert data['governance']['provisioning'] == 'scim'
    assert data['bindings']['a2a']['endpoint_url'].startswith('https://')


def test_did_key_example_uses_did_key():
    example_path = Path(__file__).resolve().parents[1] / 'examples/did-methods/did-key-agent.yaml'
    data = _parse_simple_yaml(example_path)
    assert data['agent']['did'].startswith('did:key:')
    assert data['authorization']['mode'] == 'autonomous'
    assert data['governance']['provisioning'] == 'manual'
    assert data['bindings']['anp']['did'].startswith('did:key:')
