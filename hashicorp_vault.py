import json
from collections import namedtuple
from ansible.module_utils.urls import open_url
from ansible.module_utils.basic import AnsibleModule

# import urllib to handle exceptions 
try:
    # python3
    from urllib.error import HTTPError, URLError
except ImportError:
    # python2
    from urllib2 import HTTPError, URLError

def split_path_by_parts(path):
    full_path_parts = list(filter(lambda p: p != '', path.split('/'))) # trim '' elements if path contain slash at the end (e.q. one/two/)
    kv_mount_path = full_path_parts[0]
    secret_name = full_path_parts[-1]
    kv_mountless_path = '/'.join(full_path_parts[1:])
    return kv_mount_path, kv_mountless_path, secret_name

def get_kv_mount_version(mount_name, mounts):
    if mount_name+'/' not in mounts.keys():
        return False, '%s kv engine does not exist' % mount_name
    else:
        kv_mount_version = mounts[mount_name+'/']['options']['version']
    return int(kv_mount_version)

def request(type, url, headers, data=None):
    try:
        response_data_raw = open_url(   
                            url=url,
                            headers=headers,
                            method=type,
                            validate_certs=False,
                            data = data
                            )
        response_data = json.load(response_data_raw)
        
        return response_data, False

    except HTTPError as err:
        return False, '%s - %s %s' % \
                            (url, err.code, err.reason)
    except URLError as err:
        return False, '%s - %s' % (url, err.reason)
    
    except Exception as err:
        return False, '%s' % (err)

def create_secret(url, name, path, data, token, namespace, mounts):
    kv_mount, kv_mountless, _ = split_path_by_parts(path)

    mount_version = get_kv_mount_version(kv_mount, mounts)

    create_api_endpoint = 'data' if mount_version == 2 else ''
    url_parts = tuple(filter(lambda el: el != '', [kv_mount, create_api_endpoint, kv_mountless, name]))
    create_url = '%s/v1/%s' % (url, '/'.join(url_parts))
    
    secret_data = json.dumps({'data': data}).encode()
    create_data, error = request('POST', create_url, {'X-Vault-Token': token, 'X-Vault-Namespace': namespace}, secret_data)

    if error:
        return False, error
    else:
        return create_data, False

def list_location_secrets(url, path, token, namespace, mounts):
    kv_mount, kv_mountless, _ = split_path_by_parts(path)

    kv_mount_version = get_kv_mount_version(kv_mount, mounts)
    
    pull_api_endpoint = 'metadata/' if kv_mount_version == 2 else ''
    list_url = '%s/v1/%s/%s%s' % (url, kv_mount, pull_api_endpoint, kv_mountless)

    response_data_versionless, error = request('LIST', list_url, {'X-Vault-Token': token, 'X-Vault-Namespace': namespace})

    if error:
        return False, error
    else:
        response_data_unfiltered = ['%s%s/%s' % (kv_mount, '/'+kv_mountless if kv_mountless != '' else '', key) \
                                                        for key in response_data_versionless['data']['keys']]
        response_data = list(filter(lambda p: p[-1] != '/', response_data_unfiltered))
        listed_secrets = response_data
        return listed_secrets, False

def get_single_secret(url, path, token, namespace, mounts):
    kv_mount, kv_mountless, secret_name = split_path_by_parts(path)

    VaultSecret = namedtuple('VaultSecret', ['full_path', 'secret_name', 'secret_data'])

    kv_mount_version = get_kv_mount_version(kv_mount, mounts)
    
    pull_api_endpoint = 'data/' if kv_mount_version == 2 else ''
    secret_url = '%s/v1/%s/%s%s' % (url, kv_mount, pull_api_endpoint, kv_mountless)

    response_data_versionless, error = request('GET', secret_url, {'X-Vault-Token': token, 'X-Vault-Namespace': namespace})
    if error:
        return False, error
    else:
        response_data = response_data_versionless['data'] if kv_mount_version == '1' else \
                                                response_data_versionless['data']['data']

        secret = VaultSecret('%s/%s' % (kv_mount,kv_mountless), secret_name, response_data)

        return secret, False

def login_approle(url, role_id, secret_id, namespace):
    approle_login_url = '%s/v1/auth/approle/login' % url

    data = json.dumps({'role_id': role_id, 'secret_id': secret_id}).encode()

    login_data, error = request('POST', approle_login_url, {'X-Vault-Namespace': namespace}, data)

    if error:
        return False, error
    else:
        return login_data['auth']['client_token'], False

def get_mounts_info(url, token, namespace):
    mounts_url = '%s/v1/sys/mounts' % url

    mounts, error = request('GET', mounts_url, {'X-Vault-Token': token, 'X-Vault-Namespace': namespace})
    if error:
        return False, error
    else:
        mounts = mounts['data']
        return mounts, False

def run_module():
    args = {
        'url':{
            'type': 'str',
            'required': True
        },

        'approle_id': {
            'type': 'str',
            'required': False
        },
        'approle_secret': {
            'type': 'str',
            'required': False,
            'no_log': True
        },

        'token': {
            'type': 'str',
            'required': False,
            'no_log': False
        },  

        'secret_path': {
            'type': 'raw',
            'required': False
        },

        'list_path': {
            'type': 'str',
            'required': False
        },

        'create_secret': {
            'type': 'dict',
            'required': False
        },

        'namespace': {
            'type': 'str',
            'default': 'root'
        },

        'auth_namespace': {
            'type': 'str',
        },

        'return_facts': {
            'type': 'bool',
            'default': True
        }
    }

    module = AnsibleModule(argument_spec=args, supports_check_mode=True)

    result = {
        'check_mode': False,
        'ansible_facts': {},
        'data': {},
        'metadata': {}
    }

    vault_url = module.params['url']
    namespace = module.params['namespace']
    secret_paths = []
    complex_secrets = {}

# get token
    if not any([all([module.params['approle_id'], module.params['approle_secret']]), module.params['token']]):
        module.fail_json(msg='No AppRole or token login credentials')

    elif all([module.params['approle_id'], module.params['approle_secret']]):
        # if auth_namespace not specified. Set namespace for auth set to the current namespace
        if module.params['auth_namespace'] is None:
            auth_namespace = namespace
        else:
            auth_namespace = module.params['auth_namespace']

        token, error = login_approle(vault_url, module.params['approle_id'], module.params['approle_secret'], auth_namespace)
        if error:
            module.fail_json(msg='%s' % error)

    elif module.params['token']:
        token = module.params['token']

# get mounts info
    vault_mounts, error = get_mounts_info(vault_url, token, namespace)
    if error:
        module.fail_json(msg='%s' % error)

# fail if both secret_path and list_path specified
    if all([module.params['secret_path'], module.params['list_path']]):
        module.fail_json(msg='%s' % 'Both secret_path and list_path specified')

    if module.params['create_secret'] is not None:
        create_specs = module.params['create_secret']
        if type(create_specs) is dict:
            if all([k in create_specs for k in ('name', 'path', 'data')]):
                create_response, error = create_secret(vault_url, create_specs['name'], create_specs['path'], create_specs['data'], token, namespace, vault_mounts)
                if error:
                    module.fail_json(msg='%s' % error)
                else:
                    result['metadata']['created_secret'] = create_response
            else:
                module.fail_json(msg='create_secret should contain [path, data] keys')
        else:
            module.fail_json(msg='create_secret accept only dict with [path, data] keys')

    if module.params['list_path'] is not None:
    # list_path should be string only
        if type(module.params['list_path']) is not str:
            module.fail_json(msg='%s' % 'list_path parameter should contain string only')
        else:
            listed_secrets, error = list_location_secrets(vault_url, module.params['list_path'], token, namespace, vault_mounts)
            if error:
                module.fail_json(msg='%s' % error)

        if module.params['return_facts']:
            result['ansible_facts']['vault_listed'] = listed_secrets
        else:
            result['data']['vault_listed'] = listed_secrets

    elif module.params['secret_path'] is not None:
        # ability to pass single dict or string as a secret_path
        if type(module.params['secret_path']) in (dict, str):
            module.params['secret_path'] = [module.params['secret_path']]

    # handling wrong paths spec (when path is list of lists)
        corrected_paths = module.params['secret_path'][:]
        for raw_path in module.params['secret_path']:
            if type(raw_path) is list:
                # if path is list - unpack it and merge it with main paths
                corrected_paths.remove(raw_path)
                #corrected_paths = list([*corrected_paths, *raw_path])
                corrected_paths = corrected_paths + raw_path
        
    # replacing paths arg with corrected one
        module.params['secret_path'] = corrected_paths

    # construct paths list and complex secrets dict
        for raw_path in module.params['secret_path']:
            if type(raw_path) is dict:
                if 'path' in raw_path.keys():
                    secret_name = raw_path['path'].split('/')[-1]
                    complex_secrets[secret_name] = raw_path
                    secret_paths.append(raw_path['path'])

                elif 'containerized_by_name' in raw_path.keys():
                    if all([type(s) is str for s in raw_path['containerized_by_name']]):
                        for secret_path in raw_path['containerized_by_name']:
                            secret_name = secret_path.split('/')[-1]
                            complex_secret = {'path': secret_path, 'container': secret_name}
                            complex_secrets[secret_name] = complex_secret
                            secret_paths.append(secret_path)
                    else:
                        module.fail_json(msg='containerized_by_name should be list of strings')

                else:
                    module.fail_json(msg='Wrong path form %s secret' % raw_path)

            if type(raw_path) is str:
                secret_paths.append(raw_path)

    # get secrets from Vault
        vault_secrets = []
        for path in secret_paths:
            secret, error = get_single_secret(vault_url, path, token, namespace, vault_mounts)

            if error:
                module.fail_json(msg='%s' % error)
            else:
                vault_secrets.append(secret)

    # process simple and complex secrets
        for secret in vault_secrets:
            if secret.secret_name in complex_secrets.keys():
                complex_secret = complex_secrets[secret.secret_name]
                secret_data = secret.secret_data
                
            # complex secret pipeline
                if 'keys' in complex_secret.keys():
                    #if just one exclude key specified in form of 'key: value' (not list)
                    if type(complex_secret['keys']) is str:
                        complex_secret['keys'] = [complex_secret['keys'],]
                    secret_data = { key: secret.secret_data[key] for key in complex_secret['keys'] 
                                                                    if key in secret.secret_data.keys() }

                if 'container' in complex_secret.keys():
                    secret_data = {complex_secret['container']: secret_data}
            
            else:
                secret_data = secret.secret_data

    # populate ansible fact for each KV pair
            return_data = {}
            for key, value in secret_data.items():
                return_data[key] = value

            if module.params['return_facts']:
                result['ansible_facts'] = {k:v for d in [result['ansible_facts'], return_data] for k,v in d.items()}
            else:
                result['data'] = {k:v for d in [result['data'], return_data] for k,v in d.items()}

# add token to the result
    result['token'] = token

# return module result
    module.exit_json(**result)

if __name__ == '__main__':
    run_module()