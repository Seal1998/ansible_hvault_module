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
    full_path_parts = path.split('/')
    kv_mount_path = full_path_parts[0]
    secret_name = full_path_parts[-1]
    kv_mountless_path = '/'.join(full_path_parts[1:])
    return kv_mount_path, kv_mountless_path, secret_name

def list_location_secrets(url, path, token, namespace, mounts):
    kv_mount, kv_mountless, _ = split_path_by_parts(path)

    print(kv_mount)

    if kv_mount+'/' not in mounts.keys():
        return False, '%s kv engine does not exist' % kv_mount
    else:
        kv_mount_version = mounts[kv_mount+'/']['options']['version']
    
    pull_api_endpoint = 'metadata/' if kv_mount_version == '2' else ''
    list_url = '%s/v1/%s/%s%s' % (url, kv_mount, pull_api_endpoint, kv_mountless)

    try:
        response_data_raw = open_url(   
                            url=list_url,
                            headers={'X-Vault-Token': token, 'X-Vault-Namespace': namespace},
                            method='LIST',
                            validate_certs=False
                            )
    except HTTPError as err:
        return False, '%s - %s %s' % \
                            (list_url, err.code, err.reason)
    except URLError as err:
        return False, '%s - %s' % (list_url, err.reason)

    response_data_versionless = json.load(response_data_raw)
    response_data_unfiltered = ['%s%s/%s' % (kv_mount, '/'+kv_mountless if kv_mountless != '' else '', key) \
                                                    for key in response_data_versionless['data']['keys']]
    response_data = list(filter(lambda p: p[-1] != '/', response_data_unfiltered))

    listed_secrets = response_data

    return listed_secrets, False

def get_single_secret(url, path, token, namespace, mounts):
    kv_mount, kv_mountless, secret_name = split_path_by_parts(path)

    VaultSecret = namedtuple('VaultSecret', ['full_path', 'secret_name', 'secret_data'])

    if kv_mount+'/' not in mounts.keys():
        return False, '%s kv engine does not exist' % kv_mount
    else:
        kv_mount_version = mounts[kv_mount+'/']['options']['version']
    
    pull_api_endpoint = 'data/' if kv_mount_version == '2' else ''
    secret_url = '%s/v1/%s/%s%s' % (url, kv_mount, pull_api_endpoint, kv_mountless)

    try:
        response_data_raw = open_url(   
                            url=secret_url,
                            headers={'X-Vault-Token': token, 'X-Vault-Namespace': namespace},
                            method='GET',
                            validate_certs=False
                            )
    except HTTPError as err:
        return False, '%s - %s %s' % \
                            (secret_url, err.code, err.reason)
    except URLError as err:
        return False, '%s - %s' % (secret_url, err.reason)

    response_data_versionless = json.load(response_data_raw)
    response_data = response_data_versionless['data'] if kv_mount_version == '1' else \
                                            response_data_versionless['data']['data']

    secret = VaultSecret('%s/%s' % (kv_mount,kv_mountless), secret_name, response_data)

    return secret, False

def login_approle(url, role_id, secret_id, namespace):
    approle_login_url = '%s/v1/auth/approle/login' % url

    data = json.dumps({'role_id': role_id, 'secret_id': secret_id}).encode()

    try:
        login_raw = open_url(   
                            url=approle_login_url,
                            headers={'X-Vault-Namespace': namespace},
                            method='POST',
                            data=data,
                            validate_certs=False
                            )
    except HTTPError as err:
        return False, '%s - %s %s' % \
                            (approle_login_url, err.code, err.reason)
    except URLError as err:
        return False, '%s - %s' % (approle_login_url, err.reason)

    token = json.load(login_raw)['auth']['client_token']
    
    return token, False

def get_mounts_info(url, token, namespace):
    mounts_url = '%s/v1/sys/mounts' % url
    try:
        mounts_raw = open_url(   
                            url=mounts_url,
                            headers={'X-Vault-Token': token, 'X-Vault-Namespace': namespace},
                            method='GET',
                            validate_certs=False
                            )
    except HTTPError as err:
        return False, '%s - %s %s' % \
                            (mounts_url, err.code, err.reason)
    except URLError as err:
        return False, '%s - %s' % (mounts_url, err.reason)    

    mounts = json.load(mounts_raw)['data']

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
            'type': 'list',
            'elements': 'raw',
            'required': False
        },

        'list_path': {
            'type': 'str',
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
        'data': {}
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

    elif module.params['list_path'] is not None:
    # list_path should be string only
        if type(module.params['list_path']) is not str:
            module.fail_json(msg='%s' % 'list_path parameter should contain string only')
        else:
            listed_secrets, error = list_location_secrets(vault_url, module.params['list_path'], token, namespace, vault_mounts)
            if error:
                module.fail_json(msg='%s' % error)
        
        result['listed_secrets'] = listed_secrets

    elif module.params['secret_path'] is not None:
    # handling wrong paths spec
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
                        module.fail_json(msg='containerized_by_name should be list of paths')

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
            if module.params['return_facts']:
                for key, value in secret_data.items():
                    result['ansible_facts'][key] = value
            else:
                for key, value in secret_data.items():
                    result['data'][key] = value

# add token to the result
    result['token'] = token

# return module result
    module.exit_json(**result)

if __name__ == '__main__':
    run_module()