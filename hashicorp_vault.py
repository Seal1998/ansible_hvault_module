import requests
from collections import namedtuple
from ansible.module_utils.basic import AnsibleModule

def split_path_by_parts(path):
    full_path_parts = path.split('/')
    kv_mount_path = full_path_parts[0]
    secret_name = full_path_parts[-1]
    kv_mountless_path = '/'.join(full_path_parts[1:])
    return kv_mount_path, kv_mountless_path, secret_name

def get_single_secret(url, path, token, namespace, mounts):
        kv_mount, kv_mountless, secret_name = split_path_by_parts(path)

        VaultSecret = namedtuple('VaultSecret', ['full_path', 'secret_name', 'secret_data'])

        if f'{kv_mount}/' not in mounts.keys():
            return False, f'{kv_mount} kv engine does not exist'
        else:
            kv_mount_version = mounts[f'{kv_mount}/']['options']['version']
        
        pull_api_endpoint = '/data' if kv_mount_version == '2' else ''
        secret_response_raw = requests.get(f'{url}/v1/{kv_mount}{pull_api_endpoint}/{kv_mountless}', 
                                            headers={'X-Vault-Token': token, 'X-Vault-Namespace': namespace},
                                            verify=False)
        if secret_response_raw.status_code == 200:
            response_data = secret_response_raw.json()['data'] if kv_mount_version == '1' \
                                                            else secret_response_raw.json()['data']['data']
        elif secret_response_raw.status_code == 403:
            return False, f'Access denied for {kv_mount}{pull_api_endpoint}/{kv_mountless}'
        
        else:
            return False, f'{secret_response_raw.status_code} - {kv_mount}{pull_api_endpoint}/{kv_mountless}'

        secret = VaultSecret(f'{kv_mount}/{kv_mountless}', secret_name, response_data)
        return secret, False

def login_approle(url, role_id, secret_id, namespace):
    login_raw = requests.post(f'{url}/v1/auth/approle/login', 
                        data={'role_id': role_id, 'secret_id': secret_id},
                        headers={'X-Vault-Namespace': namespace},
                        verify=False)
    login_raw_dict = login_raw.json()
    if login_raw.status_code != 200:
        return False, f'{login_raw.status_code} - auth/approle/login - {login_raw.text}'
    else:
        token = login_raw_dict['auth']['client_token']
        return token, False

def get_mounts_info(url, token, namespace):
    mounts_raw = requests.get(f'{url}/v1/sys/mounts', 
                    headers={'X-Vault-Token': token, 'X-Vault-Namespace': namespace},
                    verify=False)
    mounts_raw_dict = mounts_raw.json()
    if mounts_raw.status_code != 200:
        return False, f'{mounts_raw.status_code} - sys/mounts'
    else:
        mounts_info = mounts_raw_dict['data']
        return mounts_info, False

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
            'no_log': True
        },  

        'secret_path': {
            'type': 'list',
            'elements': 'raw',
            'required': True
        },
        'namespace': {
            'type': 'str',
            'default': 'root'
        }
    }

    module = AnsibleModule(argument_spec=args, supports_check_mode=True)

    result = {
        'check_mode': False,
        'ansible_facts': {}
    }

    vault_url = module.params['url']
    namespace = module.params['namespace']
    secret_paths = []
    complex_secrets = {}

# construct paths list and complex secrets dict
    for raw_path in module.params['secret_path']:
        if type(raw_path) is dict:
            if 'path' not in raw_path.keys():
                module.fail_json(msg=f'No path field in {raw_secret} secret')
            else:
                secret_name = raw_path['path'].split('/')[-1]
                complex_secrets[secret_name] = raw_path
                secret_paths.append(raw_path['path'])

        if type(raw_path) is str:
            secret_paths.append(raw_path)

# get token
    if not any([all([module.params['approle_id'], module.params['approle_secret']]), module.params['token']]):
        module.fail_json(msg='No AppRole or token login credentials')

    elif all([module.params['approle_id'], module.params['approle_secret']]):
        token, error = login_approle(vault_url, module.params['approle_id'], module.params['approle_secret'], namespace)
        if error:
            module.fail_json(msg=f'{error}')

    elif module.params['token']:
        token = module.params['token']

# get mounts info
    vault_mounts, error = get_mounts_info(vault_url, token, namespace)
    if error:
        module.fail_json(msg=f'{error}')

# get secrets from Vault
    vault_secrets = []
    for path in secret_paths:
        secret, error = get_single_secret(vault_url, path, token, namespace, vault_mounts)

        if error:
            module.fail_json(msg=f'{error}')
        else:
            vault_secrets.append(secret)

# process simple and complex secrets
    for secret in vault_secrets:
        if secret.secret_name in complex_secrets.keys():
            complex_secret = complex_secrets[secret.secret_name]
            secret_data = secret.secret_data
            
        # complex secret pipeline
            if 'keys' in complex_secret.keys():
                secret_data = { key: secret.secret_data[key] for key in complex_secret['keys'] 
                                                                if key in secret.secret_data.keys() }

            if 'container' in complex_secret.keys():
                secret_data = {complex_secret['container']: secret_data}
        
        else:
            secret_data = secret.secret_data

# populate ansible fact for each KV pair
        for key, value in secret_data.items():
            result['ansible_facts'][key] = value

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()