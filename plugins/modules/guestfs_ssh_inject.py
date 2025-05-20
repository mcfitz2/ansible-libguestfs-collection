#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Micah <user@example.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: guestfs_ssh_inject
short_description: Injects SSH keys into guest image
version_added: '2.10'
description:
  - Injects SSH public keys into a user's authorized_keys file in a guest image
options:
  image:
    required: True
    description: Image path on filesystem
  user:
    required: True
    description: Name of user to inject SSH key for
  ssh_key:
    required: True
    description: SSH public key content to inject
  key_file:
    required: False
    description: Path to SSH public key file to inject (alternative to ssh_key parameter)
  state:
    required: True
    description: Action to be performed
    choices:
    - present
  automount:
    required: False
    description: Whether to perform auto mount of mountpoints inside guest disk image
    default: True
  mounts:
    required: False
    description: "List of mounts that will be attempted. Each element is a dictionary {'/path/to/device': '/path/to/mountpoint'}"
  selinux_relabel:
    required: False
    description: Whether to perform SELinux context relabeling
  network:
    required: False
    description: Whether to enable network for appliance
    default: True
requirements:
  - "libguestfs"
  - "libguestfs-devel"
  - "python >= 2.7.5 || python >= 3.4"
author:
  - Micah Fitzgerald (@mcfitz2)
"""

EXAMPLES = """
- name: Inject an SSH key for a user
  guestfs_ssh_inject:
    image: /tmp/rhel7-5.qcow2
    user: root
    ssh_key: "ssh-rsa AAAAB3NzaC1yc2E... user@example.com"
    state: present

- name: Inject an SSH key from a file
  guestfs_ssh_inject:
    image: /tmp/rhel7-5.qcow2
    user: cloud-user
    key_file: /path/to/id_rsa.pub
    state: present

- name: Remove an SSH key
  guestfs_ssh_inject:
    image: /tmp/rhel7-5.qcow2
    user: root
    ssh_key: "ssh-rsa AAAAB3NzaC1yc2E... user@example.com"
    state: absent
"""

RETURN = """
msg:
  type: string
  when: failure
  description: Contains the error message (may include python exceptions)
  example: "cat: /home/user/.ssh/authorized_keys: No such file or directory"

results:
  type: array
  when: success
  description: Contains the module successful execution results
  example: [
      "SSH key for root has been injected"
  ]
"""

import os
from ansible.module_utils.basic import AnsibleModule
from ..module_utils.libguestfs import guest


def ssh_inject(guest, module):
    state = module.params['state']
    user_name = module.params['user']
    
    # Determine the SSH key content
    if module.params['ssh_key']:
        ssh_key = module.params['ssh_key']
    elif module.params['key_file']:
        try:
            with open(module.params['key_file'], 'r') as file:
                ssh_key = file.read().strip()
        except Exception as e:
            return {
                'failed': True,
                'msg': f"Error reading SSH key file: {str(e)}"
            }, True
    else:
        return {
            'failed': True,
            'msg': "Either ssh_key or key_file must be provided"
        }, True
    
    results = {
        'changed': False,
        'failed': False,
        'results': []
    }
    err = False

    try:
        # Check if user exists
        guest.sh_lines(f'id -u {user_name}')
        
        # Get user's home directory
        home_dir = guest.sh_lines(f"getent passwd {user_name} | cut -d: -f6")[0]
        ssh_dir = f"{home_dir}/.ssh"
        auth_keys_file = f"{ssh_dir}/authorized_keys"
        
        # Create .ssh directory if it doesn't exist
        guest.sh_lines(f"mkdir -p {ssh_dir}")
        guest.sh_lines(f"chown {user_name}:{user_name} {ssh_dir}")
        guest.sh_lines(f"chmod 700 {ssh_dir}")
        
        # Check if authorized_keys file exists
        try:
            existing_content = guest.sh_lines(f"cat {auth_keys_file}")
            file_exists = True
        except Exception:
            existing_content = []
            file_exists = False
        
        if state == 'present':
            if not file_exists or ssh_key not in '\n'.join(existing_content):
                if file_exists:
                    # Append the key if file exists but doesn't contain the key
                    guest.sh_lines(f"echo '{ssh_key}' >> {auth_keys_file}")
                else:
                    # Create new file if it doesn't exist
                    guest.sh_lines(f"echo '{ssh_key}' > {auth_keys_file}")
                
                # Set proper permissions
                guest.sh_lines(f"chown {user_name}:{user_name} {auth_keys_file}")
                guest.sh_lines(f"chmod 600 {auth_keys_file}")
                
                results['changed'] = True
                results['results'].append(f"SSH key for {user_name} has been injected")
            else:
                results['results'].append(f"SSH key for {user_name} already exists")
                
        elif state == 'absent':
            if file_exists and ssh_key in '\n'.join(existing_content):
                # Create a temporary file without the key
                temp_file = f"/tmp/authorized_keys.{user_name}.tmp"
                guest.sh_lines(f"grep -v '{ssh_key}' {auth_keys_file} > {temp_file}")
                guest.sh_lines(f"mv {temp_file} {auth_keys_file}")
                guest.sh_lines(f"chown {user_name}:{user_name} {auth_keys_file}")
                guest.sh_lines(f"chmod 600 {auth_keys_file}")
                
                results['changed'] = True
                results['results'].append(f"SSH key for {user_name} has been removed")
            else:
                results['results'].append(f"SSH key for {user_name} was not present")
    
    except Exception as e:
        err = True
        results['failed'] = True
        results['msg'] = str(e)

    return results, err


def main():
    module = AnsibleModule(
        argument_spec=dict(
            image=dict(required=True, type='str'),
            automount=dict(required=False, type='bool', default=True),
            mounts=dict(required=False, type='list', elements='dict'),
            network=dict(required=False, type='bool', default=True),
            selinux_relabel=dict(required=False, type='bool', default=False),
            user=dict(required=True, type='str'),
            ssh_key=dict(required=False, type='str'),
            key_file=dict(required=False, type='str'),
            state=dict(required=True, choices=['present', 'absent']),
            debug=dict(required=False, type='bool', default=False),
            automount=dict(required=False, type='bool', default=True),
            mounts=dict(required=False, type='list', elements='dict'),
            network=dict(required=False, type='bool', default=True),
            selinux_relabel=dict(required=False, type='bool', default=False),
            force=dict(required=False, type='bool', default=False)
        ),
        required_one_of=[['ssh_key', 'key_file']],
        supports_check_mode=False
    )

    g = guest(module)
    instance = g.bootstrap()
    results, err = ssh_inject(instance, module)
    g.close()

    if err:
        module.fail_json(**results)
    module.exit_json(**results)


if __name__ == '__main__':
    main()
