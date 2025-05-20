#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Vadim Khitrin <me at vkhitrin.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: guestfs_user
short_description: Manages users in guest image
version_added: '2.8'
description:
  - Manages users in guest image
options:
  image:
    required: True
    description: Image path on filesystem
  name:
    required: True
    description: Name of user to manage
  password:
    required: False
    description: User's password
  groups:
    required: False
    description: List of groups the user will be added to
    type: list
    elements: str
  shell:
    required: False
    description: Path to the user's login shell
    type: str
  state:
    required: True
    description: Action to be performed
    choices:
    - present
    - absent
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
  - Vadim Khitrin (@vkhitrin)
"""

EXAMPLES = """
- name: Creates a user
  guestfs_user:
    image: /tmp/rhel7-5.qcow2
    name: test_user
    password: test_password
    state: present

- name: Change password to an existing user
  guestfs_user:
    image: /tmp/rhel7-5.qcow2
    name: root
    password: root_password
    state: present

- name: Create a user with specific groups and shell
  guestfs_user:
    image: /tmp/rhel7-5.qcow2
    name: deploy_user
    password: secure_password
    groups:
      - wheel
      - developers
    shell: /bin/bash
    state: present

- name: Modify an existing user's groups and shell
  guestfs_user:
    image: /tmp/rhel7-5.qcow2
    name: existing_user
    groups:
      - admin
    shell: /bin/zsh
    state: present

- name: Delete a user
  guestfs_user:
    image: /tmp/rhel7-5.qcow2
    name: test_user
    state: absent
"""

RETURN = """
msg:
  type: string
  when: failure
  description: Contains the error message (may include python exceptions)
  example: "cat: /fgdfgdfg/dfgdfg: No such file or directory"

results:
  type: array
  when: success
  description: Contains the module successful execution results
  example: [
      "test_user is present",
      "Added test_user to groups: wheel, developers",
      "Changed shell to /bin/bash for test_user"
  ]
"""

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.libguestfs import guest


def users(guest, module):

    state = module.params['state']
    user_name = module.params['name']
    user_password = module.params['password']
    user_groups = module.params.get('groups', [])
    user_shell = module.params.get('shell')
    results = {
        'changed': False,
        'failed': False,
        'results': []
    }
    err = False

    try:
        guest.sh_lines('id -u {}'.format(user_name))
        user_exists = True
    except Exception:
        user_exists = False

    if state == 'present':
        if user_exists:
            # Update existing user
            changed = False
            
            # Update password if provided
            if user_password:
                try:
                    guest.sh_lines('echo {u}:{p} | chpasswd'.format(u=user_name,
                                                                    p=user_password))
                    changed = True
                    results['results'].append('Updated password for {}'.format(user_name))
                except Exception as e:
                    err = True
                    results['failed'] = True
                    results['msg'] = "Failed to update password: {}".format(str(e))
                    return results, err
            
            # Update shell if provided
            if user_shell:
                try:
                    guest.sh_lines('usermod -s {} {}'.format(user_shell, user_name))
                    changed = True
                    results['results'].append('Changed shell to {} for {}'.format(user_shell, user_name))
                except Exception as e:
                    err = True
                    results['failed'] = True
                    results['msg'] = "Failed to update shell: {}".format(str(e))
                    return results, err
            
            # Update groups if provided
            if user_groups:
                try:
                    groups_str = ','.join(user_groups)
                    guest.sh_lines('usermod -G {} {}'.format(groups_str, user_name))
                    changed = True
                    results['results'].append('Added {} to groups: {}'.format(user_name, groups_str))
                except Exception as e:
                    err = True
                    results['failed'] = True
                    results['msg'] = "Failed to update groups: {}".format(str(e))
                    return results, err
            
            if not changed:
                results['results'].append('{} already exists with the specified configuration'.format(user_name))
            else:
                results['changed'] = True
                
        else:
            # Create new user
            try:
                cmd = ['useradd']
                
                # Add shell if specified
                if user_shell:
                    cmd.append('-s {}'.format(user_shell))
                
                # Add groups if specified
                if user_groups:
                    groups_str = ','.join(user_groups)
                    cmd.append('-G {}'.format(groups_str))
                
                # Add username and execute
                cmd.append(user_name)
                guest.sh_lines(' '.join(cmd))
                
                # Set password
                guest.sh_lines('echo {u}:{p} | chpasswd'.format(u=user_name, p=user_password))
                
                results['changed'] = True
                results['results'].append('{} has been created'.format(user_name))
                
                # Add information about groups and shell if they were set
                if user_groups:
                    results['results'].append('Added {} to groups: {}'.format(user_name, ','.join(user_groups)))
                if user_shell:
                    results['results'].append('Set shell to {} for {}'.format(user_shell, user_name))
                
            except Exception as e:
                err = True
                results['failed'] = True
                results['msg'] = "Failed to create user: {}".format(str(e))

    elif state == 'absent':
        if user_exists:
            try:
                guest.sh_lines('userdel {}'.format(user_name))
                results['changed'] = True
                results['results'].append('{} has been removed'.format(user_name))
            except Exception as e:
                err = True
                results['failed'] = True
                results['msg'] = "Failed to remove user: {}".format(str(e))
        else:
            results['results'].append('{} does not exist'.format(user_name))

    return results, err


def main():

    required_together_args = [['name', 'state']]
    module = AnsibleModule(
        argument_spec=dict(
            image=dict(required=True, type='str'),
            automount=dict(required=False, type='bool', default=True),
            mounts=dict(required=False, type='list', elements='dict'),
            network=dict(required=False, type='bool', default=True),
            selinux_relabel=dict(required=False, type='bool', default=False),
            name=dict(required=True, type='str'),
            password=dict(type='str', no_log=True),
            groups=dict(type='list', elements='str', required=False),
            shell=dict(type='str', required=False),
            state=dict(required=True, choices=['present', 'absent']),
            debug=dict(required=False, type='bool', default=False),
            force=dict(required=False, type='bool', default=False)
        ),
        required_together=required_together_args,
        supports_check_mode=False
    )

    if not module.params['password'] and module.params['state'] == 'present' and not module.params.get('groups') and not module.params.get('shell'):
        err = True
        results = {
            'msg': 'When state is present, at least one of password, groups, or shell must be provided'
        }
        module.fail_json(**results)

    g = guest(module)
    instance = g.bootstrap()
    results, err = users(instance, module)
    g.close()

    if err:
        module.fail_json(**results)
    module.exit_json(**results)


if __name__ == '__main__':
    main()
