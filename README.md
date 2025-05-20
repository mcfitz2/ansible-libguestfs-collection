# libguestfs Collection

**NOTE:** This collection is not endorsed by the [libguestfs](https://libguestfs.org)
community, this is a personal effort.

libguestfs modules allow users to use Ansible to automate commonly used
libguestfs actions in a native way.

## Prerequisites

On Ansible Controller:

- Ansible >= 2.8.0 (May work on earlier releases)
- Python >= 2.7.5 || Python >= 3.4
- gcc

On Ansible Host:

- gcc
- libguestfs
- libguestfs-devel
- Python >= 2.7.5 || Python >= 3.4
- libguestfs python bindings:
  - System:
    If your distribution's package manager contains `python-libguestfs`, install it (via `yum`, `apt` ...)
  - pip:
    If a virtual environment is used or you do not have a pre packaged `python-libguestfs`,
    refer to [guestfs python bindings in a virtualenv](https://www.libguestfs.org/guestfs-python.3.html#using-python-bindings-in-a-virtualenv)
    In order to install via pip download the relevant version from `http://download.libguestfs.org/python/`
    Example, `https://download.libguestfs.org/python/guestfs-1.40.2.tar.gz`

## Compatibility Matrix

|       Distro       | Supported |                                                           Notes                                                            |
| :----------------: | :-------- | :------------------------------------------------------------------------------------------------------------------------: |
| Fedora/CentOS/RHEL | Yes       |                                                                                                                            |
|   Ubuntu/Debian    | Yes       |                                                                                                                            |
|      Windows       | No        | [Not Supported, no plans to support right now](https://listman.redhat.com/archives/libguestfs/2016-February/msg00145.html) |

## Documentation

Please refer to [docs](/docs) directory.

## Installation

### Ansible Galaxy

Collection can be installed from Ansible galaxy:

```shell
ansible-galaxy collection install mcfitz2.libguestfs
```

### Locally

Build the collection:

```shell
ansible-galaxy collection build
```

Install collection:

```shell
ansible-galaxy collection install --force mcfitz2-libguestfs-<VERSION>.tar.gz
```

## Development

### Pre-commit Hooks

This project uses pre-commit hooks to ensure code quality and consistency. To use the pre-commit hooks:

1. Install the required dependencies:

```shell
pipenv install ansible-lint pylint yamllint pre-commit
```

2. Set up the pre-commit hooks:

```shell
pipenv run pre-commit install
```

The pre-commit hooks will automatically run on every commit and check for:

- Python linting issues using pylint
- YAML syntax validation with yamllint
- Ansible best practices with ansible-lint
- Duplicate entries in argument_spec definitions
- Debugging print statements
- Proper Ansible module documentation

If you need to bypass the hooks for a specific commit:

```shell
git commit --no-verify
```

You can also run all the hooks manually on all files:

```shell
pipenv run pre-commit run --all-files
```

## License

This project is licensed under GPL-3.0 License. Please see the [COPYING.md](/COPYING.md) for more information.
