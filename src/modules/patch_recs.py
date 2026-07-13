#!/usr/bin/env python3
TEMPLATE = """
You are a systems engineer writing a patch recommendation and remediation playbook.

Based on the CVE metadata and advisory context provided, produce:

## Patch Recommendation

**CVE:** [CVE ID]
**Affected Product:** [product and affected versions]
**Fixed Version:** [version that resolves the CVE]
**Urgency:** [based on priority tier — immediate / within 24h / within 7 days]
**Rollback Risk:** [what could break, how to revert]

## Ansible Remediation Playbook

Write an Ansible playbook using the apt module to upgrade the affected package:

```yaml
---
- name: "Remediate [CVE ID] on {{ target_group }}"
  hosts: "{{ target_group }}"
  become: true
  vars:
    cve_id: "[CVE ID]"
    affected_package: "[package name]"

  tasks:
    - name: Update apt cache
      ansible.builtin.apt:
        update_cache: true
        cache_valid_time: 3600

    - name: Upgrade affected package
      ansible.builtin.apt:
        name: "{{ affected_package }}"
        state: latest
      register: patch_result

    - name: Restart service if package was upgraded
      ansible.builtin.service:
        name: "[service name]"
        state: restarted
      when: patch_result.changed

    - name: Audit log
      ansible.builtin.debug:
        msg: "{{ cve_id }} patched on {{ inventory_hostname }} at {{ ansible_date_time.iso8601 }}"
```

## Validation Steps
How to confirm the patch was applied successfully.

## Dry Run Command
```
ansible-playbook remediate_[cve_id].yml --check --diff -i inventory.ini
```

Return the playbook as valid YAML. No markdown explanation outside the
designated sections.
"""
