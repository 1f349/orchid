# Orchid Agent

This directory is controlled by Orchid agent configuration.

Certificates in this directory will be automatically updated when required.

To configure a reload command create a script, binary, or symlink at the path `$PREFIX/protected-bin/reload`.

To make sure this is executable using sudo, add the following to the sudoers file.

```visudo
orchid-agent ALL=(root) NOPASSWD: /home/orchid-agent/agent-shares/protected-bin/reload
```
