wg-apply
===============

## Introduction

`wg-apply` is a command-line tool designed to reload the config file of wg-quick (located under `/etc/wireguard`) seamlessly. Unlike shutting down the entire interface, wg-apply makes changes as needed, without resetting the status of the WireGuard interface or causing any interruption to non-affected peers.

While wg-apply currently only supports the config file of wg-quick, a systemd-networkd compatible implementation is planned and coming soon.

## Usage

There are two ways to use `wg-apply`:

### Method 1: As a Replacement for `wg-quick up wg0`

You can simply use `wg-apply wg0` as a replacement for `wg-quick up wg0`.

Please note that wg-apply does not intend to support the following options found in the wg-quick configure file: `DNS=`, `PreUp=`, `PostUp=`, `PreDown=`, `PostDown=`, and `SaveConfig=`. If you need these feature, I'd recommand you still use `wg-quick up wg0` to bring up the interface.

### Method 2: As `ExecReload=` for `wg-quick@.service`

`wg-apply` can be configured as `ExecReload=` for `wg-quick@.service`:

1. Execute the following command to create an override file for the `wg-quick@.service`:

   ```bash
   systemctl edit wg-quick@.service
   ```

2. Add the following lines to the file, between the hint comments:

   ```ini
   [Service]
   ExecReload=
   ExecReload=/usr/local/bin/wg-apply %i
   ```

3. Save and close the file.

4. Finally, execute the following command to reload the wg-quick configuration file for the specified WireGuard interface (in this case, `wg0`):

   ```
   systemctl reload wg-quick@wg0.service
   ```

