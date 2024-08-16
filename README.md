## gotify-proxy

gotify-proxy is a simple proxy that is compatible with the `POST /message`
endpoint of the [Gotify](https://gotify.net/) server, but will instead send the
message to a [ntfy](https://ntfy.sh/) server.

I wrote this to be able to use ntfy in Proxmox, since Proxmox only supports
sending emails or to a Gotify server.
