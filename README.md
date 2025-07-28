# mullvadupdater
Why did i make this script? Mullvad constantly needs updating and you have to manually do it. 

Mullvad VPN Auto-Updater
A PowerShell script that automatically checks for, downloads, and installs Mullvad VPN updates.

Features
- Stable releases only (skips beta versions by default)
- Downgrade protection (won't downgrade to older versions)
- Auto-starts Mullvad after updates
- Administrator privilege handling
- Window persistence (won't close unexpectedly)

Requirements
Windows PowerShell 5.1+
Administrator privileges (for installation)
Internet connection
Never downgrades unless you specifically use -Force -AllowDowngrade
Only stable releases are installed by default
Backs up settings during updates (Mullvad handles this)
