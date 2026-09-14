macOS install: sudo installer -pkg Sentinel-Agent-macOS-5.15.0.pkg -target /
macOS uninstall: sudo '/Library/Application Support/SentinelAgent/uninstall-sentinel-macos.sh'
Windows install/uninstall: use the MSI UI or msiexec /i and msiexec /x as administrator; MSI uninstall invokes protected cleanup automatically.
Reporting credentials are intentionally absent. Deliver a device-bound enrollment JSON through a protected enterprise channel, then invoke SentinelServiceHost --enroll <file> as root/administrator; bundled scripts remain fixed compatibility engines.
