# PiOS image build (experimental)

The Raspberry Pi Imager can write a PiOS image directly to microSD or SSD by selecting **Use custom**.

This build is based on the official Raspberry Pi OS 64-bit image tooling `pi-gen` (`arm64` branch). It runs on a Linux x86_64 computer with Docker and substantial free disk space (recommend 30 GB or more), or on a suitable Linux builder.

## Run

```bash
sudo apt-get install -y docker.io git
sudo usermod -aG docker "$USER"
# log out/in if group was just changed
./scripts/build-image.sh
```

The build script clones pi-gen in a temporary work folder and adds a PiOS installation stage. Images will be under `image-build/pi-gen/deploy/`. Compressed `.img.xz` files can be selected directly by recent Raspberry Pi Imager versions. **Build scripts are experimental and have not yet been validated end to end.**

PiOS starts as a web service at `http://<device-ip>:8080` on the trusted local network. Create your own admin account via its first-run wizard.

Important:
- Do not expose port 8080 to the public Internet.
- The alpha setup endpoint is not protected against a network client who reaches it before the owner completes setup; isolate the first boot on a trusted LAN.
- Do not put usernames, passwords or Wi-Fi secrets in a public image.
- A local HDMI graphical desktop is planned for a later image revision.
- Writing an image overwrites the selected card or drive.
