"""PiOS Update Manager: a small, separate privileged service that installs signed OTA releases.

It deliberately shares no code with the web backend (`pios`) and is not part of OTA packages itself:
it ships in the image under /usr/lib/pios-updater so a faulty update can never replace the thing that
installs and rolls back updates.
"""
UPDATER_API = 1
