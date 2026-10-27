meta:
	ADDON_NAME = ofxBraid
	ADDON_DESCRIPTION = ofxBraid is an openFrameworks mailbox that keeps one person on two paths, negotiated on Bluetooth first. The person is the Bluetooth peer id. Presence carries the signing key so a UDP socket and an allowlist name the same person. ofxENet carries the packet when that peer is up, and the same packet is retried on ofxBluetoothLE when that path drops.
	ADDON_AUTHOR = Dan Rosser
	ADDON_TAGS = "networking" "bluetooth" "enet" "multiplayer"
	ADDON_URL = https://github.com/danoli3/ofxBraid

common:
	# https://github.com/danoli3/ofxENet
	# https://github.com/danoli3/ofxBluetoothLE-experiment
	ADDON_DEPENDENCIES = ofxENet ofxBluetoothLE
	ADDON_INCLUDES = src
	ADDON_SOURCES = src/ofxBraid.cpp

linux64:
linux:
linuxarmv6l:
linuxarmv7l:
msys2:
android/armeabi:
android/armeabi-v7a:
osx:
ios:
tvos:
