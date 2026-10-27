#pragma once

#include "ofMain.h"
#include "ofAppNoWindow.h"
#include "ofxUnitTests.h"
#include "ofxBraid.h"

#include <chrono>
#include <cstdio>
#include <thread>
#include <type_traits>
#include <utility>

// Localhost checks. Nothing advertises. The radio retry itself needs two machines.

namespace {

const std::uint16_t kPort = 60131;
const std::uint16_t kAttackPort = 60132;
const std::string kPass = "braid-test";
const std::string kHostPeer = "3dbef9edfd1f62b9";
const std::string kClientPeer = "a1b2c3d4e5f60718";
const std::string kHostKey(64, 'a');
const std::string kClientKey(64, 'b');

// True when this ofxENet can stretch Force and ForceHigh apart.
template <typename Peer>
auto passphraseTakesRounds(int) -> decltype(std::declval<Peer &>().setPassphrase(std::declval<const std::string &>(), 1), std::true_type{});

template <typename Peer>
std::false_type passphraseTakesRounds(long);

constexpr bool kPassphraseTakesRounds = decltype(passphraseTakesRounds<ofxENet::Peer>(0))::value;

ofxBraid::Settings person(const std::string & peer, const std::string & key, const std::string & nick, bool listen) {
	ofxBraid::Settings settings;
	settings.listen = listen;
	settings.connectHost = listen ? std::string() : "127.0.0.1";
	settings.port = kPort;
	settings.passphrase = kPass;
	settings.peerId = peer;
	settings.signingKey = key;
	settings.nick = nick;
	settings.bluetooth = false;
	settings.network = true;
	settings.encryption = ofxBraid::Encryption::Force;
	return settings;
}

template <typename Done>
bool pump(ofxBraid::Mailbox & host, ofxBraid::Mailbox & client, Done done, int timeoutMs = 5000) {
	const auto start = ofGetElapsedTimeMillis();
	while (!done()) {
		if (ofGetElapsedTimeMillis() - start > static_cast<uint64_t>(timeoutMs)) {
			return false;
		}
		host.update();
		client.update();
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	return true;
}

std::string frame(char kind, std::uint32_t seq, const std::string & peer, const std::string & body) {
	char seqHex[9];
	std::snprintf(seqHex, sizeof(seqHex), "%08x", seq);
	return std::string("#L ") + kind + " " + seqHex + " " + peer + " " + body;
}

const ofxBraid::User * findUser(const ofxBraid::Mailbox & box, const std::string & peer) {
	for (const auto & user : box.users()) {
		if (user.peerId == peer) {
			return &user;
		}
	}
	return nullptr;
}

} // namespace

class ofApp : public ofxUnitTestsApp {
	void run() {
		testLocal();
		testPeers();
		testEncryption();
		testSecurity();
	}

	void testLocal() {
		ofxBraid::Mailbox box;
		ofxBraid::Settings settings = person(kHostPeer, kHostKey, "RoomCaller", true);
		settings.network = false;
		settings.bluetooth = false;
		settings.listen = false;
		box.setup(nullptr, settings);

		ofxTest(box.send("") == 0, "empty body is refused");
		settings.peerId = "short";
		box.setup(nullptr, settings);
		ofxTest(box.send("#G M city") == 0, "short peer id is refused");

		settings.peerId = kHostPeer;
		box.setup(nullptr, settings);
		const auto first = box.send("#G M city");
		ofxTest(first == 1, "first local seq");
		auto mine = box.take();
		ofxTestEq(mine.size(), std::size_t(1), "one local copy");
		if (!mine.empty()) {
			ofxTest(mine[0].mine, "local copy is mine");
			ofxTestEq(mine[0].fromPeer, kHostPeer, "local peer id");
			ofxTestEq(mine[0].body, std::string("#G M city"), "local body");
			ofxTestEq(mine[0].seq, first, "local seq");
		}
		box.update();
		ofxTest(box.take().empty(), "presence is not a game packet");

		const std::string status = box.status();
		ofxTest(status.find("network off") != std::string::npos, "status names network off");
		ofxTest(status.find("bluetooth off") != std::string::npos, "status names bluetooth off");
		ofxTest(status.find("udp aes-256-gcm") != std::string::npos, "default cipher label");

		box.setPolicy(true, false, ofxBraid::Encryption::Off);
		ofxTest(box.status().find("udp plaintext") != std::string::npos, "encryption off label");
		ofxTest(box.status().find("bluetooth off") == std::string::npos, "bluetooth on drops that phrase");

		settings = person(kHostPeer, kHostKey, "RoomCaller", false);
		settings.connectHost.clear();
		settings.bluetooth = true;
		settings.encryption = ofxBraid::Encryption::ForceHigh;
		box.setup(nullptr, settings);
		ofxTest(box.status().find("radio only") != std::string::npos, "empty host stays on the radio");
		ofxTest(box.status().find("udp aes-256-gcm high") != std::string::npos, "high cipher label");
		const auto radioSeq = box.send("#G M local", ofxBraid::Priority::Radio);
		ofxTest(radioSeq != 0, "radio priority still records the line");
		ofxTestEq(box.take().size(), std::size_t(1), "radio priority is local when the mesh is down");
		box.stop();
	}

	void testPeers() {
		ofxBraid::Mailbox host;
		ofxBraid::Mailbox client;
		host.setup(nullptr, person(kHostPeer, kHostKey, "RoomCaller", true));
		client.setup(nullptr, person(kClientPeer, kClientKey, "phone", false));
		ofxTest(host.status().find("listening") != std::string::npos, "host listens on " + ofToString(kPort));

		ofxTest(pump(host, client, [&] {
			return host.status().find("net 1") != std::string::npos
				&& client.status().find("net 1") != std::string::npos;
		}), "both sides connect");
		ofxTest(pump(host, client, [&] {
			const auto * user = findUser(host, kClientPeer);
			return user != nullptr && user->signingKey == kClientKey && user->nick == "phone" && user->net;
		}), "presence binds the bluetooth person on the socket");
		const auto * user = findUser(host, kClientPeer);
		if (user != nullptr) {
			ofxTest(!user->radio, "this socket is not the radio path");
			ofxTest(user->netId != 0, "enet id is only a path handle");
		}
		host.take();
		client.take();

		const auto seq = client.send("#G M city");
		ofxTest(seq != 0, "client sends a move");
		auto local = client.take();
		ofxTestEq(local.size(), std::size_t(1), "sender keeps one copy");
		std::vector<ofxBraid::Packet> got;
		ofxTest(pump(host, client, [&] {
			auto next = host.take();
			if (!next.empty()) {
				got.insert(got.end(), next.begin(), next.end());
			}
			return !got.empty();
		}), "host receives the move");
		ofxTestEq(got.size(), std::size_t(1), "one delivery");
		if (!got.empty()) {
			ofxTestEq(got[0].seq, seq, "same packet id");
			ofxTestEq(got[0].fromPeer, kClientPeer, "user id stays the bluetooth peer id");
			ofxTestEq(got[0].nick, std::string("phone"), "nick from presence");
			ofxTestEq(got[0].body, std::string("#G M city"), "move body");
			ofxTest(!got[0].mine, "host copy is the other person");
			ofxTest(!got[0].fromRadio, "copy arrived on the network");
		}
		host.update();
		client.update();
		ofxTest(host.take().empty(), "the same packet is not delivered twice");

		client.send("#G M radio", ofxBraid::Priority::Radio);
		ofxTestEq(client.take().size(), std::size_t(1), "radio priority is kept locally");
		pump(host, client, [&] { return false; }, 200);
		ofxTest(host.take().empty(), "radio priority does not cross the socket");

		host.stop();
		client.stop();
	}

	void testEncryption() {
		ofxBraid::Mailbox host;
		ofxBraid::Mailbox client;
		auto hostSettings = person(kHostPeer, kHostKey, "RoomCaller", true);
		auto clientSettings = person(kClientPeer, kClientKey, "phone", false);
		hostSettings.encryption = ofxBraid::Encryption::Off;
		clientSettings.encryption = ofxBraid::Encryption::Off;
		host.setup(nullptr, hostSettings);
		client.setup(nullptr, clientSettings);
		ofxTest(pump(host, client, [&] {
			return host.status().find("net 1") != std::string::npos
				&& client.status().find("net 1") != std::string::npos;
		}), "plaintext room connects");

		auto expect = [&](const std::string & body, bool arrives, const std::string & name) {
			host.take();
			client.take();
			client.send(body);
			client.take();
			std::vector<ofxBraid::Packet> got;
			pump(host, client, [&] {
				auto next = host.take();
				if (!next.empty()) {
					got.insert(got.end(), next.begin(), next.end());
				}
				return !got.empty();
			}, arrives ? 3000 : 400);
			if (arrives) {
				ofxTestEq(got.size(), std::size_t(1), name);
				if (!got.empty()) {
					ofxTestEq(got[0].body, body, name + " body");
				}
			} else {
				ofxTest(got.empty(), name);
			}
		};

		expect("#G M plain", true, "matching plaintext arrives");
		host.setPolicy(false, true, ofxBraid::Encryption::Force);
		expect("#G M dropped", false, "plaintext is dropped when the host forces encryption");
		client.setPolicy(false, true, ofxBraid::Encryption::Force);
		ofxTest(host.status().find("udp aes-256-gcm") != std::string::npos, "force label");
		expect("#G M sealed", true, "matching force arrives");
		host.setPolicy(false, true, ofxBraid::Encryption::ForceHigh);
		client.setPolicy(false, true, ofxBraid::Encryption::ForceHigh);
		ofxTest(host.status().find("high") != std::string::npos, "high label");
		expect("#G M stretched", true, "matching high arrives");
		client.setPolicy(false, true, ofxBraid::Encryption::Force);
		if (kPassphraseTakesRounds) {
			expect("#G M mismatch", false, "force and high do not open each other");
		} else {
			expect("#G M same stretch", true, "this ofxENet seals force and high the same way");
		}
		host.stop();
		client.stop();
	}

	void testSecurity() {
		ofxBraid::Mailbox host;
		auto settings = person(kHostPeer, kHostKey, "RoomCaller", true);
		settings.port = kAttackPort;
		host.setup(nullptr, settings);
		ofxTest(host.status().find("listening") != std::string::npos, "security host is listening");

		ofxENet::Peer stranger;
		stranger.startClient();
		bool rejected = false;
		auto rejectListener = stranger.onDisconnect.newListener([&](ofxENet::DisconnectionEvent & event) {
			rejected = event.reason == ofxENet::DisconnectionEvent::Reason::InvalidPassword;
		});
		stranger.connect("127.0.0.1", kAttackPort, "wrong-pass");
		ofxTest(pumpOne(host, stranger, [&] { return rejected; }), "wrong room password is rejected");
		ofxTest(host.status().find("net 0") != std::string::npos, "a rejected peer is not in the room");
		ofxTest(host.take().empty(), "a rejected peer delivered nothing");
		stranger.stop();

		ofxENet::Peer attacker;
		attacker.startClient();
		ofxENet::PeerId serverId = 0;
		auto connectListener = attacker.onConnect.newListener([&](ofxENet::ConnectionEvent & event) {
			serverId = event.peer;
		});
		attacker.connect("127.0.0.1", kAttackPort, kPass);
		ofxTest(pumpOne(host, attacker, [&] {
			return serverId != 0 && host.status().find("net 1") != std::string::npos;
		}), "the room password opens the socket");

		const std::string forgedPeer = "ffffffffffffffff";
		attacker.send(serverId, ofxBraid::messageType, frame('n', 1, forgedPeer, "#G M forged"));
		pumpOne(host, attacker, [&] { return false; }, 400);
		ofxTest(host.take().empty(), "plaintext is dropped while encryption is forced");
		ofxTest(findUser(host, forgedPeer) == nullptr, "a stranger does not become a person");

		attacker.setPassphrase(kPass);
		attacker.send(serverId, ofxBraid::messageType, frame('n', 7, forgedPeer, "#G M sealed"));
		std::vector<ofxBraid::Packet> got;
		ofxTest(pumpOne(host, attacker, [&] {
			auto next = host.take();
			if (!next.empty()) {
				got.insert(got.end(), next.begin(), next.end());
			}
			return !got.empty();
		}), "the matching cipher admits the line");
		ofxTestEq(got.size(), std::size_t(1), "one admitted line");
		if (!got.empty()) {
			ofxTestEq(got[0].fromPeer, forgedPeer, "the peer id is the one inside the sealed line");
			ofxTestEq(got[0].body, std::string("#G M sealed"), "sealed body");
		}

		attacker.send(serverId, ofxBraid::messageType, frame('n', 7, forgedPeer, "#G M sealed"));
		pumpOne(host, attacker, [&] { return false; }, 400);
		ofxTest(host.take().empty(), "replaying the same packet id is dropped");

		attacker.send(serverId, ofxBraid::messageType, frame('n', 8, "FFFFFFFFFFFFFFFF", "#G M upper"));
		attacker.send(serverId, ofxBraid::messageType, std::string("#L n 00"));
		attacker.send(serverId, ofxBraid::messageType, std::string("not a braid line"));
		attacker.send(serverId, 99, frame('n', 9, forgedPeer, "#G M other-type"));
		std::uint32_t state = 0x12345678u;
		for (int i = 0; i < 40; ++i) {
			state = state * 1664525u + 1013904223u;
			std::string junk(16 + (state % 48), static_cast<char>(state & 0xff));
			if (junk.compare(0, 3, "#L ") == 0) {
				junk[0] = 'x';
			}
			attacker.send(serverId, ofxBraid::messageType, junk);
		}
		pumpOne(host, attacker, [&] { return false; }, 500);
		ofxTest(host.take().empty(), "malformed frames are ignored");
		host.stop();
		attacker.stop();
	}

	template <typename Done>
	bool pumpOne(ofxBraid::Mailbox & host, ofxENet::Peer & peer, Done done, int timeoutMs = 5000) {
		const auto start = ofGetElapsedTimeMillis();
		while (!done()) {
			if (ofGetElapsedTimeMillis() - start > static_cast<uint64_t>(timeoutMs)) {
				return false;
			}
			host.update();
			peer.update();
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
		return true;
	}
};
