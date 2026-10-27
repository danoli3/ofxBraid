#pragma once

#include "ofxENet.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// ofxBraid keeps one person on two paths.
//
// The person is the Bluetooth identity file. On the wire that is the 16-hex
// peer id (stable across launches). A presence line also carries the 64-hex
// Ed25519 signing key, which is what an allowlist already uses. An ENet peer
// number is only the UDP socket for this process. It is never the user id.
//
// Priority::Net sends on ENet when any peer is connected. If that send fails,
// or a peer drops within two seconds, the same packet id is sent on the
// Bluetooth mesh. Priority::Radio is the mesh only. Priority::Both is how a
// presence line reaches a phone that has only one of the two paths.
// The receiver keeps the first copy of (peer id, seq).

namespace ofxBraid {

// UDP message type for a braid line. Other types are ignored.
constexpr std::uint8_t messageType = 11;

// The mesh is supplied by the app. ofxBluetoothLE's session fits SessionRadio.
class Radio {
public:
	virtual ~Radio() = default;
	virtual void sendPublic(const std::string & text) = 0;
	virtual std::size_t size() const = 0;
	virtual std::string textAt(std::size_t index) const = 0;
	virtual bool mineAt(std::size_t index) const = 0;
};

template <typename Mesh>
class SessionRadio : public Radio {
public:
	explicit SessionRadio(Mesh * mesh) : mesh(mesh) {}
	void sendPublic(const std::string & text) override { mesh->sendPublic(text); }
	std::size_t size() const override { return mesh->lines().size(); }
	std::string textAt(std::size_t index) const override { return mesh->lines()[index].text; }
	bool mineAt(std::size_t index) const override { return mesh->lines()[index].mine; }

private:
	Mesh * mesh = nullptr;
};

enum class Priority {
	Net,
	Radio,
	Both,
};

// Off: UDP payloads are plaintext. Force: AES-256-GCM and plaintext is
// dropped. ForceHigh: the same cipher with a longer PBKDF2 stretch.
// Both devices have to use the same mode. The Bluetooth mesh seal is
// separate and stays on while the radio is up.
enum class Encryption {
	Off,
	Force,
	ForceHigh,
};

struct Settings {
	bool listen = false;
	std::string connectHost;
	std::uint16_t port = 60100;
	std::string passphrase;
	std::string peerId;
	std::string signingKey;
	std::string nick;
	bool bluetooth = true;
	bool network = true;
	Encryption encryption = Encryption::Force;
};

struct User {
	std::string peerId;
	std::string signingKey;
	std::string nick;
	std::string netAddress;
	ofxENet::PeerId netId = 0;
	double radioSeen = 0;
	double netSeen = 0;
	bool radio = false;
	bool net = false;
};

struct Packet {
	std::uint32_t seq = 0;
	std::string fromPeer;
	std::string nick;
	std::string body;
	bool mine = false;
	bool fromRadio = false;
};

class Mailbox {
public:
	Mailbox() = default;
	~Mailbox();

	Mailbox(const Mailbox &) = delete;
	Mailbox & operator=(const Mailbox &) = delete;

	void setup(Radio * radio, const Settings & settings);
	void update();
	void stop();
	// Live switches. Network off closes the UDP socket. Bluetooth off skips
	// the mesh. Encryption applies to UDP on the next packet.
	void setPolicy(bool bluetooth, bool network, Encryption encryption);
	// Call after the mesh is started again so old lines are not replayed.
	void noteRadio();

	// body is the game line or chat line, without the braid header.
	// An empty room on the net path is sent on the radio immediately.
	std::uint32_t send(const std::string & body, Priority priority = Priority::Net);

	std::vector<Packet> take();
	const std::vector<User> & users() const { return roster; }
	std::string status() const;

private:
	struct Recent {
		std::string wire;
		double at = 0;
		bool sentRadio = false;
	};

	void onConnect(ofxENet::ConnectionEvent & event);
	void onDisconnect(ofxENet::DisconnectionEvent & event);
	void onMessage(ofxENet::MessageEvent & event);
	void ingest(const std::string & text, bool fromRadio, bool mine);
	void bindNet(const std::string & peer, ofxENet::PeerId id, const std::string & address);
	User & ensure(const std::string & peer);
	bool remember(const std::string & peer, std::uint32_t seq);
	void sendRadio(const std::string & wire);
	void refresh();
	void applyCipher();
	void startNet();
	void stopNet();
	std::string encryptionLabel() const;

	Radio * radio = nullptr;
	ofxENet::Peer net;
	ofEventListener connectListener;
	ofEventListener disconnectListener;
	ofEventListener messageListener;

	Settings settings;
	std::vector<User> roster;
	std::vector<Packet> inbox;
	std::vector<Recent> recent;
	std::vector<std::pair<std::string, double>> seen;
	std::size_t seenMesh = 0;
	std::uint32_t nextSeq = 0;
	double nextPresence = 0;
	bool listening = false;
	std::string dialState;
};

} // namespace ofxBraid
