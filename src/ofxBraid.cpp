#include "ofxBraid.h"

#include "ofLog.h"
#include "ofUtils.h"

#include <cstdio>
#include <cstdlib>

namespace ofxBraid {

namespace {

constexpr double kRetrySeconds = 2.0;
constexpr double kPathSeconds = 6.0;
constexpr double kSeenSeconds = 30.0;
constexpr int kForceIterations = 200000;
constexpr int kHighIterations = 1000000;

// danoli3/ofxENet origin takes the passphrase only (200000 rounds). A newer
// Peer::setPassphrase forwards the iteration count. ForceHigh uses it when
// that overload is present, and the default stretch otherwise.
template <typename Peer>
auto applyPassphrase(Peer & peer, const std::string & pass, int rounds, int)
	-> decltype(peer.setPassphrase(pass, rounds), void()) {
	peer.setPassphrase(pass, rounds);
}

template <typename Peer>
void applyPassphrase(Peer & peer, const std::string & pass, int, long) {
	peer.setPassphrase(pass);
}

bool isHex(const std::string & text) {
	if (text.empty()) {
		return false;
	}
	for (const char c : text) {
		const bool digit = c >= '0' && c <= '9';
		const bool lower = c >= 'a' && c <= 'f';
		if (!digit && !lower) {
			return false;
		}
	}
	return true;
}

struct Wire {
	Priority priority = Priority::Net;
	std::uint32_t seq = 0;
	std::string peer;
	std::string body;
};

char priorityChar(Priority priority) {
	if (priority == Priority::Radio) {
		return 'r';
	}
	if (priority == Priority::Both) {
		return 'b';
	}
	return 'n';
}

std::string formatWire(Priority priority, std::uint32_t seq, const std::string & peer, const std::string & body) {
	char seqHex[9];
	std::snprintf(seqHex, sizeof(seqHex), "%08x", seq);
	return std::string("#L ") + priorityChar(priority) + " " + seqHex + " " + peer + " " + body;
}

bool parseWire(const std::string & line, Wire * out) {
	// "#L <n|r|b> <8 hex> <16 hex> <body>"
	if (out == nullptr || line.size() < 31 || line.compare(0, 3, "#L ") != 0) {
		return false;
	}
	if (line[4] != ' ' || line[13] != ' ' || line[30] != ' ') {
		return false;
	}
	const char kind = line[3];
	if (kind != 'n' && kind != 'r' && kind != 'b') {
		return false;
	}
	const std::string seqText = line.substr(5, 8);
	const std::string peer = line.substr(14, 16);
	if (!isHex(seqText) || !isHex(peer)) {
		return false;
	}
	if (kind == 'r') {
		out->priority = Priority::Radio;
	} else if (kind == 'b') {
		out->priority = Priority::Both;
	} else {
		out->priority = Priority::Net;
	}
	out->seq = static_cast<std::uint32_t>(std::strtoul(seqText.c_str(), nullptr, 16));
	out->peer = peer;
	out->body = line.substr(31);
	return true;
}

} // namespace

Mailbox::~Mailbox() {
	stop();
}

void Mailbox::setup(Radio * mesh, const Settings & next) {
	stop();
	radio = mesh;
	settings = next;
	seenMesh = radio == nullptr ? 0 : radio->size();
	nextPresence = 0;
	nextSeq = 0;
	listening = false;
	dialState.clear();
	startNet();
}

void Mailbox::stopNet() {
	connectListener.unsubscribe();
	disconnectListener.unsubscribe();
	messageListener.unsubscribe();
	if (net.isRunning()) {
		net.stop();
	}
	listening = false;
}

void Mailbox::stop() {
	stopNet();
	radio = nullptr;
}

void Mailbox::applyCipher() {
	if (settings.encryption == Encryption::Off || settings.passphrase.empty()) {
		net.setPassphrase("");
		net.requireEncryption = false;
		return;
	}
	const int rounds = settings.encryption == Encryption::ForceHigh ? kHighIterations : kForceIterations;
	applyPassphrase(net, settings.passphrase, rounds, 0);
	net.requireEncryption = true;
}

void Mailbox::startNet() {
	stopNet();
	applyCipher();
	if (!settings.network) {
		dialState = "network off";
		return;
	}
	if (settings.listen) {
		listening = net.startServer(settings.port, 16, settings.passphrase);
		dialState = listening ? "listening" : "port busy";
		ofLogNotice("ofxBraid") << (listening ? "listening on " : "could not listen on ") << settings.port;
	} else if (!settings.connectHost.empty()) {
		if (net.startClient()) {
			net.connect(settings.connectHost, settings.port, settings.passphrase);
			dialState = "dialing";
			ofLogNotice("ofxBraid") << "dialing " << settings.connectHost << ":" << settings.port;
		} else {
			dialState = "dial failed";
		}
	} else {
		dialState = "radio only";
	}
	if (net.isRunning()) {
		connectListener = net.onConnect.newListener([this](ofxENet::ConnectionEvent & event) { onConnect(event); });
		disconnectListener = net.onDisconnect.newListener([this](ofxENet::DisconnectionEvent & event) { onDisconnect(event); });
		messageListener = net.onMessage.newListener([this](ofxENet::MessageEvent & event) { onMessage(event); });
	}
}

void Mailbox::setPolicy(bool bluetooth, bool network, Encryption encryption) {
	const bool wasNetwork = settings.network;
	const Encryption wasEncryption = settings.encryption;
	settings.bluetooth = bluetooth;
	settings.network = network;
	settings.encryption = encryption;
	if (encryption != wasEncryption) {
		applyCipher();
	}
	if (network == wasNetwork) {
		return;
	}
	if (!network) {
		for (auto & item : recent) {
			if (!item.sentRadio) {
				sendRadio(item.wire);
				item.sentRadio = true;
			}
		}
		stopNet();
		dialState = "network off";
		return;
	}
	startNet();
}

void Mailbox::noteRadio() {
	seenMesh = radio == nullptr ? 0 : radio->size();
}

void Mailbox::update() {
	refresh();
	if (net.isRunning()) {
		net.update();
	}
	if (radio != nullptr && settings.bluetooth) {
		while (seenMesh < radio->size()) {
			ingest(radio->textAt(seenMesh), true, radio->mineAt(seenMesh));
			++seenMesh;
		}
	} else if (radio != nullptr) {
		seenMesh = radio->size();
	}
	const double now = ofGetElapsedTimef();
	if (settings.peerId.size() == 16 && now >= nextPresence) {
		nextPresence = now + 2.0;
		send("#P " + settings.signingKey + " " + settings.nick, Priority::Both);
	}
}

std::uint32_t Mailbox::send(const std::string & body, Priority priority) {
	if (settings.peerId.size() != 16 || body.empty()) {
		return 0;
	}
	const std::uint32_t seq = ++nextSeq;
	const std::string wire = formatWire(priority, seq, settings.peerId, body);
	remember(settings.peerId, seq);
	if (body.compare(0, 3, "#P ") != 0) {
		Packet packet;
		packet.seq = seq;
		packet.fromPeer = settings.peerId;
		packet.nick = settings.nick;
		packet.body = body;
		packet.mine = true;
		inbox.push_back(packet);
	}
	bool sentNet = false;
	if (settings.network && priority != Priority::Radio && net.isRunning() && net.getNumConnections() > 0) {
		sentNet = net.broadcast(messageType, wire);
	}
	const bool wantRadio = settings.bluetooth && (priority == Priority::Radio || priority == Priority::Both || !sentNet);
	if (wantRadio) {
		sendRadio(wire);
		return seq;
	}
	Recent held;
	held.wire = wire;
	held.at = ofGetElapsedTimef();
	recent.push_back(held);
	return seq;
}

std::vector<Packet> Mailbox::take() {
	std::vector<Packet> out;
	out.swap(inbox);
	return out;
}

std::string Mailbox::status() const {
	std::string text = "braid  " + dialState + "  " + encryptionLabel();
	if (!settings.bluetooth) {
		text += "  bluetooth off";
	}
	if (listening) {
		text += " :" + ofToString(settings.port);
	} else if (!settings.connectHost.empty()) {
		text += " " + settings.connectHost + ":" + ofToString(settings.port);
	}
	text += "   net " + ofToString(net.isRunning() ? net.getNumConnections() : 0);
	for (const auto & user : roster) {
		if (user.peerId == settings.peerId) {
			continue;
		}
		text += "\n";
		text += user.nick.empty() ? user.peerId : user.nick;
		if (user.radio) {
			text += "  radio";
		}
		if (user.net) {
			text += "  net";
		}
		if (user.signingKey.size() >= 8) {
			text += "  " + user.signingKey.substr(0, 8);
		}
	}
	return text;
}

void Mailbox::onConnect(ofxENet::ConnectionEvent & event) {
	dialState = listening ? "listening" : "up";
	ofLogNotice("ofxBraid") << "net up " << event.address << " id " << event.peer;
}

void Mailbox::onDisconnect(ofxENet::DisconnectionEvent & event) {
	for (auto & user : roster) {
		if (user.netId == event.peer) {
			user.net = false;
			user.netId = 0;
		}
	}
	if (!listening && net.getNumConnections() == 0) {
		dialState = event.reason == ofxENet::DisconnectionEvent::Reason::ConnectFailed ? "dial failed" : "down";
	}
	ofLogNotice("ofxBraid") << "net down " << ofxENet::toString(event.reason);
	const double now = ofGetElapsedTimef();
	for (auto & item : recent) {
		if (item.sentRadio || now - item.at > kRetrySeconds) {
			continue;
		}
		ofLogNotice("ofxBraid") << "radio retry";
		sendRadio(item.wire);
		item.sentRadio = true;
	}
}

void Mailbox::onMessage(ofxENet::MessageEvent & event) {
	if (event.type != messageType) {
		return;
	}
	if (net.requireEncryption && !event.authentic) {
		return;
	}
	Wire wire;
	if (!parseWire(event.getText(), &wire)) {
		return;
	}
	bindNet(wire.peer, event.peer, event.address);
	ingest(event.getText(), false, false);
}

void Mailbox::ingest(const std::string & text, bool fromRadio, bool mine) {
	Wire wire;
	if (!parseWire(text, &wire)) {
		return;
	}
	const double now = ofGetElapsedTimef();
	User & user = ensure(wire.peer);
	if (fromRadio) {
		user.radio = true;
		user.radioSeen = now;
	} else {
		user.net = true;
		user.netSeen = now;
	}
	if (!remember(wire.peer, wire.seq)) {
		return;
	}
	if (wire.body.compare(0, 3, "#P ") == 0 && wire.body.size() >= 3 + 64 && isHex(wire.body.substr(3, 64))) {
		user.signingKey = wire.body.substr(3, 64);
		if (wire.body.size() > 3 + 64 + 1) {
			user.nick = wire.body.substr(3 + 64 + 1);
		}
		return;
	}
	Packet packet;
	packet.seq = wire.seq;
	packet.fromPeer = wire.peer;
	packet.nick = user.nick.empty() ? wire.peer : user.nick;
	packet.body = wire.body;
	packet.mine = mine || wire.peer == settings.peerId;
	packet.fromRadio = fromRadio;
	inbox.push_back(packet);
}

void Mailbox::bindNet(const std::string & peer, ofxENet::PeerId id, const std::string & address) {
	for (auto & user : roster) {
		if (user.netId == id && user.peerId != peer) {
			user.netId = 0;
			user.net = false;
		}
	}
	User & user = ensure(peer);
	user.netId = id;
	user.netAddress = address;
	user.net = true;
	user.netSeen = ofGetElapsedTimef();
}

User & Mailbox::ensure(const std::string & peer) {
	for (auto & user : roster) {
		if (user.peerId == peer) {
			return user;
		}
	}
	User created;
	created.peerId = peer;
	roster.push_back(created);
	return roster.back();
}

bool Mailbox::remember(const std::string & peer, std::uint32_t seq) {
	const std::string key = peer + ":" + ofToString(seq);
	const double now = ofGetElapsedTimef();
	for (const auto & item : seen) {
		if (item.first == key) {
			return false;
		}
	}
	seen.emplace_back(key, now);
	return true;
}

void Mailbox::sendRadio(const std::string & wire) {
	if (settings.bluetooth && radio != nullptr) {
		radio->sendPublic(wire);
	}
}

std::string Mailbox::encryptionLabel() const {
	if (settings.encryption == Encryption::Off) {
		return "udp plaintext";
	}
	if (settings.encryption == Encryption::ForceHigh) {
		return "udp aes-256-gcm high";
	}
	return "udp aes-256-gcm";
}

void Mailbox::refresh() {
	const double now = ofGetElapsedTimef();
	for (auto & user : roster) {
		if (user.radio && now - user.radioSeen > kPathSeconds) {
			user.radio = false;
		}
		if (user.net && user.netId == 0 && now - user.netSeen > kPathSeconds) {
			user.net = false;
		}
	}
	std::vector<std::pair<std::string, double>> keptSeen;
	for (const auto & item : seen) {
		if (now - item.second <= kSeenSeconds) {
			keptSeen.push_back(item);
		}
	}
	seen.swap(keptSeen);
	std::vector<Recent> kept;
	for (const auto & item : recent) {
		if (!item.sentRadio && now - item.at <= kRetrySeconds) {
			kept.push_back(item);
		}
	}
	recent.swap(kept);
}

} // namespace ofxBraid
