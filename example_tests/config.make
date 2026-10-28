OF_ROOT = ../../..

# Optional third tunnel. ofxBraid stays ENet-only unless the app sets this
# and lists ofxRakNet (mafianet branch) in addons.make.
PROJECT_CFLAGS += -DOFXBRAID_USE_RAKNET
