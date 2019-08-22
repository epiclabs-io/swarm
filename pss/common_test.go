package pss

import (
	"crypto/ecdsa"
	"flag"
	"fmt"

	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common/hexutil"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/simulations/adapters"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethersphere/swarm/network"
	"github.com/ethersphere/swarm/network/simulation"
	"github.com/ethersphere/swarm/state"
)

var (
	initOnce        = sync.Once{}
	loglevel        = flag.Int("loglevel", 2, "logging verbosity")
	longrunning     = flag.Bool("longrunning", false, "do run long-running tests")
	psslogmain      log.Logger
	pssprotocols    map[string]*protoCtrl
	useHandshake    bool
	noopHandlerFunc = func(msg []byte, p *p2p.Peer, asymmetric bool, keyid string) error {
		return nil
	}
	defNeighSize      = 2
	DefaultTestParams = testParams{NeighbourhoodSize: &defNeighSize, AllowRaw: false}
)

// needed to make the enode id of the receiving node available to the handler for triggers
type HandlerContextFunc func(*adapters.NodeConfig) *handler

type TestContextI interface {
	nodeMessageHandlers() map[Topic]HandlerContextFunc
	getKademlias() map[enode.ID]*network.Kademlia
}

// setup simulated network with bzz/discovery and pss services.
// connects nodes in a circle
func setupNetwork(numnodes int, allowRaw bool) (clients []*rpc.Client, closeSimFunc func(), err error) {
	clients = make([]*rpc.Client, numnodes)
	if numnodes < 2 {
		return nil, nil, fmt.Errorf("minimum two nodes in network")
	}

	sim := simulation.NewInProc(newServices(testParams{NeighbourhoodSize: &defNeighSize, AllowRaw: allowRaw}))
	closeSimFunc = sim.Close
	if numnodes == 2 {
		_, err = sim.AddNodesAndConnectChain(numnodes)

	} else {
		_, err = sim.AddNodesAndConnectRing(numnodes)
	}
	if err != nil {
		return nil, nil, err
	}

	nodes := sim.Net.GetNodes()
	for id, node := range nodes {
		client, err := node.Client()
		if err != nil {
			return nil, nil, fmt.Errorf("error getting the nodes clients")
		}
		clients[id] = client
	}
	return clients, closeSimFunc, nil
}

type testParams struct {
	NeighbourhoodSize *int
	AllowRaw          bool
}

func newServices(testParams testParams) map[string]simulation.ServiceFunc {
	return newServicesWithHandlers(newEmptyTestContext(), testParams)
}

// an adaptation of the same services setup as in pss_test.go
// replaces pss_test.go when those tests are rewritten to the new swarm/network/simulation package
func newServicesWithHandlers(td TestContextI, testParams testParams) map[string]simulation.ServiceFunc {
	stateStore := state.NewInmemoryStore()
	kademlias := td.getKademlias()
	kademlia := func(id enode.ID, bzzkey []byte) *network.Kademlia {
		if k, ok := kademlias[id]; ok {
			return k
		}
		params := network.NewKadParams()
		if testParams.NeighbourhoodSize != nil {
			params.NeighbourhoodSize = *testParams.NeighbourhoodSize
		}
		params.MaxBinSize = 3
		params.MinBinSize = 1
		params.MaxRetries = 1000
		params.RetryExponent = 2
		params.RetryInterval = 1000000
		kademlias[id] = network.NewKademlia(bzzkey, params)
		return kademlias[id]
	}
	return map[string]simulation.ServiceFunc{
		"bzz": func(ctx *adapters.ServiceContext, bucket *sync.Map) (node.Service, func(), error) {
			initTest()
			var err error
			var bzzPrivateKey *ecdsa.PrivateKey
			// normally translation of enode id to swarm address is concealed by the network package
			// however, we need to keep track of it in the test driver as well.
			// if the translation in the network package changes, that can cause these tests to unpredictably fail
			// therefore we keep a local copy of the translation here
			addr := network.NewAddr(ctx.Config.Node())
			bzzPrivateKey, err = simulation.BzzPrivateKeyFromConfig(ctx.Config)
			if err != nil {
				return nil, nil, err
			}
			bzzKey := network.PrivateKeyToBzzKey(bzzPrivateKey)
			addr.OAddr = bzzKey
			bucket.Store(simulation.BucketKeyBzzPrivateKey, bzzPrivateKey)
			hp := network.NewHiveParams()
			hp.Discovery = false
			config := &network.BzzConfig{
				OverlayAddr:  addr.Over(),
				UnderlayAddr: addr.Under(),
				HiveParams:   hp,
			}
			pskad := kademlia(ctx.Config.ID, bzzKey)
			bucket.Store(simulation.BucketKeyKademlia, pskad)
			return network.NewBzz(config, pskad, stateStore, nil, nil), nil, nil
		},
		protocolName: func(ctx *adapters.ServiceContext, bucket *sync.Map) (node.Service, func(), error) {
			// execadapter does not exec init()
			initTest()

			// create keys in cryptoUtils and set up the pss object
			privkey, err := ethCrypto.GenerateKey()
			pssp := NewParams().WithPrivateKey(privkey)
			pssp.AllowRaw = testParams.AllowRaw
			bzzPrivateKey, err := simulation.BzzPrivateKeyFromConfig(ctx.Config)
			if err != nil {
				return nil, nil, err
			}
			bzzKey := network.PrivateKeyToBzzKey(bzzPrivateKey)
			pskad := kademlia(ctx.Config.ID, bzzKey)
			bucket.Store(simulation.BucketKeyKademlia, pskad)
			ps, err := New(pskad, pssp)
			if err != nil {
				return nil, nil, err
			}
			ping := &Ping{
				OutC: make(chan bool),
				Pong: true,
			}
			p2pp := NewPingProtocol(ping)
			pp, err := RegisterProtocol(ps, &PingTopic, PingProtocol, p2pp, &ProtocolParams{Asymmetric: true})
			if err != nil {
				return nil, nil, err
			}
			// register the handlers we've been passed
			var deregisters []func()
			for tpc, hndlrFunc := range td.nodeMessageHandlers() {
				deregisters = append(deregisters, ps.Register(&tpc, hndlrFunc(ctx.Config)))
			}
			deregisters = append(deregisters, ps.Register(&PingTopic, &handler{
				f: pp.Handle,
				caps: &handlerCaps{
					raw: true,
				},
			}))

			// if handshake mode is set, add the controller
			// TODO: This should be hooked to the handshake test file
			if useHandshake {
				SetHandshakeController(ps, NewHandshakeParams())
			}

			// we expose some api calls for cheating
			ps.addAPI(rpc.API{
				Namespace: "psstest",
				Version:   "0.3",
				Service:   NewAPITest(ps),
				Public:    false,
			})
			pssprotocols[ctx.Config.ID.String()] = &protoCtrl{
				C:        ping.OutC,
				protocol: pp,
				run:      p2pp.Run,
			}
			// return Pss and cleanups
			return ps, func() {
				// run the handler deregister functions in reverse order
				for i := len(deregisters); i > 0; i-- {
					deregisters[i-1]()
				}
			}, nil
		},
	}
}

func initTest() {
	initOnce.Do(
		func() {
			psslogmain = log.New("psslog", "*")
			hs := log.StreamHandler(os.Stderr, log.TerminalFormat(true))
			hf := log.LvlFilterHandler(log.Lvl(*loglevel), hs)
			h := log.CallerFileHandler(hf)
			log.Root().SetHandler(h)

			pssprotocols = make(map[string]*protoCtrl)
		},
	)
}

type protoCtrl struct {
	C        chan bool
	protocol *Protocol
	run      func(*p2p.Peer, p2p.MsgReadWriter) error
}

// API calls for test/development use
type APITest struct {
	*Pss
}

func NewAPITest(ps *Pss) *APITest {
	return &APITest{Pss: ps}
}

func (apitest *APITest) SetSymKeys(pubkeyid string, recvsymkey []byte, sendsymkey []byte, limit uint16, topic Topic, to hexutil.Bytes) ([2]string, error) {

	recvsymkeyid, err := apitest.SetSymmetricKey(recvsymkey, topic, PssAddress(to), true)
	if err != nil {
		return [2]string{}, err
	}
	sendsymkeyid, err := apitest.SetSymmetricKey(sendsymkey, topic, PssAddress(to), false)
	if err != nil {
		return [2]string{}, err
	}
	return [2]string{recvsymkeyid, sendsymkeyid}, nil
}

func (apitest *APITest) Clean() (int, error) {
	return apitest.Pss.cleanKeys(), nil
}

type emptyTestContext struct {
	kademlias map[enode.ID]*network.Kademlia
}

func newEmptyTestContext() TestContextI {
	return emptyTestContext{
		kademlias: make(map[enode.ID]*network.Kademlia),
	}
}

func (td emptyTestContext) nodeMessageHandlers() map[Topic]HandlerContextFunc {
	return make(map[Topic]HandlerContextFunc)
}
func (td emptyTestContext) getKademlias() map[enode.ID]*network.Kademlia {
	return td.kademlias
}
