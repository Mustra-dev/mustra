//go:build loadsim

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gonats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
)

type fleetCfg struct {
	nats           *natsOpts
	hbEvery        time.Duration
	factsEvery     time.Duration
	sensorEvery    time.Duration
	perfEvery      time.Duration
	eventsEvery    time.Duration
	customEvery    time.Duration
	spread         time.Duration
	commandLatency time.Duration
	fixedReconnect bool
	answerSpread   time.Duration
	p              *payloads
}

// fleetStats is everything the fleet measures. Counters are cumulative;
// latency windows reset when /stats?reset=1 is read, so a driver script can
// measure one phase at a time.
type fleetStats struct {
	start                       time.Time
	connected, registered       atomic.Int64
	connectErr, registerErr     atomic.Int64
	disconnects, reconnects     atomic.Int64
	expired, authErr            atomic.Int64
	pubOK, pubFail              atomic.Int64
	pubBytes                    atomic.Int64
	queries, queryAnswers       atomic.Int64
	reqOK, reqFail              atomic.Int64
	firstConnect, register, pub latencies
	reconnect, agentReq         latencies
	callout                     latencies
	callouts                    atomic.Int64
	lastRegistered              atomic.Int64 // unix nanos of the latest first registration
	cmdMu                       sync.Mutex
	cmds                        map[string]int
	cmdFirst, cmdLast           map[string]time.Time
	queryFirst, queryLast       atomic.Int64
}

type simAgent struct {
	id    identity
	cfg   *fleetCfg
	st    *fleetStats
	nc    *gonats.Conn
	js    jetstream.JetStream
	info  proto.AgentInfo
	facts proto.Facts
	disc  atomic.Int64 // unix nanos of the last disconnect
}

func runFleet(args []string) {
	fs := flag.NewFlagSet("fleet", flag.ExitOnError)
	cfg := &fleetCfg{nats: natsFlags(fs)}
	n := fs.Int("n", 50, "simulated agents")
	creds := fs.String("creds", "creds.jsonl", "identities from loadsim enroll")
	tdir := fs.String("templates", "templates", "payload templates from loadsim capture")
	fs.DurationVar(&cfg.hbEvery, "heartbeat", 10*time.Second, "heartbeat interval (agent default 10s)")
	fs.DurationVar(&cfg.factsEvery, "facts", 60*time.Second, "facts interval (agent default 60s)")
	fs.DurationVar(&cfg.sensorEvery, "sensor", 15*time.Minute, "sensor interval (agent default 15m)")
	fs.DurationVar(&cfg.perfEvery, "perf", 60*time.Second, "performance sensor interval (agent: 60s)")
	fs.DurationVar(&cfg.eventsEvery, "events", 5*time.Minute, "process/recorder event batch interval (0 disables)")
	fs.DurationVar(&cfg.customEvery, "custom", 5*time.Minute, "custom-sensor definition poll (agent: 5m)")
	fs.DurationVar(&cfg.spread, "spread", 0, "start agents uniformly over this window (0 = all at once: a storm)")
	fs.DurationVar(&cfg.commandLatency, "cmd-latency", 200*time.Millisecond, "how long a simulated package command 'runs'")
	fs.DurationVar(&cfg.answerSpread, "answer-spread", 0, "experiment: answer fleet-wide queries within this window instead of the one the server asks for")
	fs.BoolVar(&cfg.fixedReconnect, "fixed-reconnect", false, "reconnect after a fixed 2s, as agents did before FleetReconnectBackoff, for comparison")
	ctl := fs.String("ctl", "127.0.0.1:18803", "stats/control HTTP listener")
	observe := fs.Bool("observe", true, "time auth callouts as the broker sees them (needs -pass, the server's NATS password)")
	_ = fs.Parse(args)

	p, err := loadPayloads(*tdir)
	if err != nil {
		fatal(err)
	}
	cfg.p = p
	ids, err := loadIdentities(*creds, *n)
	if err != nil {
		fatal(err)
	}
	st := &fleetStats{start: time.Now(), cmds: map[string]int{}, cmdFirst: map[string]time.Time{}, cmdLast: map[string]time.Time{}}
	go serveStats(*ctl, st, *n)
	if *observe && cfg.nats.pass != "" {
		if err := observeCallouts(cfg.nats, st); err != nil {
			fatal(err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("starting %d agents (spread %s, sensors %v)\n", *n, cfg.spread, p.kinds)
	var wg sync.WaitGroup
	for i, id := range ids {
		a := &simAgent{id: id, cfg: cfg, st: st}
		delay := time.Duration(0)
		if cfg.spread > 0 {
			delay = time.Duration(float64(cfg.spread) * float64(i) / float64(len(ids)))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}
			a.run(ctx)
		}()
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			printStats(st, *n)
			return
		case <-tick.C:
			fmt.Printf("%s conn=%d reg=%d disc=%d reconn=%d expired=%d pub=%d/%d fail queries=%d cmds=%v\n",
				time.Now().Format("15:04:05"), st.connected.Load(), st.registered.Load(), st.disconnects.Load(),
				st.reconnects.Load(), st.expired.Load(), st.pubOK.Load(), st.pubFail.Load(), st.queryAnswers.Load(), st.cmdCounts())
		}
	}
}

func (st *fleetStats) cmdCounts() map[string]int {
	st.cmdMu.Lock()
	defer st.cmdMu.Unlock()
	out := map[string]int{}
	for k, v := range st.cmds {
		out[k] = v
	}
	return out
}

func (a *simAgent) run(ctx context.Context) {
	id := a.id
	a.info = proto.AgentInfo{Hostname: id.Hostname, OS: id.OS, Arch: "amd64", Site: id.Site, Version: simVersion}
	a.facts = a.cfg.p.facts
	a.facts.AgentID, a.facts.Hostname, a.facts.OS, a.facts.Site, a.facts.AgentVer = id.AgentID, id.Hostname, id.OS, id.Site, simVersion
	a.facts.IPs = []string{fmt.Sprintf("10.%d.%d.%d", 20+id.Index/65536, (id.Index/256)%256, id.Index%256)}
	a.facts.Settings = nil

	st := a.st
	t0 := time.Now()
	// The same options internal/nats.ConnectWithCreds gives a real agent.
	opts := []gonats.Option{
		gonats.Name("agent:" + id.Hostname),
		gonats.MaxReconnects(-1),
		gonats.ReconnectWait(2 * time.Second),
		gonats.ReconnectBufSize(-1),
		gonats.RootCAs(a.cfg.nats.ca),
		gonats.UserInfo(id.AgentID, id.Secret),
		gonats.IgnoreAuthErrorAbort(),
		reconnectOption(a.cfg.fixedReconnect),
		gonats.CustomInboxPrefix(bnats.AgentInboxPrefix(id.AgentID)),
		gonats.Timeout(20 * time.Second),
		gonats.DisconnectErrHandler(func(_ *gonats.Conn, err error) {
			st.disconnects.Add(1)
			st.connected.Add(-1)
			a.disc.Store(time.Now().UnixNano())
		}),
		gonats.ReconnectHandler(func(*gonats.Conn) {
			st.reconnects.Add(1)
			st.connected.Add(1)
			if d := a.disc.Load(); d > 0 {
				st.reconnect.add(time.Since(time.Unix(0, d)))
			}
		}),
		gonats.ErrorHandler(func(_ *gonats.Conn, _ *gonats.Subscription, err error) {
			msg := strings.ToLower(err.Error())
			switch {
			case strings.Contains(msg, "expired"):
				st.expired.Add(1)
			case strings.Contains(msg, "authoriz"):
				st.authErr.Add(1)
			}
		}),
	}
	var nc *gonats.Conn
	var err error
	for {
		nc, err = gonats.Connect(a.cfg.nats.url, opts...)
		if err == nil {
			break
		}
		st.connectErr.Add(1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second): // the agent's own retry cadence
		}
	}
	st.firstConnect.add(time.Since(t0))
	st.connected.Add(1)
	a.nc = nc
	defer nc.Close()

	if !a.register(ctx) {
		return
	}
	st.register.add(time.Since(t0))
	st.registered.Add(1)
	st.lastRegistered.Store(time.Now().UnixNano())

	a.js, _ = jetstream.New(nc)
	for _, subj := range []string{bnats.QAll(), bnats.QOS(id.OS), bnats.QSite(id.Site), bnats.QAgent(id.AgentID)} {
		if _, err := nc.Subscribe(subj, a.handleQuery); err != nil {
			fmt.Fprintln(os.Stderr, "subscribe:", err)
		}
	}
	_, _ = nc.Subscribe(bnats.Cmd(id.AgentID), a.handleCommand)
	_, _ = nc.Subscribe(bnats.Shell(id.AgentID), func(*gonats.Msg) {})

	go a.every(ctx, a.cfg.hbEvery, true, a.heartbeat)
	go a.every(ctx, a.cfg.factsEvery, true, a.publishFacts)
	go a.every(ctx, a.cfg.perfEvery, true, func(ctx context.Context) { a.publishSensor(ctx, "performance") })
	go a.every(ctx, a.cfg.sensorEvery, true, a.publishSensors)
	if a.cfg.eventsEvery > 0 {
		go a.every(ctx, a.cfg.eventsEvery, false, a.publishEvents)
	}
	go a.every(ctx, a.cfg.customEvery, true, func(ctx context.Context) {
		payload, _ := json.Marshal(proto.CustomSensorRequest{Version: 3})
		a.request(ctx, bnats.CustomSensors(id.AgentID), payload, 10*time.Second)
	})
	<-ctx.Done()
}

func (a *simAgent) register(ctx context.Context) bool {
	payload, _ := json.Marshal(proto.RegisterRequest{AgentID: a.id.AgentID, Info: a.info})
	backoff := time.Second
	for {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		msg, err := a.nc.RequestWithContext(rctx, bnats.RegisterAgent(a.id.AgentID), payload)
		cancel()
		if err == nil {
			var resp proto.RegisterResponse
			if json.Unmarshal(msg.Data, &resp) == nil && resp.AgentID == a.id.AgentID {
				return true
			}
		}
		a.st.registerErr.Add(1)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
}

// every runs f now (when immediate, as the agent's loops do at start) and
// then on a ticker.
func (a *simAgent) every(ctx context.Context, d time.Duration, immediate bool, f func(context.Context)) {
	if immediate {
		f(ctx)
	} else {
		// Spread the first tick so event batches do not land together.
		select {
		case <-time.After(time.Duration(rand.Int64N(int64(d)))):
			f(ctx)
		case <-ctx.Done():
			return
		}
	}
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f(ctx)
		}
	}
}

func (a *simAgent) publish(ctx context.Context, subject string, payload []byte) {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st := time.Now()
	if _, err := a.js.Publish(pctx, subject, payload); err != nil {
		if ctx.Err() == nil {
			a.st.pubFail.Add(1)
		}
		return
	}
	a.st.pub.add(time.Since(st))
	a.st.pubOK.Add(1)
	a.st.pubBytes.Add(int64(len(payload)))
}

func (a *simAgent) request(ctx context.Context, subject string, payload []byte, timeout time.Duration) []byte {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	st := time.Now()
	msg, err := a.nc.RequestWithContext(rctx, subject, payload)
	if err != nil {
		if ctx.Err() == nil {
			a.st.reqFail.Add(1)
		}
		return nil
	}
	a.st.agentReq.add(time.Since(st))
	a.st.reqOK.Add(1)
	return msg.Data
}

func (a *simAgent) heartbeat(ctx context.Context) {
	payload, _ := json.Marshal(proto.Heartbeat{AgentID: a.id.AgentID, Timestamp: time.Now().UTC()})
	a.publish(ctx, bnats.AgentHeartbeat(a.id.AgentID), payload)
}

func (a *simAgent) publishFacts(ctx context.Context) {
	f := a.facts
	f.Timestamp = time.Now().UTC()
	f.UptimeSec = uint64(time.Since(a.st.start).Seconds()) + 86400
	payload, _ := json.Marshal(f)
	a.publish(ctx, bnats.AgentFacts(a.id.AgentID), payload)
}

func (a *simAgent) publishSensors(ctx context.Context) {
	for _, kind := range a.cfg.p.kinds {
		if kind == "performance" {
			continue // its own 60s loop
		}
		if kind == "patches" {
			// collectPatches asks the server for its patch-list scope first.
			payload, _ := json.Marshal(proto.PatchListQuery{})
			a.request(ctx, bnats.PatchListQuery(a.id.AgentID), payload, 3*time.Second)
		}
		a.publishSensor(ctx, kind)
	}
}

func (a *simAgent) publishSensor(ctx context.Context, kind string) {
	data, ok := a.cfg.p.sensors[kind]
	if !ok {
		return
	}
	snap := proto.SensorSnapshot{AgentID: a.id.AgentID, Sensor: proto.SensorKind(kind), Timestamp: time.Now().UTC(), Data: data}
	payload, _ := json.Marshal(snap)
	a.publish(ctx, bnats.AgentSensor(a.id.AgentID, kind), payload)
}

func (a *simAgent) publishEvents(ctx context.Context) {
	if len(a.cfg.p.procEvents) > 0 {
		a.publish(ctx, bnats.AgentProcessEvents(a.id.AgentID), a.cfg.p.restamp(a.cfg.p.procEvents, a.id.AgentID))
	}
	if len(a.cfg.p.recEvents) > 0 {
		a.publish(ctx, bnats.AgentRecorderEvents(a.id.AgentID), a.cfg.p.restamp(a.cfg.p.recEvents, a.id.AgentID))
	}
}

func (a *simAgent) handleQuery(msg *gonats.Msg) {
	var q proto.QueryEnvelope
	if err := json.Unmarshal(msg.Data, &q); err != nil {
		return
	}
	if !q.Predicate.Match(a.info) {
		return
	}
	now := time.Now().UnixNano()
	a.st.queries.Add(1)
	a.st.queryFirst.CompareAndSwap(0, now)
	a.st.queryLast.Store(now)
	res := map[string]any{"query_id": q.QueryID, "agent_id": a.id.AgentID, "timestamp": time.Now().UTC()}
	switch q.Kind {
	case proto.QueryKindFacts:
		f := a.facts
		f.Timestamp = time.Now().UTC()
		res["facts"] = f
	case proto.QueryKindProcesses:
		res["processes"] = a.cfg.p.sensors["processes"]
	case proto.QueryKindServices:
		res["services"] = a.cfg.p.sensors["services"]
	case proto.QueryKindInstalledApps:
		res["installed_apps"] = a.cfg.p.sensors["installed_apps"]
	case proto.QueryKindPatches:
		res["patches"] = a.cfg.p.sensors["patches"]
	default:
		res["error"] = "unsupported query kind: " + string(q.Kind)
	}
	payload, _ := json.Marshal(res)
	send := func() {
		if err := a.nc.Publish(bnats.ResultFrom(q.QueryID, a.id.AgentID), payload); err == nil {
			a.st.queryAnswers.Add(1)
		}
	}
	// As the agent does (internal/agent/query.go): a fleet-wide query is
	// answered within the window the server asked for; -answer-spread
	// overrides it for experiments.
	window := time.Duration(q.AnswerWithinMs) * time.Millisecond
	if a.cfg.answerSpread > 0 {
		window = a.cfg.answerSpread
	}
	if window > 0 && msg.Subject != bnats.QAgent(a.id.AgentID) {
		time.AfterFunc(time.Duration(rand.Int64N(int64(window))), send)
		return
	}
	send()
}

func (a *simAgent) handleCommand(msg *gonats.Msg) {
	var cmd proto.AgentCommand
	if err := json.Unmarshal(msg.Data, &cmd); err != nil {
		return
	}
	a.st.noteCmd(cmd.Cmd)
	// Answered off the subscription goroutine, as a slow real command would
	// be measured: the reply comes when the command ends.
	go func() {
		res := proto.AgentCommandResult{OK: true}
		switch cmd.Cmd {
		case "run_software":
			time.Sleep(a.cfg.commandLatency)
			res.Output = "simulated: " + cmd.Command
		case "deploy_capabilities", "run_deploy":
			res.DeployVersion = proto.DeployVersion
		case "deploy_settings", "configure", "watch", "set_sensor_interval", "notify_user", "cancel_deploy":
		default:
			res = proto.AgentCommandResult{Error: "not supported by the load simulator: " + cmd.Cmd}
		}
		if msg.Reply != "" {
			payload, _ := json.Marshal(res)
			_ = a.nc.Publish(msg.Reply, payload)
		}
	}()
}

func (st *fleetStats) noteCmd(kind string) {
	now := time.Now()
	st.cmdMu.Lock()
	st.cmds[kind]++
	if _, ok := st.cmdFirst[kind]; !ok {
		st.cmdFirst[kind] = now
	}
	st.cmdLast[kind] = now
	st.cmdMu.Unlock()
}

type statsView struct {
	Agents         int                `json:"agents"`
	UptimeSec      float64            `json:"uptime_sec"`
	Connected      int64              `json:"connected"`
	Registered     int64              `json:"registered"`
	AllRegisteredS float64            `json:"all_registered_after_s"`
	ConnectErr     int64              `json:"connect_errors"`
	RegisterErr    int64              `json:"register_retries"`
	Disconnects    int64              `json:"disconnects"`
	Reconnects     int64              `json:"reconnects"`
	Expired        int64              `json:"auth_expired_errors"`
	AuthErr        int64              `json:"auth_errors"`
	PubOK          int64              `json:"pub_ok"`
	PubFail        int64              `json:"pub_fail"`
	PubMB          float64            `json:"pub_mb"`
	ReqOK          int64              `json:"agent_requests_ok"`
	ReqFail        int64              `json:"agent_requests_fail"`
	Queries        int64              `json:"queries_received"`
	QueryAnswers   int64              `json:"query_answers"`
	QuerySpreadMS  float64            `json:"query_first_to_last_ms"`
	Cmds           map[string]int     `json:"commands"`
	CmdSpreadMS    map[string]float64 `json:"command_first_to_last_ms"`
	FirstConnect   summary            `json:"first_connect"`
	Register       summary            `json:"start_to_registered"`
	Reconnect      summary            `json:"reconnect"`
	Publish        summary            `json:"publish_ack"`
	AgentReq       summary            `json:"agent_request"`
	Callouts       int64              `json:"callouts_answered"`
	Callout        summary            `json:"callout_latency"`
}

func view(st *fleetStats, n int, reset bool) statsView {
	v := statsView{Agents: n, UptimeSec: time.Since(st.start).Seconds(), Connected: st.connected.Load(), Registered: st.registered.Load(),
		ConnectErr: st.connectErr.Load(), RegisterErr: st.registerErr.Load(), Disconnects: st.disconnects.Load(),
		Reconnects: st.reconnects.Load(), Expired: st.expired.Load(), AuthErr: st.authErr.Load(),
		PubOK: st.pubOK.Load(), PubFail: st.pubFail.Load(), PubMB: float64(st.pubBytes.Load()) / 1e6,
		ReqOK: st.reqOK.Load(), ReqFail: st.reqFail.Load(), Queries: st.queries.Load(), QueryAnswers: st.queryAnswers.Load(),
		Cmds: map[string]int{}, CmdSpreadMS: map[string]float64{},
		FirstConnect: summarize(st.firstConnect.snapshot(false)), Register: summarize(st.register.snapshot(false)),
		Reconnect: summarize(st.reconnect.snapshot(reset)), Publish: summarize(st.pub.snapshot(reset)),
		AgentReq: summarize(st.agentReq.snapshot(reset)), Callouts: st.callouts.Load(),
		Callout: summarize(st.callout.snapshot(reset))}
	if v.Registered >= int64(n) {
		v.AllRegisteredS = time.Unix(0, st.lastRegistered.Load()).Sub(st.start).Seconds()
	}
	if f, l := st.queryFirst.Load(), st.queryLast.Load(); f > 0 {
		v.QuerySpreadMS = float64(l-f) / 1e6
	}
	st.cmdMu.Lock()
	for k, c := range st.cmds {
		v.Cmds[k] = c
		v.CmdSpreadMS[k] = ms(st.cmdLast[k].Sub(st.cmdFirst[k]))
	}
	if reset {
		st.cmds, st.cmdFirst, st.cmdLast = map[string]int{}, map[string]time.Time{}, map[string]time.Time{}
		st.queries.Store(0)
		st.queryAnswers.Store(0)
		st.queryFirst.Store(0)
		st.queryLast.Store(0)
	}
	st.cmdMu.Unlock()
	return v
}

func serveStats(addr string, st *fleetStats, n int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(view(st, n, r.URL.Query().Get("reset") == "1"))
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "stats listener:", err)
	}
}

func printStats(st *fleetStats, n int) {
	raw, _ := json.MarshalIndent(view(st, n, false), "", "  ")
	fmt.Println(string(raw))
}

// observeCallouts connects as the server's own NATS user (which bypasses
// the callout) and times every authorization request from the broker's
// $SYS.REQ.USER.AUTH publish to the control plane's answer on its
// $SYS._INBOX reply subject: queueing in the server plus the decision.
// It is a plain subscriber beside the server's queue subscription, so it
// sees every request without answering any.
func observeCallouts(o *natsOpts, st *fleetStats) error {
	nc, err := gonats.Connect(o.url, gonats.Name("loadsim-observer"), gonats.RootCAs(o.ca), gonats.UserInfo(o.user, o.pass),
		gonats.MaxReconnects(-1))
	if err != nil {
		return err
	}
	var mu sync.Mutex
	pending := map[string]time.Time{}
	if _, err := nc.Subscribe(bnats.AuthCalloutSubject, func(m *gonats.Msg) {
		mu.Lock()
		pending[m.Reply] = time.Now()
		if len(pending) > 100000 { // unanswered ones would grow without bound
			pending = map[string]time.Time{}
		}
		mu.Unlock()
	}); err != nil {
		return err
	}
	sub, err := nc.Subscribe("$SYS._INBOX.>", func(m *gonats.Msg) {
		mu.Lock()
		t0, ok := pending[m.Subject]
		delete(pending, m.Subject)
		mu.Unlock()
		if ok {
			st.callout.add(time.Since(t0))
			st.callouts.Add(1)
		}
	})
	if err != nil {
		return err
	}
	_ = sub.SetPendingLimits(-1, -1)
	return nil
}

// reconnectOption is the agent's reconnect policy (bnats.FleetReconnectBackoff),
// or the fixed 2 s wait agents used before it.
func reconnectOption(fixed bool) gonats.Option {
	if fixed {
		return gonats.ReconnectWait(2 * time.Second)
	}
	return bnats.FleetReconnectBackoff()
}
