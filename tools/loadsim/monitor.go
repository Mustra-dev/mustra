//go:build loadsim

package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runMonitor samples resource use of the three processes under test and
// JetStream consumer lag every -every, appending CSV rows to -out:
//
//	unix_ms, server_cpu%, server_rss_mb, pg_cpu%, pg_rss_mb, nats_cpu%,
//	nats_rss_mb, nats_conns, lag_<consumer>... (num_pending+num_ack_pending)
//
// CPU% is of one core (400 = all four cores of the test box).
func runMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	serverPID := fs.Int("server-pid", 0, "control-plane pid")
	natsPID := fs.Int("nats-pid", 0, "nats-server pid (docker inspect -f {{.State.Pid}})")
	serverPIDFile := fs.String("server-pidfile", "", "file holding the control-plane pid, re-read every sample (survives restarts)")
	natsContainer := fs.String("nats-container", "", "docker container running nats-server, re-resolved every sample")
	pgData := fs.String("pgdata", "/var/tmp/mustra-load-pg/data", "Postgres data directory (for postmaster.pid)")
	natsMon := fs.String("nats-monitor", "http://127.0.0.1:14802", "nats-server monitoring URL")
	every := fs.Duration("every", 2*time.Second, "sample interval")
	out := fs.String("out", "monitor.csv", "CSV output (appended)")
	_ = fs.Parse(args)
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	consumers := []string{"server-heartbeat", "server-facts", "server-sensors", "server-action-results", "server-process-events", "server-recorder-events", "server-file-events"}
	if st, _ := f.Stat(); st.Size() == 0 {
		fmt.Fprintf(f, "unix_ms,server_cpu,server_rss_mb,pg_cpu,pg_rss_mb,nats_cpu,nats_rss_mb,nats_conns,%s\n", "lag_"+strings.Join(consumers, ",lag_"))
	}
	prev := map[int]uint64{}
	prevT := time.Now()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	t := time.NewTicker(*every)
	defer t.Stop()
	for {
		select {
		case <-sig:
			return
		case <-t.C:
		}
		now := time.Now()
		dt := now.Sub(prevT).Seconds()
		prevT = now
		cpu := func(pids []int) (float64, float64) {
			var c float64
			var rss float64
			for _, p := range pids {
				ticks, r := procStat(p)
				if old, ok := prev[p]; ok && ticks >= old {
					c += float64(ticks-old) / 100 / dt * 100
				}
				prev[p] = ticks
				rss += r
			}
			return c, rss
		}
		if *serverPIDFile != "" {
			if raw, err := os.ReadFile(*serverPIDFile); err == nil {
				*serverPID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
			}
		}
		if *natsContainer != "" {
			if out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", *natsContainer).Output(); err == nil {
				*natsPID, _ = strconv.Atoi(strings.TrimSpace(string(out)))
			}
		}
		sc, sr := cpu([]int{*serverPID})
		pc, pr := cpu(postgresPIDs(*pgData))
		npc, nr := cpu([]int{*natsPID})
		conns, lag := natsState(*natsMon)
		row := []string{strconv.FormatInt(now.UnixMilli(), 10), f1(sc), f1(sr), f1(pc), f1(pr), f1(npc), f1(nr), strconv.Itoa(conns)}
		for _, c := range consumers {
			row = append(row, strconv.Itoa(lag[c]))
		}
		fmt.Fprintln(f, strings.Join(row, ","))
	}
}

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// procStat returns utime+stime in clock ticks and RSS in MB.
func procStat(pid int) (uint64, float64) {
	if pid <= 0 {
		return 0, 0
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0
	}
	s := string(raw)
	fields := strings.Fields(s[strings.LastIndex(s, ")")+2:])
	if len(fields) < 22 {
		return 0, 0
	}
	ut, _ := strconv.ParseUint(fields[11], 10, 64)
	stt, _ := strconv.ParseUint(fields[12], 10, 64)
	rssPages, _ := strconv.ParseFloat(fields[21], 64)
	return ut + stt, rssPages * 4096 / 1e6
}

// postgresPIDs is the postmaster and its children (backends, workers).
func postgresPIDs(pgdata string) []int {
	raw, err := os.ReadFile(filepath.Join(pgdata, "postmaster.pid"))
	if err != nil {
		return nil
	}
	master, _ := strconv.Atoi(strings.SplitN(string(raw), "\n", 2)[0])
	pids := []int{master}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		s := string(st)
		fields := strings.Fields(s[strings.LastIndex(s, ")")+2:])
		if len(fields) > 1 && fields[1] == strconv.Itoa(master) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func natsState(base string) (int, map[string]int) {
	lag := map[string]int{}
	hc := http.Client{Timeout: 2 * time.Second}
	var varz struct {
		Connections int `json:"connections"`
	}
	if resp, err := hc.Get(base + "/varz"); err == nil {
		_ = json.NewDecoder(resp.Body).Decode(&varz)
		resp.Body.Close()
	}
	var jsz struct {
		Accounts []struct {
			Streams []struct {
				Consumers []struct {
					Name       string `json:"name"`
					NumPending int    `json:"num_pending"`
					AckPending int    `json:"num_ack_pending"`
				} `json:"consumer_detail"`
			} `json:"stream_detail"`
		} `json:"account_details"`
	}
	if resp, err := hc.Get(base + "/jsz?consumers=true"); err == nil {
		_ = json.NewDecoder(resp.Body).Decode(&jsz)
		resp.Body.Close()
	}
	for _, a := range jsz.Accounts {
		for _, s := range a.Streams {
			for _, c := range s.Consumers {
				lag[c.Name] = c.NumPending + c.AckPending
			}
		}
	}
	return varz.Connections, lag
}

// runMonSummary prints mean and max of every monitor column between two
// unix-millisecond bounds (inclusive), for one test phase.
func runMonSummary(args []string) {
	fs := flag.NewFlagSet("msum", flag.ExitOnError)
	in := fs.String("csv", "monitor.csv", "monitor CSV")
	from := fs.Int64("from", 0, "start, unix ms")
	to := fs.Int64("to", 1<<62, "end, unix ms")
	_ = fs.Parse(args)
	f, err := os.Open(*in)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(bufio.NewReader(f))
	head, err := r.Read()
	if err != nil {
		fatal(err)
	}
	sum := make([]float64, len(head))
	max := make([]float64, len(head))
	n := 0
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		ts, _ := strconv.ParseInt(row[0], 10, 64)
		if ts < *from || ts > *to {
			continue
		}
		n++
		for i := 1; i < len(row) && i < len(head); i++ {
			v, _ := strconv.ParseFloat(row[i], 64)
			sum[i] += v
			if v > max[i] {
				max[i] = v
			}
		}
	}
	if n == 0 {
		fmt.Println("no samples in range")
		return
	}
	type kv struct {
		k         string
		mean, max float64
	}
	var rows []kv
	for i := 1; i < len(head); i++ {
		rows = append(rows, kv{head[i], sum[i] / float64(n), max[i]})
	}
	sort.SliceStable(rows, func(i, j int) bool { return false })
	fmt.Printf("%d samples\n", n)
	for _, r := range rows {
		fmt.Printf("  %-28s mean %8.1f  max %8.1f\n", r.k, r.mean, r.max)
	}
}
