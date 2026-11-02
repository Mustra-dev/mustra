package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	metaBucket   = []byte("meta")
	outboxBucket = []byte("outbox")
)

const metaKeyAgentID = "agent_id"

// BufferedMessage is one message queued locally because it could not be
// published to NATS immediately. Order is preserved: messages are drained
// in the order they were enqueued.
type BufferedMessage struct {
	Subject string    `json:"subject"`
	Payload []byte    `json:"payload"`
	Queued  time.Time `json:"queued"`
}

// Store is the agent's local persistence: its assigned identity and a
// durable store-and-forward outbox that survives process restarts as well
// as NATS outages. Backed by a single bbolt file so the agent has no
// external dependency to stay alive between control-plane outages.
type Store struct {
	db *bolt.DB
}

// OpenStore opens (creating if necessary) the bbolt database at path.
func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt store: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(metaBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(outboxBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init bbolt buckets: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying bbolt file.
func (s *Store) Close() error { return s.db.Close() }

// LoadAgentID returns the previously persisted agent ID, or "" if this
// agent has never successfully registered.
func (s *Store) LoadAgentID() (string, error) {
	var id string
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(metaBucket).Get([]byte(metaKeyAgentID))
		if v != nil {
			id = string(v)
		}
		return nil
	})
	return id, err
}

// LoadSettings returns the last profile settings the server pushed, if any.
func (s *Store) LoadSettings() ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(metaBucket).Get([]byte("settings")); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}

// SaveSettings persists pushed settings so they survive a restart.
func (s *Store) SaveSettings(raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(metaBucket).Put([]byte("settings"), raw)
	})
}

// LoadPatchVerifications returns the patch jobs waiting on a restart to be
// checked, as saved by SavePatchVerifications.
func (s *Store) LoadPatchVerifications() ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(metaBucket).Get([]byte("patch_verify")); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}

// SavePatchVerifications persists them across the restart they wait on.
func (s *Store) SavePatchVerifications(raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(metaBucket).Put([]byte("patch_verify"), raw)
	})
}

// LoadWatchConfig returns the last integrity watch set the server pushed.
func (s *Store) LoadWatchConfig() ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(metaBucket).Get([]byte("watch")); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}

// SaveWatchConfig persists a pushed watch set so it survives a restart.
func (s *Store) SaveWatchConfig(raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(metaBucket).Put([]byte("watch"), raw)
	})
}

// LoadBranding returns the last Self Service branding the server sent.
func (s *Store) LoadBranding() ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(metaBucket).Get([]byte("branding")); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}

// SaveBranding persists the branding; nil removes it (the default look).
func (s *Store) SaveBranding(raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if raw == nil {
			return tx.Bucket(metaBucket).Delete([]byte("branding"))
		}
		return tx.Bucket(metaBucket).Put([]byte("branding"), raw)
	})
}

// SaveAgentID persists the agent ID confirmed by the server.
func (s *Store) SaveAgentID(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(metaBucket).Put([]byte(metaKeyAgentID), []byte(id))
	})
}

// Enqueue appends a message to the durable outbox.
func (s *Store) Enqueue(msg BufferedMessage) error {
	msg.Queued = msg.Queued.UTC()
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal buffered message: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		return b.Put(seqKey(seq), data)
	})
}

// DropFirst removes the message at the head of the outbox and returns it.
//
// It exists for one situation: the outbox drains strictly in order, so a
// message the server will never accept — one published to a subject the
// agent's credential is not allowed to publish, say — sits at the head
// and blocks every message queued behind it, forever and silently. Losing
// that one message is bad; losing all telemetry after it is worse.
func (s *Store) DropFirst() (BufferedMessage, error) {
	var msg BufferedMessage
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		k, v := b.Cursor().First()
		if k == nil {
			return nil
		}
		if err := json.Unmarshal(v, &msg); err != nil {
			// Undecodable is its own reason to drop it.
			msg = BufferedMessage{Subject: "(unreadable)"}
		}
		return b.Delete(append([]byte(nil), k...))
	})
	if err != nil {
		return msg, fmt.Errorf("drop first outbox entry: %w", err)
	}
	return msg, nil
}

// Pending returns the number of messages currently buffered.
func (s *Store) Pending() (int, error) {
	n := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(outboxBucket).Stats().KeyN
		return nil
	})
	return n, err
}

// Drain calls fn once per buffered message in enqueue order. If fn returns
// a nil error the message is removed from the outbox and iteration
// continues. If fn returns an error, iteration stops immediately (leaving
// that message and everything after it in the outbox) and Drain returns
// that error — this preserves ordering when, e.g., NATS drops mid-flush.
func (s *Store) Drain(fn func(msg BufferedMessage) error) error {
	for {
		var (
			key []byte
			msg BufferedMessage
			any bool
		)
		err := s.db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(outboxBucket).Cursor()
			k, v := c.First()
			if k == nil {
				return nil
			}
			any = true
			key = append([]byte(nil), k...)
			return json.Unmarshal(v, &msg)
		})
		if err != nil {
			return fmt.Errorf("read outbox entry: %w", err)
		}
		if !any {
			return nil
		}
		if err := fn(msg); err != nil {
			return err
		}
		if err := s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(outboxBucket).Delete(key)
		}); err != nil {
			return fmt.Errorf("delete drained outbox entry: %w", err)
		}
	}
}

// EnqueueLatest buffers a message whose subject is latest-wins — a
// heartbeat, facts, a sensor snapshot — replacing anything already queued
// for that subject. An agent that was offline for two days has nothing to
// gain from delivering forty-eight stale hourly snapshots in order; the
// server keeps one per sensor anyway, and every stale one queued ahead of
// the current one is a round-trip the current one waits for.
func (s *Store) EnqueueLatest(msg BufferedMessage) error {
	msg.Queued = msg.Queued.UTC()
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal buffered message: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		var stale [][]byte
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var m BufferedMessage
			if json.Unmarshal(v, &m) == nil && m.Subject == msg.Subject {
				stale = append(stale, append([]byte(nil), k...))
			}
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		return b.Put(seqKey(seq), data)
	})
}

// OutboxEntry is a buffered message together with its position key, for
// callers that publish a batch and then delete exactly what was acked.
type OutboxEntry struct {
	Key []byte
	Msg BufferedMessage
}

// PeekBatch returns up to n messages from the head of the outbox without
// removing them. Entries that cannot be decoded are returned with an
// "(unreadable)" subject so the caller can drop them by key.
func (s *Store) PeekBatch(n int) ([]OutboxEntry, error) {
	var out []OutboxEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(outboxBucket).Cursor()
		for k, v := c.First(); k != nil && len(out) < n; k, v = c.Next() {
			e := OutboxEntry{Key: append([]byte(nil), k...)}
			if err := json.Unmarshal(v, &e.Msg); err != nil {
				e.Msg = BufferedMessage{Subject: "(unreadable)"}
			}
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("peek outbox: %w", err)
	}
	return out, nil
}

// DeleteKeys removes the given outbox entries in one transaction.
func (s *Store) DeleteKeys(keys [][]byte) error {
	if len(keys) == 0 {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// DrainWhere is Drain restricted to messages whose subject match accepts,
// in enqueue order; the rest are left in place. Used to send latest-wins
// subjects ahead of a long telemetry backlog: they are independent of it,
// so publishing them first loses nothing and gets the endpoint back to
// "online" now rather than after the backlog.
func (s *Store) DrainWhere(match func(subject string) bool, fn func(msg BufferedMessage) error) error {
	var after []byte
	for {
		var (
			key []byte
			msg BufferedMessage
			any bool
		)
		err := s.db.View(func(tx *bolt.Tx) error {
			c := tx.Bucket(outboxBucket).Cursor()
			var k, v []byte
			if after == nil {
				k, v = c.First()
			} else {
				k, v = c.Seek(after)
				if k != nil && bytes.Equal(k, after) {
					k, v = c.Next()
				}
			}
			for ; k != nil; k, v = c.Next() {
				var m BufferedMessage
				if json.Unmarshal(v, &m) != nil || !match(m.Subject) {
					continue
				}
				any = true
				key = append([]byte(nil), k...)
				msg = m
				return nil
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("read outbox entry: %w", err)
		}
		if !any {
			return nil
		}
		if err := fn(msg); err != nil {
			return err
		}
		if err := s.DeleteKeys([][]byte{key}); err != nil {
			return fmt.Errorf("delete drained outbox entry: %w", err)
		}
		after = key
	}
}

// PruneOutbox drops buffered messages that are no longer worth sending:
// any expirable message queued longer than maxAge, and — if the outbox
// still holds more than maxCount entries — the oldest expirable ones until
// it does not. Non-expirable messages (action results, file events) are
// never dropped here. Returns how many were removed.
func (s *Store) PruneOutbox(now time.Time, maxAge time.Duration, maxCount int, expirable func(subject string) bool) (int, error) {
	dropped := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(outboxBucket)
		var victims [][]byte
		var candidates [][]byte // expirable and young, oldest first
		total := 0
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			total++
			var m BufferedMessage
			if err := json.Unmarshal(v, &m); err != nil {
				victims = append(victims, append([]byte(nil), k...))
				continue
			}
			if !expirable(m.Subject) {
				continue
			}
			if now.Sub(m.Queued) > maxAge {
				victims = append(victims, append([]byte(nil), k...))
				continue
			}
			candidates = append(candidates, append([]byte(nil), k...))
		}
		over := total - len(victims) - maxCount
		for i := 0; i < len(candidates) && over > 0; i++ {
			victims = append(victims, candidates[i])
			over--
		}
		for _, k := range victims {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		dropped = len(victims)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("prune outbox: %w", err)
	}
	return dropped, nil
}

func seqKey(seq uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return b
}
