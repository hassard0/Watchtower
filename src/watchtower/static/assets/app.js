// Watchtower dashboard logic. Alpine.js component.
function watchtower() {
  return {
    state: { entities: {}, scanners: [], baseline_progress: {}, alerts_unack_24h: 0 },
    entities: [],
    alerts: [],
    visits: [],
    discoveryCandidates: [],
    discoveryProbing: {},
    discoveryProbed: {},
    spectrum: { midband_samples: [], subghz_decodes: [] },
    zones: [],
    settings: {},
    settingsSchema: {},
    settingsDirty: false,
    recap: null,
    recapHours: 8,
    toasts: [],
    _seenAlertIds: new Set(),
    _firstLoad: true,
    entityDetail: null,
    loading: false,
    now: '',
    tab: 'overview',
    entityScope: 'active',
    entityOrder: 'active',
    timelineHours: 24,

    tabs: [
      { id: 'overview',  label: 'Overview',  icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>' },
      { id: 'discover',  label: 'Discover',  icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="10" cy="10" r="7"/><path d="M21 21l-6-6"/></svg>' },
      { id: 'entities',  label: 'Entities',  icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="7" r="4"/><circle cx="17" cy="11" r="3"/><path d="M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2M14 21v-2a3 3 0 0 1 3-3h2"/></svg>' },
      { id: 'timeline',  label: 'Timeline',  icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="6" width="18" height="3" rx="1"/><rect x="6" y="11" width="12" height="3" rx="1"/><rect x="3" y="16" width="14" height="3" rx="1"/></svg>' },
      { id: 'spectrum',  label: 'Spectrum',  icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12h2l3-9 6 18 3-9h6"/></svg>' },
      { id: 'zones',     label: 'Zones',     icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>' },
      { id: 'alerts',    label: 'Alerts',    icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21a2 2 0 0 0 4 0"/></svg>' },
      { id: 'settings',  label: 'Settings',  icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>' },
    ],

    scopeBtns: [
      { id: 'active',     label: 'Active now' },
      { id: 'anomalous',  label: 'Anomalous' },
      { id: 'unknown',    label: 'Unknown' },
      { id: 'enrolled',   label: 'Enrolled' },
      { id: 'all',        label: 'All' },
    ],

    windowBtns: [
      { h: 1,  label: '1h' },
      { h: 6,  label: '6h' },
      { h: 24, label: '24h' },
      { h: 72, label: '3d' },
      { h: 168, label: '7d' },
    ],

    classifications: [
      { id: 'anchor',       label: 'Anchor',       activeCls: 'border-anchor/60 text-anchor bg-anchor/10' },
      { id: 'satellite',    label: 'Satellite',    activeCls: 'border-satellite/60 text-satellite bg-satellite/10' },
      { id: 'known_guest',  label: 'Known guest',  activeCls: 'border-guest/60 text-guest bg-guest/10' },
      { id: 'untrusted',    label: 'Untrusted',    activeCls: 'border-threat/60 text-threat bg-threat/10' },
      { id: null,           label: 'Unknown',      activeCls: 'border-slate-500/60 text-slate-300 bg-slate-500/10' },
    ],

    // ---- INIT ----
    init() {
      // Restore last-used tab from localStorage.
      try {
        const saved = localStorage.getItem('watchtower.tab');
        if (saved && this.tabs.find(t => t.id === saved)) this.tab = saved;
      } catch (e) {}
      this.$watch('tab', v => {
        try { localStorage.setItem('watchtower.tab', v); } catch (e) {}
      });
      this.refresh();
      setInterval(() => { this.tick(); }, 1000);
      setInterval(() => { this.refresh(); }, 5000);
    },

    tick() {
      const d = new Date();
      this.now = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    },

    async refresh() {
      this.loading = true;
      try {
        const tasks = [this.loadState(), this.loadEntities(), this.loadAlerts()];
        if (this.tab === 'timeline')  tasks.push(this.loadTimeline());
        if (this.tab === 'spectrum')  tasks.push(this.loadSpectrum());
        if (this.tab === 'zones')     tasks.push(this.loadZones());
        if (this.tab === 'discover')  tasks.push(this.loadDiscovery());
        if (this.tab === 'overview')  tasks.push(this.loadRecap());
        if (this.tab === 'settings' && !this.settingsDirty) tasks.push(this.loadSettings());
        await Promise.all(tasks);
      } finally {
        this.loading = false;
      }
    },

    async loadState() {
      try {
        const r = await fetch('/api/state');
        this.state = await r.json();
      } catch (e) { console.warn('loadState', e); }
    },

    async loadEntities() {
      try {
        const r = await fetch(`/api/entities?scope=${this.entityScope}&order=${this.entityOrder}&limit=300`);
        const j = await r.json();
        this.entities = j.entities || [];
      } catch (e) { console.warn('loadEntities', e); }
    },

    async loadAlerts() {
      try {
        const r = await fetch('/api/alerts');
        const j = await r.json();
        const newAlerts = j.alerts || [];
        // Toast for any high/critical alert we've never shown before.
        if (!this._firstLoad) {
          for (const a of newAlerts) {
            if (this._seenAlertIds.has(a.alert_id)) continue;
            this._seenAlertIds.add(a.alert_id);
            if (a.severity === 'high' || a.severity === 'critical') {
              this.pushToast(a);
            }
          }
        } else {
          // First load: just record IDs without toasting.
          for (const a of newAlerts) this._seenAlertIds.add(a.alert_id);
          this._firstLoad = false;
        }
        this.alerts = newAlerts;
      } catch (e) { console.warn('loadAlerts', e); }
    },

    pushToast(alert) {
      const id = (Math.random() * 1e9).toString(36);
      const t = { ...alert, id };
      this.toasts.push(t);
      setTimeout(() => this.dismissToast(id), 8000);
      this.beep(alert.severity);
    },

    audioEnabled: false,
    _audioCtx: null,
    enableAudio() {
      try {
        this._audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        this.audioEnabled = true;
        try { localStorage.setItem('watchtower.audio', '1'); } catch (e) {}
        // Confirmation chirp
        this.beep('medium');
      } catch (e) { console.warn(e); }
    },
    disableAudio() {
      this.audioEnabled = false;
      try { localStorage.removeItem('watchtower.audio'); } catch (e) {}
    },
    beep(severity) {
      if (!this.audioEnabled || !this._audioCtx) return;
      const ctx = this._audioCtx;
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.type = 'sine';
      const f = severity === 'critical' ? 880 : severity === 'high' ? 660 : 440;
      o.frequency.value = f;
      g.gain.value = 0.0001;
      o.connect(g).connect(ctx.destination);
      const t = ctx.currentTime;
      g.gain.exponentialRampToValueAtTime(0.18, t + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.4);
      o.start(t); o.stop(t + 0.42);
      if (severity === 'critical' || severity === 'high') {
        // Double beep
        setTimeout(() => this._beepOnce(f), 250);
      }
    },
    _beepOnce(f) {
      if (!this._audioCtx) return;
      const ctx = this._audioCtx;
      const o = ctx.createOscillator(); const g = ctx.createGain();
      o.type = 'sine'; o.frequency.value = f; g.gain.value = 0.0001;
      o.connect(g).connect(ctx.destination);
      const t = ctx.currentTime;
      g.gain.exponentialRampToValueAtTime(0.18, t + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, t + 0.3);
      o.start(t); o.stop(t + 0.32);
    },

    dismissToast(id) {
      this.toasts = this.toasts.filter(t => t.id !== id);
    },

    async loadTimeline() {
      try {
        const to = Math.floor(Date.now() / 1000);
        const from = to - this.timelineHours * 3600;
        const r = await fetch(`/api/timeline?from=${from}&to=${to}`);
        const j = await r.json();
        this.visits = j.visits || [];
      } catch (e) { console.warn('loadTimeline', e); }
    },

    async loadSpectrum() {
      try {
        const r = await fetch('/api/spectrum');
        this.spectrum = await r.json();
      } catch (e) { console.warn('loadSpectrum', e); }
    },

    async loadZones() {
      try {
        const r = await fetch('/api/zones');
        const j = await r.json();
        this.zones = j.zones || [];
      } catch (e) { console.warn('loadZones', e); }
    },

    async loadDiscovery() {
      try {
        const r = await fetch('/api/discovery');
        const j = await r.json();
        this.discoveryCandidates = j.candidates || [];
      } catch (e) { console.warn('loadDiscovery', e); }
    },

    async loadRecap() {
      try {
        const r = await fetch('/api/recap?hours=' + this.recapHours);
        this.recap = await r.json();
      } catch (e) { console.warn('loadRecap', e); }
    },

    async loadSettings() {
      try {
        const r = await fetch('/api/settings');
        const j = await r.json();
        this.settings = j.settings;
        this.settingsSchema = j.schema || {};
        this.settingsDirty = false;
      } catch (e) { console.warn('loadSettings', e); }
    },

    async saveSettings() {
      try {
        const r = await fetch('/api/settings', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(this.settings),
        });
        if (!r.ok) throw new Error('save failed');
        const j = await r.json();
        this.settings = j.settings;
        this.settingsDirty = false;
      } catch (e) { alert('save failed: ' + e.message); }
    },

    settingsLabel(key) {
      return ({
        'linger_threshold_sec': 'Linger threshold',
        'anchor_timeout_sec': 'Anchor timeout',
        'close_perimeter_rssi_dbm': 'Close-perimeter RSSI',
        'after_hours_start_utc': 'After-hours start (UTC)',
        'after_hours_end_utc': 'After-hours end (UTC)',
        'anomaly_severity_high_threshold': 'High-severity score',
        'anomaly_severity_medium_threshold': 'Medium-severity score',
      })[key] || key;
    },
    settingsHint(key) {
      return ({
        'linger_threshold_sec': 'seconds',
        'anchor_timeout_sec': 'seconds',
        'close_perimeter_rssi_dbm': 'dBm (higher = closer)',
        'after_hours_start_utc': 'hour 0–23',
        'after_hours_end_utc': 'hour 0–23',
        'anomaly_severity_high_threshold': '0.0–1.0',
        'anomaly_severity_medium_threshold': '0.0–1.0',
      })[key] || '';
    },
    settingsStep(key) {
      if (key.includes('threshold') && !key.includes('sec')) return '0.05';
      return '1';
    },
    ruleLabel(key) {
      return ({
        'rule_anchor_absent_unknown_linger': 'Anchor absent + unknown lingering',
        'rule_unknown_keyfob_emission':      'Unknown key-fob emission (sub-GHz)',
        'rule_unknown_garage_emission':      'Unknown garage-door emission (sub-GHz)',
        'rule_airtag_findmy_present':        'Apple Find-My / AirTag broadcast',
        'rule_first_time_visitor_after_hours': 'First-time visitor after hours',
        'rule_close_unknown_signal':         'Strong-signal unknown nearby',
        'rule_rogue_hotspot':                'Rogue Wi-Fi hotspot',
      })[key] || key;
    },
    ruleDescription(key) {
      return ({
        'rule_anchor_absent_unknown_linger': 'Fires when an unknown entity is present > linger threshold while no anchor is home.',
        'rule_unknown_keyfob_emission':      'Fires on unrecognized 315/433 MHz key-fob protocol activity.',
        'rule_unknown_garage_emission':      'Fires on unrecognized 315/390 MHz garage-door protocol activity.',
        'rule_airtag_findmy_present':        'Fires on Apple Find-My broadcasts near the Pi.',
        'rule_first_time_visitor_after_hours': 'New entity first-seen after-hours window. Requires at least one anchor enrolled.',
        'rule_close_unknown_signal':         'Mobile BLE device with very strong RSSI and recurring presence.',
        'rule_rogue_hotspot':                'Random-BSSID Wi-Fi AP with strong signal — phone hotspot near the property.',
      })[key] || '';
    },
    async testNtfy() {
      try {
        // Save settings first if dirty so the test uses the current values.
        if (this.settingsDirty) await this.saveSettings();
        const r = await fetch('/api/admin/test-ntfy', { method: 'POST' });
        if (r.ok) {
          alert('Test alert dispatched. Check your phone / webhook / MQTT subscriber.');
        } else {
          alert('Test failed: ' + r.status);
        }
      } catch (e) { alert('failed: ' + e.message); }
    },

    async resetEntities() {
      if (!confirm('Wipe entities/visits and rebuild from raw_events on next analytics tick?')) return;
      try {
        await fetch('/api/admin/reset-entities', { method: 'POST' });
        await this.refresh();
      } catch (e) { alert('failed: ' + e.message); }
    },
    async ackAllAlerts() {
      if (!confirm('Mark all alerts acknowledged?')) return;
      try {
        await fetch('/api/alerts/ack-all', { method: 'POST' });
        await this.loadAlerts();
        await this.loadState();
      } catch (e) { alert('failed: ' + e.message); }
    },

    async quickProbe(c) {
      if (this.discoveryProbing[c.entity_id]) return;
      this.discoveryProbing = { ...this.discoveryProbing, [c.entity_id]: true };
      try {
        const r = await fetch(`/api/entities/${encodeURIComponent(c.entity_id)}/probe`, { method: 'POST' });
        const j = await r.json();
        this.discoveryProbed = { ...this.discoveryProbed, [c.entity_id]: j.result };
        if (j.result?.ok) {
          await this.loadDiscovery();
          await this.loadEntities();
        }
      } catch (e) {
        this.discoveryProbed = { ...this.discoveryProbed, [c.entity_id]: { ok: false, error: e.message } };
      } finally {
        this.discoveryProbing = { ...this.discoveryProbing, [c.entity_id]: false };
      }
    },

    async quickClassify(c, classification) {
      try {
        await fetch(`/api/entities/${encodeURIComponent(c.entity_id)}/classify`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ classification }),
        });
        c.classification = classification;
        await this.loadDiscovery();
        await this.loadEntities();
        await this.loadState();
      } catch (e) { console.warn('quickClassify', e); }
    },

    async openEntity(eid) {
      try {
        const sameEntity = this.entityDetail?.entity?.entity_id === eid;
        const r = await fetch(`/api/entities/${encodeURIComponent(eid)}`);
        this.entityDetail = await r.json();
        if (!sameEntity) this.probeResult = null;
      } catch (e) { console.warn('openEntity', e); }
    },

    probing: false,
    probeResult: null,
    async probeEntity() {
      if (!this.entityDetail || this.probing) return;
      this.probing = true;
      this.probeResult = null;
      const eid = this.entityDetail.entity.entity_id;
      try {
        const r = await fetch(`/api/entities/${encodeURIComponent(eid)}/probe`, { method: 'POST' });
        const j = await r.json();
        const result = j.result || { ok: false, error: 'no response' };
        // If probe succeeded, refetch the entity and the entities list so the
        // new friendly_name is reflected — but DON'T clear probeResult, so the
        // user sees what we found.
        if (result.ok) {
          try {
            const r2 = await fetch(`/api/entities/${encodeURIComponent(eid)}`);
            const detail = await r2.json();
            this.entityDetail = detail;
          } catch (e) { /* keep showing result regardless */ }
          this.loadEntities();  // fire-and-forget
        }
        this.probeResult = result;
      } catch (e) {
        this.probeResult = { ok: false, error: e.message };
      } finally {
        this.probing = false;
      }
    },

    async classifyEntity(c) {
      if (!this.entityDetail) return;
      const eid = this.entityDetail.entity.entity_id;
      await fetch(`/api/entities/${encodeURIComponent(eid)}/classify`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ classification: c }),
      });
      this.entityDetail.entity.classification = c;
      this.loadEntities();
    },

    async renameEntity(name) {
      if (!this.entityDetail) return;
      const eid = this.entityDetail.entity.entity_id;
      await fetch(`/api/entities/${encodeURIComponent(eid)}/name`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ friendly_name: name }),
      });
      this.entityDetail.entity.friendly_name = name;
      this.loadEntities();
    },

    async ackAlert(a) {
      await fetch(`/api/alerts/${a.alert_id}/ack`, { method: 'POST' });
      a.acknowledged = 1;
    },

    async feedbackAlert(a, f) {
      await fetch(`/api/alerts/${a.alert_id}/feedback`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ feedback: f }),
      });
      a.user_feedback = f;
    },

    // ---- DERIVED VIEWS ----

    get scannerRows() {
      const map = { 'ble_scanner': { label: 'BLE', color: 'bg-signal-glow', barColor: 'bg-signal-glow', icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="#00d9ff" stroke-width="2"><path d="M7 7l10 10M7 17l10-10M12 4v16"/></svg>' },
                    'wifi_scanner': { label: 'WiFi', color: 'bg-signal-deep', barColor: 'bg-signal-deep', icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14 0M8.5 16.05a6 6 0 0 1 7 0M12 19h.01M2 8.82a15 15 0 0 1 20 0"/></svg>' },
                    'subghz_scanner': { label: 'Sub-GHz', color: 'bg-signal-warm', barColor: 'bg-signal-warm', icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="#ffb547" stroke-width="2"><path d="M2 12h2l3-9 6 18 3-9h6"/></svg>' },
                    'midband_scanner': { label: 'Mid-band', color: 'bg-signal-pulse', barColor: 'bg-signal-pulse', icon: '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="#00ff88" stroke-width="2"><rect x="3" y="10" width="2" height="4"/><rect x="7" y="6" width="2" height="12"/><rect x="11" y="3" width="2" height="18"/><rect x="15" y="8" width="2" height="8"/><rect x="19" y="11" width="2" height="2"/></svg>' } };
      const known = ['ble_scanner', 'wifi_scanner', 'subghz_scanner', 'midband_scanner'];
      const max = Math.max(1, ...(this.state.scanners || []).map(s => s.events_last_hour || 0));
      const seen = new Map((this.state.scanners || []).map(s => [s.scanner, s.events_last_hour]));
      return known.map(name => {
        const events = seen.get(name) || 0;
        const m = map[name] || { label: name, color: 'bg-slate-500', barColor: 'bg-slate-500', icon: '' };
        return { scanner: name, label: m.label, events, color: m.color, barColor: m.barColor, icon: m.icon, barPct: (events / max) * 100 };
      });
    },

    get baselineProgressPct() {
      const b = this.state.baseline_progress || {};
      if (!b.max_buckets) return 0;
      return Math.min(100, (b.buckets_seen / b.max_buckets) * 100);
    },

    get heroHeadline() {
      if (this.state.any_anchor_enrolled === false) return 'SETUP';
      if (this.state.home_state === 'home') {
        return this.state.entities?.anomalous_now > 0 ? 'WATCHING' : 'CALM';
      }
      if (this.state.home_state === 'away') {
        return this.state.entities?.anomalous_now > 0 ? 'EYES UP' : 'AWAY · QUIET';
      }
      return 'INITIALIZING';
    },

    get heroSubline() {
      const a = this.state.entities?.anomalous_now ?? 0;
      const u = this.state.entities?.unknown ?? 0;
      const act = this.state.entities?.active_now ?? 0;
      if (this.state.any_anchor_enrolled === false) {
        return `Tap Discover → mark your phone as ANCHOR so the system knows when you're home. ${act} entities currently in range.`;
      }
      if (a > 0) {
        const verb = this.state.home_state === 'away' ? 'while you are away' : 'in range';
        return `${a} entit${a===1?'y':'ies'} flagged ${verb} · ${act} active now`;
      }
      if (act > 0) return `${act} active · ${u} unknown · no anomalies`;
      return 'no signals · waiting';
    },

    get anomalyHeroScore() {
      const e = this.entities.filter(x => x.currently_present).map(x => x.anomaly_score || 0);
      return e.length ? Math.max(...e) : 0;
    },

    get topAnomalies() {
      return this.entities
        .filter(e => (e.anomaly_score || 0) > 0.2)
        .sort((a,b) => (b.anomaly_score || 0) - (a.anomaly_score || 0))
        .slice(0, 8);
    },

    get radarDots() {
      // Map currently-present entities into a circular layout with RSSI as radial distance.
      const present = this.entities.filter(e => e.currently_present && e.avg_rssi != null);
      const max = present.length;
      return present.slice(0, 30).map((e, i) => {
        // Angle: deterministic from entity_id hash
        let h = 0; for (const c of e.entity_id) h = (h * 31 + c.charCodeAt(0)) >>> 0;
        const angle = (h % 360) * Math.PI / 180;
        // Radius: -30dBm = center, -90dBm = edge
        const rssi = e.avg_rssi || -70;
        const norm = Math.min(1, Math.max(0, (Math.abs(rssi) - 30) / 60));
        const r = 0.92 * norm;
        const x = Math.cos(angle) * r * 50; // pct of half-side
        const y = Math.sin(angle) * r * 50;
        const colorMap = {
          anchor: 'bg-anchor', satellite: 'bg-satellite', known_guest: 'bg-guest', untrusted: 'bg-threat'
        };
        let cls = colorMap[e.classification] || 'bg-unknown/70';
        let shadow = '#cbd5e1';
        if (e.classification === 'anchor') shadow = '#f6c453';
        else if (e.classification === 'satellite') shadow = '#5dd0a8';
        else if (e.classification === 'known_guest') shadow = '#7dd3fc';
        else if (e.classification === 'untrusted') shadow = '#ff5470';
        if ((e.anomaly_score || 0) >= 0.5) { cls = 'bg-threat'; shadow = '#ff5470'; }
        const size = 6 + Math.round((1 - norm) * 12);
        return {
          id: e.entity_id, x, y, size,
          cls,
          shadow,
          glow: Math.min(1, (e.anomaly_score || 0)),
          label: this.entityDisplayName(e),
          rssi: Math.round(e.avg_rssi),
        };
      });
    },

    get baselineRows() {
      // Build a per-feature current-vs-baseline strip. We use the `scanners`
      // last-hour counts compared to baseline_stats summary if available.
      // Simpler: pull /api/baseline once on demand. For now, derive from state.
      // Fallback: if no baseline data, return scanner rows only.
      const out = [];
      const scanners = this.state.scanners || [];
      const feat2 = this.scannerFeatureMap();
      for (const s of scanners) {
        const stat = feat2[s.scanner + '_count'];
        const cur = s.events_last_hour || 0;
        if (!stat) {
          out.push({ feature: s.scanner, label: s.scanner.replace('_scanner', ''),
                     mean: cur, stddev: 0, n: 0, bandLeft: 50, bandRight: 50, meanPct: 50, nowPct: 50, zClass: 'bg-signal-glow' });
          continue;
        }
        const z = stat.stddev > 0 ? (cur - stat.mean) / stat.stddev : 0;
        const range = Math.max(stat.mean + 4 * stat.stddev, cur * 1.2, 1);
        const pct = (v) => Math.max(0, Math.min(100, (v / range) * 100));
        const nowPct = pct(cur);
        const meanPct = pct(stat.mean);
        const lo = pct(stat.mean - 3 * stat.stddev);
        const hi = pct(stat.mean + 3 * stat.stddev);
        out.push({
          feature: s.scanner,
          label: s.scanner.replace('_scanner','') + ' · events / hour',
          mean: stat.mean, stddev: stat.stddev, n: stat.n,
          bandLeft: lo, bandRight: 100 - hi, meanPct, nowPct,
          zClass: Math.abs(z) > 3 ? 'bg-threat' : Math.abs(z) > 2 ? 'bg-signal-warm' : 'bg-signal-pulse',
        });
      }
      return out;
    },

    _baselineCache: null,
    scannerFeatureMap() {
      // load /api/baseline lazily and cache
      if (this._baselineCache) return this._baselineCache;
      this._baselineCache = {};
      fetch('/api/baseline').then(r => r.json()).then(j => {
        const map = {};
        const nowHw = this.currentHourOfWeek();
        for (const [feature, rows] of Object.entries(j.baseline || {})) {
          const cur = rows.find(r => r.hour_of_week === nowHw);
          if (cur) map[feature] = cur;
        }
        this._baselineCache = map;
      }).catch(() => {});
      return this._baselineCache;
    },

    currentHourOfWeek() {
      const d = new Date();
      // JS getDay: 0=Sun..6=Sat. We use Monday=0 mapping in backend.
      const dow = (d.getUTCDay() + 6) % 7;
      return dow * 24 + d.getUTCHours();
    },

    get spectrumBands() {
      const samples = this.spectrum?.midband_samples || [];
      if (!samples.length) return [];
      const byBand = {};
      const ordered = samples.slice().reverse();
      for (const s of ordered) {
        if (!byBand[s.band]) byBand[s.band] = [];
        byBand[s.band].push(s);
      }
      const out = [];
      for (const [band, points] of Object.entries(byBand)) {
        if (points.length === 0) continue;
        const energies = points.map(p => p.energy_dbm);
        const lo = Math.min(...energies, -100);
        const hi = Math.max(...energies, -50);
        const range = Math.max(1, hi - lo);
        const last = energies[energies.length - 1];
        const linePts = points.map((p, i) => `${i},${(100 * (1 - (p.energy_dbm - lo) / range)).toFixed(1)}`).join(' ');
        const polyPts = `0,100 ${linePts} ${points.length - 1},100`;
        const freq_label = points[points.length - 1].freq_hz
          ? (points[points.length - 1].freq_hz / 1e6).toFixed(1) + ' MHz'
          : '';
        out.push({
          band,
          label: this.bandLabel(band),
          last, lo, hi,
          points,
          freq_label,
          svgLine: linePts,
          svgPolygon: polyPts,
        });
      }
      const order = ['700MHz','850MHz','GSM900','900MHz','AviationBand','GPS-L1','OutOfBand'];
      out.sort((a,b) => order.indexOf(a.band) - order.indexOf(b.band));
      return out;
    },

    spectrumCellColor(e, lo, hi) {
      const range = Math.max(1, hi - lo);
      const t = Math.max(0, Math.min(1, (e - lo) / range));
      // 0 = #1f2740 (cold)
      // 0.33 = #5dd0a8 (calm green)
      // 0.66 = #f6c453 (warm gold)
      // 1 = #ff5470 (hot red)
      const stops = [
        [0,    [31, 39, 64]],
        [0.33, [93, 208, 168]],
        [0.66, [246, 196, 83]],
        [1,    [255, 84, 112]],
      ];
      for (let i = 0; i < stops.length - 1; i++) {
        const [s0, c0] = stops[i];
        const [s1, c1] = stops[i+1];
        if (t >= s0 && t <= s1) {
          const k = (t - s0) / (s1 - s0);
          const r = Math.round(c0[0] + (c1[0] - c0[0]) * k);
          const g = Math.round(c0[1] + (c1[1] - c0[1]) * k);
          const b = Math.round(c0[2] + (c1[2] - c0[2]) * k);
          return `rgb(${r},${g},${b})`;
        }
      }
      return 'rgb(31,39,64)';
    },

    bandLabel(band) {
      return ({
        '700MHz': 'LTE 700 MHz (low-band cellular)',
        '850MHz': 'Cellular 850 MHz',
        'GSM900': 'Cellular 900 MHz (GSM)',
        '900MHz': 'ISM 902-928 MHz (LoRa, sub-GHz IoT)',
        'AviationBand': 'Aviation 108-138 MHz',
        'GPS-L1': 'GPS L1 1.575 GHz (reference)',
        'OutOfBand': 'Out of band',
      })[band] || band;
    },

    get timelineFrom() { return Math.floor(Date.now()/1000) - this.timelineHours * 3600; },
    get timelineTo()   { return Math.floor(Date.now()/1000); },
    get timelineMid()  { return (this.timelineFrom + this.timelineTo) / 2; },

    get timelineRows() {
      const groups = {};
      const total = this.timelineTo - this.timelineFrom;
      for (const v of this.visits) {
        const eid = v.entity_id;
        if (!groups[eid]) {
          groups[eid] = {
            entity_id: eid,
            label: v.friendly_name || eid,
            classification: v.classification,
            anomaly: v.anomaly_score || 0,
            visits: [],
          };
        }
        const left = ((v.start_unix - this.timelineFrom) / total) * 100;
        const width = Math.max(0.5, ((v.end_unix - v.start_unix) / total) * 100);
        groups[eid].visits.push({ ...v, left, width });
      }
      return Object.values(groups).sort((a,b) => (b.anomaly || 0) - (a.anomaly || 0));
    },

    // ---- HELPERS ----
    entityDisplayName(e) {
      if (!e) return '—';
      if (e.friendly_name) return e.friendly_name;
      if (e.kind === 'ble_phone' && e.is_random_mac) {
        return e.vendor ? `${e.vendor} phone` : 'phone (random MAC)';
      }
      if (e.entity_id?.startsWith('subghz:')) {
        const parts = e.entity_id.split(':');
        return `${parts[1]} ${parts[2] !== 'unknown' ? parts[2] : ''}`.trim();
      }
      if (e.entity_id?.startsWith('ble:')) return e.entity_id.slice(4);
      return e.entity_id || '—';
    },
    entityMetaLine(e) {
      const bits = [];
      if (e.avg_rssi != null) bits.push(`${Math.round(e.avg_rssi)} dBm`);
      bits.push(`${e.visit_count || 0} visits`);
      if (e.regularity != null) bits.push(`${Math.round(e.regularity * 100)}% regular`);
      bits.push(this.relTime(e.last_seen_unix));
      return bits.join(' · ');
    },
    relTime(ts) {
      if (!ts) return '—';
      const dt = Math.floor(Date.now()/1000) - ts;
      if (dt < 30) return 'just now';
      if (dt < 60) return `${dt}s ago`;
      if (dt < 3600) return `${Math.floor(dt/60)}m ago`;
      if (dt < 86400) return `${Math.floor(dt/3600)}h ago`;
      return `${Math.floor(dt/86400)}d ago`;
    },
    formatTime(ts) {
      const d = new Date(ts * 1000);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },
    formatDateTime(ts) {
      const d = new Date(ts * 1000);
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },
    formatDuration(s) {
      if (s < 60) return `${s}s`;
      if (s < 3600) return `${Math.floor(s/60)}m ${s%60}s`;
      return `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
    },
    formatEvidence(k, v) {
      if (typeof v === 'number') return v % 1 ? v.toFixed(2) : v;
      if (typeof v === 'string') return v;
      return JSON.stringify(v);
    },
    heatColor(score) {
      // 0 = green, 0.5 = amber, 1 = red
      const s = Math.max(0, Math.min(1, score));
      if (s < 0.5) {
        // green -> amber
        const t = s / 0.5;
        const r = Math.round(93 + (246 - 93) * t);
        const g = Math.round(208 + (196 - 208) * t);
        const b = Math.round(168 + (83 - 168) * t);
        return `rgb(${r}, ${g}, ${b})`;
      }
      const t = (s - 0.5) / 0.5;
      const r = Math.round(246 + (255 - 246) * t);
      const g = Math.round(196 + (84 - 196) * t);
      const b = Math.round(83 + (112 - 83) * t);
      return `rgb(${r}, ${g}, ${b})`;
    },
    classificationClass(c) {
      return ({
        'anchor': 'bg-anchor/15 text-anchor',
        'satellite': 'bg-satellite/15 text-satellite',
        'known_guest': 'bg-guest/15 text-guest',
        'untrusted': 'bg-threat/15 text-threat',
      })[c] || 'bg-slate-500/15 text-slate-400';
    },
    classificationDot(c) {
      return ({
        'anchor': 'bg-anchor', 'satellite': 'bg-satellite', 'known_guest': 'bg-guest', 'untrusted': 'bg-threat',
      })[c] || 'bg-unknown/60';
    },
    kindBadgeClass(k) {
      if (!k) return 'bg-slate-700/40 text-slate-400';
      if (k.includes('phone')) return 'bg-signal-glow/15 text-signal-glow';
      if (k.includes('headphones')) return 'bg-satellite/15 text-satellite';
      if (k.includes('keyfob')) return 'bg-signal-warm/15 text-signal-warm';
      if (k.includes('garage')) return 'bg-signal-warm/15 text-signal-warm';
      if (k.includes('findmy')) return 'bg-signal-deep/20 text-purple-300';
      return 'bg-slate-700/40 text-slate-400';
    },
    visitColor(v) {
      const a = v.anomaly_score || 0;
      if (a >= 0.5) return '#ff5470';
      const c = ({
        'anchor': '#f6c453', 'satellite': '#5dd0a8', 'known_guest': '#7dd3fc', 'untrusted': '#ff5470',
      })[v.classification] || '#94a3b8';
      return c;
    },
    severityBorderClass(s) {
      return ({ critical: 'border-l-threat', high: 'border-l-signal-warm', medium: 'border-l-signal-glow', low: 'border-l-slate-500' })[s] || 'border-l-slate-500';
    },
    severityChipBg(s) {
      return ({ critical: 'bg-threat/15', high: 'bg-signal-warm/15', medium: 'bg-signal-glow/15', low: 'bg-slate-700/40' })[s] || 'bg-slate-700/40';
    },
    severityChipText(s) {
      return ({ critical: 'text-threat', high: 'text-signal-warm', medium: 'text-signal-glow', low: 'text-slate-400' })[s] || 'text-slate-400';
    },
    severityChipFull(s) {
      return ({
        critical: 'bg-threat/20 text-threat',
        high: 'bg-signal-warm/20 text-signal-warm',
        medium: 'bg-signal-glow/20 text-signal-glow',
        low: 'bg-slate-700/40 text-slate-400',
      })[s] || 'bg-slate-700/40 text-slate-400';
    },
    visitsAt(day, hour) {
      if (!this.entityDetail?.visits) return 0;
      let n = 0;
      for (const v of this.entityDetail.visits) {
        const d = new Date(v.start_unix * 1000);
        const dow = (d.getUTCDay() + 6) % 7;
        if (dow === day && d.getUTCHours() === hour) n++;
      }
      return n;
    },
    heatmapCell(day, hour) {
      const n = this.visitsAt(day, hour);
      if (n === 0) return 'rgba(31, 39, 64, 0.5)';
      const max = (this.entityDetail?.visits || []).length || 1;
      const t = Math.min(1, n / Math.max(3, max / 30));
      const alpha = 0.2 + 0.8 * t;
      return `rgba(124, 58, 237, ${alpha})`;
    },
  };
}
