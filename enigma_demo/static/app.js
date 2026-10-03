"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const DOMAIN_SIZE = 17576;
  const TERMINAL_STATES = new Set(["complete", "cancelled", "timed_out", "failed"]);
  const TEXT_POLICY = "A–Z only, in either case. ASCII spaces, tabs and line breaks are removed; punctuation and other characters are rejected.";
  const state = {
    mode: "transform", token: null, ready: false, busy: false,
    generation: 0, jobId: null, lastJob: null, unknown: false,
    cancelling: false, reconnecting: false, pollTimer: null,
    samples: [], activeSample: null, maxLetters: 256,
    transformation: null, traceIndex: 0,
  };

  class RequestError extends Error {
    constructor(message, status = 0) {
      super(message);
      this.status = status;
    }
  }

  class InputError extends Error {
    constructor(message, field) {
      super(message);
      this.field = field;
    }
  }

  function text(id, value) {
    const node = $(id);
    const next = String(value);
    if (node.textContent !== next) node.textContent = next;
  }

  function integer(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
    return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
  }

  function setConnection(online, label) {
    $("connection-badge").className = `connection-badge ${online ? "is-online" : "is-offline"}`;
    text("connection-label", label || (online ? "Running locally" : "Connection interrupted"));
  }

  function setStatus(message, badge = null, tone = "") {
    text("request-status", message);
    if (badge !== null) text("result-badge", badge);
    $("result-badge").className = `result-badge ${tone ? `is-${tone}` : ""}`;
  }

  function clearError() {
    $("error-message").hidden = true;
    text("error-message", "");
    document.querySelectorAll('[aria-invalid="true"]').forEach((node) => node.removeAttribute("aria-invalid"));
  }

  function showError(message, field = null) {
    text("error-message", message);
    $("error-message").hidden = false;
    if (field && !field.disabled) {
      field.setAttribute("aria-invalid", "true");
      field.focus();
    }
  }

  function refreshControls() {
    const locked = state.busy || !state.ready;
    $("machine-fields").disabled = locked;
    $("run-button").disabled = locked;
    $("mode-transform").disabled = state.busy;
    $("mode-search").disabled = state.busy;
    $("cancel-button").hidden = !(state.busy && state.mode === "search" && state.jobId);
    $("cancel-button").disabled = state.cancelling || state.reconnecting;
    text("cancel-button", state.cancelling ? "Cancellation requested…" : "Cancel search");
    $("retry-button").disabled = state.reconnecting;
    $("machine-form").setAttribute("aria-busy", String(state.busy));
    text("run-label", state.busy ? (state.mode === "search" ? "Search in progress…" : "Transforming…") :
      (state.mode === "search" ? "Search 17,576 starts" : "Transform message"));
  }

  function clearPolling() {
    if (state.pollTimer !== null) window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }

  function clearResults() {
    state.transformation = null;
    state.traceIndex = 0;
    state.lastJob = null;
    state.jobId = null;
    $("welcome-panel").hidden = state.mode === "search";
    $("transform-result").hidden = true;
    $("search-result").hidden = state.mode !== "search";
    if (state.mode === "search") resetSearchView();
    setStatus(state.mode === "search" ? "Choose a reference search or enter a ciphertext and known plaintext fragment." :
      "Load an example or use the default settings, then transform your message.", "Ready");
  }

  function setMode(mode) {
    if (state.busy || !["transform", "search"].includes(mode)) return;
    state.mode = mode;
    state.generation += 1;
    state.activeSample = null;
    $("sample-expectation").hidden = true;
    const search = mode === "search";
    for (const name of ["transform", "search"]) {
      $(`mode-${name}`).classList.toggle("is-selected", name === mode);
      $(`mode-${name}`).setAttribute("aria-pressed", String(name === mode));
    }
    $("search-fields").hidden = !search;
    $("positions-field").hidden = search;
    $("positions").disabled = search;
    $("unknown-windows-note").hidden = !search;
    $("key-fields").classList.toggle("is-search", search);
    text("key-hint", search ? "Ring settings are three letters, left to right." : "Three letters, left to right. Windows are set before the first keypress.");
    text("message-label", search ? "Ciphertext to search" : "Message to transform");
    text("mode-caption", search ? "One unknown: the starting windows." : "A known key. An observable path.");
    text("results-heading", search ? "Explore the starting positions" : "Inside the machine");
    text("action-hint", search ? "All matching starts are returned. A short crib may match many keys." : "Encrypt and decrypt with the same initial settings.");
    clearError();
    clearResults();
    refreshControls();
  }

  function normalizedLetters(value, label, field, allowEmpty = false) {
    if (!/^[A-Za-z \t\n\r\f\v]*$/.test(value)) {
      throw new InputError(`${label} can contain only A–Z letters and ASCII whitespace. Remove punctuation and other characters.`, field);
    }
    const normalized = value.replace(/[ \t\n\r\f\v]/g, "").toUpperCase();
    if (!allowEmpty && !normalized.length) throw new InputError(`${label} must contain at least one letter.`, field);
    if (normalized.length > state.maxLetters) throw new InputError(`${label} is limited to ${state.maxLetters} letters after whitespace is removed.`, field);
    return normalized;
  }

  function updateCount() {
    const raw = $("message-input").value;
    const count = raw.replace(/[ \t\n\r\f\v]/g, "").length;
    const valid = /^[A-Za-z \t\n\r\f\v]*$/.test(raw) && count <= state.maxLetters;
    text("message-count", `${count.toLocaleString("en-US")} ${count === 1 ? "letter" : "letters"}`);
    $("message-count").classList.toggle("is-invalid", !valid);
  }

  function readSettings() {
    const rotors = [$("rotor-left").value, $("rotor-middle").value, $("rotor-right").value];
    if (new Set(rotors).size !== 3) throw new InputError("Select three different rotors; a rotor cannot occupy two slots.", $("rotor-left"));
    for (const id of state.mode === "search" ? ["rings"] : ["rings", "positions"]) {
      if (!/^[A-Za-z]{3}$/.test($(id).value)) throw new InputError(`${id === "rings" ? "Ring settings" : "Starting windows"} must be exactly three A–Z letters, with no spaces.`, $(id));
    }
    const rawPlugs = $("plugboard").value;
    if (!/^[A-Za-z \t\n\r\f\v]*$/.test(rawPlugs)) throw new InputError("Plugboard pairs must use A–Z letters separated by ASCII spaces.", $("plugboard"));
    const pairs = rawPlugs.trim() ? rawPlugs.trim().toUpperCase().split(/[ \t\n\r\f\v]+/) : [];
    const joined = pairs.join("");
    if (pairs.length > 13 || pairs.some((pair) => !/^[A-Z]{2}$/.test(pair)) || new Set(joined).size !== joined.length) {
      throw new InputError("Use up to 13 disjoint plugboard pairs, such as AB CD. Each letter must appear only once.", $("plugboard"));
    }
    return {
      rotors, reflector: $("reflector").value, rings: $("rings").value.toUpperCase(),
      positions: state.mode === "search" ? "AAA" : $("positions").value.toUpperCase(),
      plugboard: pairs.join(" "),
    };
  }

  function readRequest() {
    const settings = readSettings();
    const raw = $("message-input").value;
    const message = normalizedLetters(raw, state.mode === "search" ? "Ciphertext" : "Message", $("message-input"), state.mode === "transform");
    if (state.mode === "transform") return { settings, text: raw };
    const crib = normalizedLetters($("crib-input").value, "Known plaintext fragment", $("crib-input"));
    const offsetText = $("offset-input").value;
    if (!/^\d+$/.test(offsetText) || !integer(Number(offsetText))) throw new InputError("Offset must be a whole number of zero or more.", $("offset-input"));
    const offset = Number(offsetText);
    if (offset + crib.length > message.length) throw new InputError("The plaintext fragment must fit inside the ciphertext at the selected offset.", $("offset-input"));
    return { settings, ciphertext: raw, crib: $("crib-input").value, offset, strategy: $("strategy-input").value };
  }

  async function api(path, options = {}) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 15000);
    const method = options.method || "GET";
    const headers = { Accept: "application/json" };
    if (method === "POST") {
      headers["Content-Type"] = "application/json";
      headers["X-Enigma-Token"] = state.token;
    }
    try {
      const response = await fetch(path, {
        method, headers, credentials: "same-origin", cache: "no-store", signal: controller.signal,
        ...(method === "POST" ? { body: JSON.stringify(options.body || {}) } : {}),
      });
      let payload;
      try { payload = await response.json(); }
      catch { throw new RequestError("The local server returned an unreadable response.", response.ok ? 0 : response.status); }
      if (!response.ok) {
        const detail = typeof payload.error === "string" ? payload.error : `The local server returned HTTP ${response.status}.`;
        throw new RequestError(detail, response.status);
      }
      return payload;
    } catch (error) {
      if (error instanceof RequestError) throw error;
      throw new RequestError(error.name === "AbortError" ? "The local server did not respond in time." : "Could not reach the local server.");
    } finally {
      window.clearTimeout(timer);
    }
  }

  function showSampleDescription() {
    const sample = state.samples.find((item) => item.id === $("sample-select").value);
    text("sample-description", sample ? sample.description || "Load its complete machine settings." : "Choose an example to load its settings and reference expectation.");
  }

  function loadSample() {
    if (state.busy) return;
    const sample = state.samples.find((item) => item.id === $("sample-select").value);
    if (!sample) return;
    setMode(sample.mode === "search" ? "search" : "transform");
    state.activeSample = sample;
    const settings = sample.settings || {};
    const rotors = settings.rotors || ["I", "II", "III"];
    ["rotor-left", "rotor-middle", "rotor-right"].forEach((id, index) => { $(id).value = rotors[index]; });
    $("reflector").value = settings.reflector || "B";
    $("rings").value = settings.rings || "AAA";
    $("positions").value = settings.positions || settings.windows || "AAA";
    $("plugboard").value = Array.isArray(settings.plugboard) ? settings.plugboard.join(" ") : settings.plugboard || "";
    $("message-input").value = state.mode === "search" ? sample.ciphertext || "" : sample.text || "";
    $("crib-input").value = sample.crib || "AAAAA";
    $("offset-input").value = String(sample.offset ?? 0);
    $("strategy-input").value = sample.strategy === "early" ? "early" : "baseline";
    const expected = sample.expected || {};
    let expectation = "See this example’s reference notes.";
    if (typeof expected.output === "string") expectation = `Output: ${expected.output || "(empty)"}`;
    if (Array.isArray(expected.matches)) {
      expectation = expected.matches.length <= 6 ? `Matching starts: ${expected.matches.join(", ") || "none"}` : `${expected.matches.length.toLocaleString("en-US")} matching starting positions`;
    } else if (integer(expected.match_count)) {
      expectation = `${expected.match_count.toLocaleString("en-US")} matching starting positions`;
    }
    text("sample-expected-text", expectation);
    text("sample-footnote", sample.footnote || "Reference expectation; run the example to compare the result.");
    $("sample-expectation").hidden = false;
    showSampleDescription();
    updateCount();
    if (state.mode === "search") resetSearchView();
    setStatus(`Loaded ${sample.title}. The example has not been run yet.`, "Example loaded");
  }

  async function bootstrap() {
    const payload = await api("/api/bootstrap");
    if (typeof payload.token !== "string" || !payload.token || !Array.isArray(payload.samples)) throw new RequestError("The local server returned an incomplete session configuration.");
    state.token = payload.token;
    state.samples = payload.samples.filter((sample) => sample && typeof sample.id === "string" && typeof sample.title === "string");
    state.maxLetters = integer(payload.limits?.max_text_letters, 1, 100000) ? payload.limits.max_text_letters : 256;
    const selected = $("sample-select").value;
    $("sample-select").replaceChildren();
    for (const sample of state.samples) {
      const option = document.createElement("option");
      option.value = sample.id;
      option.textContent = `${sample.mode === "search" ? "Search" : "Transform"} · ${sample.title}`;
      $("sample-select").append(option);
    }
    if (state.samples.some((sample) => sample.id === selected)) $("sample-select").value = selected;
    text("text-policy", `${TEXT_POLICY} Up to ${state.maxLetters} letters after normalization.`);
    state.ready = true;
    setConnection(true);
    showSampleDescription();
    updateCount();
    refreshControls();
  }

  function formatSettings(settings) {
    const plugs = Array.isArray(settings.plugboard) ? settings.plugboard.join(" ") : settings.plugboard;
    return `${settings.rotors.join(" · ")}  /  ${settings.reflector}  /  rings ${settings.rings}  /  start ${settings.positions}  /  plugs ${plugs || "none"}`;
  }

  function validateTransform(payload) {
    if (!payload || typeof payload.input !== "string" || typeof payload.output !== "string" || !Array.isArray(payload.trace) ||
      payload.input.length !== payload.output.length || payload.trace.length !== payload.input.length || !/^[A-Z]{3}$/.test(payload.final_positions) ||
      !payload.settings || !Array.isArray(payload.settings.rotors) || payload.settings.rotors.length !== 3) throw new RequestError("The server returned an incomplete transformation trace.");
    payload.trace.forEach((step, index) => {
      if (!step || !/^[A-Z]{3}$/.test(step.before) || !/^[A-Z]{3}$/.test(step.after) ||
        !Array.isArray(step.steps) || step.steps.length !== 3 || !step.steps.every((value) => typeof value === "boolean") ||
        !Array.isArray(step.path) || step.path.length !== 9 || step.input_letter !== payload.input[index] || step.output_letter !== payload.output[index]) {
        throw new RequestError("The server returned an inconsistent character trace.");
      }
    });
  }

  function renderWindows(target, positions, stepped = null) {
    const fragment = document.createDocumentFragment();
    [...positions].forEach((letter, index) => {
      const tile = document.createElement("div");
      tile.className = `window-tile ${stepped?.[index] ? "is-stepped" : ""}`;
      const name = document.createElement("span");
      name.className = "rotor-name";
      name.textContent = state.transformation.settings.rotors[index];
      const window = document.createElement("strong");
      window.textContent = letter;
      const movement = document.createElement("span");
      movement.className = "movement-label";
      movement.textContent = stepped ? (stepped[index] ? "Stepped" : "Held") : "Window";
      tile.append(name, window, movement);
      fragment.append(tile);
    });
    $(target).replaceChildren(fragment);
  }

  function renderTrace(index) {
    if (!state.transformation?.trace.length) return;
    state.traceIndex = Math.max(0, Math.min(index, state.transformation.trace.length - 1));
    const step = state.transformation.trace[state.traceIndex];
    text("trace-counter", `Character ${state.traceIndex + 1} of ${state.transformation.trace.length}`);
    text("trace-letter", `${step.input_letter} → ${step.output_letter}`);
    $("trace-step").value = String(state.traceIndex + 1);
    $("trace-step").setAttribute("aria-valuetext", `Character ${state.traceIndex + 1}: ${step.input_letter} becomes ${step.output_letter}`);
    $("trace-prev").disabled = state.traceIndex === 0;
    $("trace-next").disabled = state.traceIndex === state.transformation.trace.length - 1;
    renderWindows("windows-before", step.before);
    renderWindows("windows-after", step.after, step.steps);
    const fragment = document.createDocumentFragment();
    step.path.forEach((stage, stageIndex) => {
      const item = document.createElement("li");
      item.className = `signal-stage ${stage.direction === "reflect" ? "is-reflector" : ""}`;
      const heading = document.createElement("div");
      heading.className = "stage-heading";
      const component = document.createElement("span");
      component.textContent = stage.component === "plugboard" ? "Plugboard" : stage.direction === "reflect" ? `Reflector ${stage.component}` : `Rotor ${stage.component}`;
      const number = document.createElement("span");
      number.className = "stage-number";
      number.textContent = String(stageIndex + 1).padStart(2, "0");
      heading.append(component, number);
      const direction = document.createElement("span");
      direction.className = "stage-direction";
      direction.textContent = ({ in: "entry", out: "exit", forward: "toward reflector", reverse: "return path", reflect: "turnaround" })[stage.direction] || stage.direction;
      const letters = document.createElement("span");
      letters.className = "stage-letters";
      const input = document.createTextNode(stage.input_letter);
      const arrow = document.createElement("span");
      arrow.className = "stage-arrow";
      arrow.textContent = "→";
      letters.append(input, arrow, document.createTextNode(stage.output_letter));
      item.append(heading, direction, letters);
      fragment.append(item);
    });
    $("signal-path").replaceChildren(fragment);
  }

  function showTransformation(payload) {
    validateTransform(payload);
    state.transformation = payload;
    $("welcome-panel").hidden = true;
    $("transform-result").hidden = false;
    $("search-result").hidden = true;
    text("transform-settings", formatSettings(payload.settings));
    text("output-text", payload.output);
    text("output-length", `${payload.output.length} ${payload.output.length === 1 ? "letter" : "letters"} transformed`);
    text("final-windows", payload.final_positions);
    $("copy-output").disabled = !payload.output.length;
    text("copy-output", "Copy output");
    $("trace-panel").hidden = !payload.trace.length;
    $("empty-trace").hidden = !!payload.trace.length;
    $("trace-step").max = String(Math.max(1, payload.trace.length));
    renderTrace(0);
    setStatus("Transformation complete. Inspect the recorded path for any character below.", "Complete", "active");
  }

  function resetSearchView() {
    text("search-title", "Every start, one bounded search");
    text("search-state-detail", "Rotor order, rings, reflector and plugboard stay fixed.");
    $("search-progress").value = 0;
    text("search-progress-label", "0 / 17,576");
    text("progress-caption", "Progress is reported by the local server.");
    text("search-strategy", $("strategy-input").value === "early" ? "Early rejection" : "Baseline");
    text("search-character-count", "0");
    text("match-count", "—");
    text("matches-label", "Awaiting a complete search");
    text("matches-explanation", "Matches are shown only after all starting positions have been checked.");
    $("matches-list").replaceChildren();
    $("matches-list").hidden = true;
    $("search-settings-panel").hidden = true;
  }

  function validateJob(job) {
    if (!job || typeof job.id !== "string" || !job.id || !["running", ...TERMINAL_STATES].includes(job.status) ||
      !["baseline", "early"].includes(job.strategy) || job.domain_size !== DOMAIN_SIZE || !integer(job.candidates_checked, 0, DOMAIN_SIZE) ||
      !integer(job.characters_transformed)) throw new RequestError("The local server returned an incomplete search status.");
    if (job.status === "complete") {
      const result = job.result;
      if (job.candidates_checked !== DOMAIN_SIZE || job.partial_matches_unverified !== false || !result || result.complete !== true ||
        result.global_domain !== true || result.candidates_checked !== DOMAIN_SIZE || !Array.isArray(result.matches) ||
        !result.matches.every((value) => typeof value === "string" && /^[A-Z]{3}$/.test(value))) {
        throw new RequestError("The local server has not supplied a verified complete search result.");
      }
    }
  }

  function applyJob(job, generation) {
    if (generation !== state.generation || !state.busy) return;
    validateJob(job);
    if (state.jobId && job.id !== state.jobId) throw new RequestError("The search response belongs to a different job.");
    if (state.lastJob && job.status === "running" && job.candidates_checked < state.lastJob.candidates_checked) return;
    state.jobId = job.id;
    state.lastJob = job;
    state.unknown = false;
    setConnection(true);
    clearError();
    $("retry-button").hidden = true;
    $("welcome-panel").hidden = true;
    $("transform-result").hidden = true;
    $("search-result").hidden = false;
    $("search-progress").value = job.candidates_checked;
    text("search-progress-label", `${job.candidates_checked.toLocaleString("en-US")} / 17,576`);
    text("search-character-count", job.characters_transformed.toLocaleString("en-US"));
    text("search-strategy", job.strategy === "early" ? "Early rejection" : "Baseline");
    if (job.status === "running") {
      text("search-title", state.cancelling ? "Waiting for cancellation" : "Checking the starting positions");
      text("search-state-detail", "Every candidate is checked against the same fixed settings and aligned plaintext fragment.");
      text("progress-caption", "Live, server-reported progress. A partial search is not a complete result.");
      setStatus(state.cancelling ? "Cancellation requested. Waiting for the server to confirm the final state." : "Search running. Configuration is locked until the job ends.", state.cancelling ? "Cancelling" : "Searching", "active");
    } else {
      clearPolling();
      state.busy = false;
      state.cancelling = false;
      state.generation += 1;
      if (job.status === "complete") {
        const matches = job.result.matches;
        const settings = job.result.settings;
        if (settings && Array.isArray(settings.rotors)) {
          const plugs = Array.isArray(settings.plugboard) ? settings.plugboard.join(" ") : settings.plugboard;
          text("search-settings", `${settings.rotors.join(" · ")} / ${settings.reflector} / rings ${settings.rings} / plugs ${plugs || "none"} / starts AAA–ZZZ / crib offset ${job.result.offset}`);
          text("search-input-snapshot", `Ciphertext: ${job.result.ciphertext}\nKnown fragment: ${job.result.crib}\nOffset: ${job.result.offset}`);
          $("search-settings-panel").hidden = false;
        }
        text("search-title", "All 17,576 positions checked");
        text("search-state-detail", "This is a complete result for the supplied settings, ciphertext and crib.");
        text("progress-caption", "Complete domain checked. All matching starting positions are listed below.");
        text("match-count", matches.length.toLocaleString("en-US"));
        text("matches-label", `${matches.length.toLocaleString("en-US")} ${matches.length === 1 ? "match" : "matches"}`);
        text("matches-explanation", matches.length === 0 ? "No starting position matches this crib under the supplied fixed settings. This is a valid complete search result." :
          matches.length === 1 ? "One starting position matches this crib under the supplied fixed settings. This uniqueness applies to this search only." :
            "Several starting positions fit the same fragment. A longer correctly aligned crib may help distinguish them; every match is retained here.");
        const fragment = document.createDocumentFragment();
        for (const position of matches) {
          const item = document.createElement("span");
          item.className = "match-position";
          item.setAttribute("role", "listitem");
          item.textContent = position;
          fragment.append(item);
        }
        $("matches-list").replaceChildren(fragment);
        $("matches-list").hidden = matches.length === 0;
        setStatus(`Search complete: ${matches.length.toLocaleString("en-US")} matching ${matches.length === 1 ? "start" : "starts"} across all 17,576 candidates.`, "Complete", "active");
      } else {
        const labels = { cancelled: "Search cancelled", timed_out: "Search reached its time limit", failed: "Search failed" };
        text("search-title", labels[job.status]);
        text("search-state-detail", "The complete domain was not verified. Partial matches are not presented as a solution.");
        text("progress-caption", "Last reported progress at the end of this incomplete job.");
        text("match-count", "—");
        text("matches-label", "No complete result");
        text("matches-explanation", "This search ended without a verified complete result. You can adjust the inputs and start a new search.");
        $("matches-list").hidden = true;
        $("matches-list").replaceChildren();
        setStatus(`${labels[job.status]}. ${job.candidates_checked.toLocaleString("en-US")} candidates were checked; the result is incomplete.`, job.status === "cancelled" ? "Cancelled" : "Incomplete", "warning");
        if (job.error) showError(String(job.error));
      }
    }
    refreshControls();
  }

  function markUnknown(message) {
    state.unknown = true;
    state.cancelling = false;
    clearPolling();
    setConnection(false);
    text("search-title", "Search status is unknown");
    text("search-state-detail", "The server may still be working. No completion or cancellation has been confirmed.");
    text("progress-caption", "Last confirmed progress. This display is paused until the connection is restored.");
    setStatus("Connection interrupted. The job’s outcome is unknown; its settings remain locked.", "Unknown", "warning");
    showError(`${message} ${state.jobId ? "Use Check connection to resume checking this same job." : "The submission may have reached the server. Restart the local app before reloading this page to safely begin another search."}`);
    $("retry-button").hidden = false;
    refreshControls();
  }

  function schedulePoll(generation) {
    clearPolling();
    if (generation !== state.generation || !state.busy || !state.jobId || state.unknown) return;
    state.pollTimer = window.setTimeout(() => pollJob(generation), 350);
  }

  async function pollJob(generation) {
    if (generation !== state.generation || !state.busy || !state.jobId) return;
    const jobId = state.jobId;
    try {
      const job = await api(`/api/search/${encodeURIComponent(jobId)}`);
      if (generation !== state.generation || !state.busy || state.jobId !== jobId) return;
      applyJob(job, generation);
      schedulePoll(generation);
    } catch (error) {
      if (generation === state.generation && state.busy) markUnknown(error.message);
    }
  }

  async function submit(event) {
    event.preventDefault();
    if (state.busy || !state.ready) return;
    clearError();
    let request;
    try { request = readRequest(); }
    catch (error) { showError(error.message, error.field); return; }
    const generation = ++state.generation;
    state.busy = true;
    state.unknown = false;
    state.cancelling = false;
    state.jobId = null;
    state.lastJob = null;
    clearPolling();
    $("retry-button").hidden = true;
    refreshControls();
    if (state.mode === "search") {
      resetSearchView();
      $("welcome-panel").hidden = true;
      $("transform-result").hidden = true;
      $("search-result").hidden = false;
      setStatus("Starting a complete search of all 17,576 positions…", "Starting", "active");
    } else {
      setStatus("Transforming the message and recording its signal path…", "Working", "active");
    }
    try {
      const response = await api(state.mode === "search" ? "/api/search" : "/api/transform", { method: "POST", body: request });
      if (generation !== state.generation) return;
      if (state.mode === "search") {
        applyJob(response, generation);
        schedulePoll(generation);
      } else {
        showTransformation(response);
        state.busy = false;
        refreshControls();
      }
    } catch (error) {
      if (generation !== state.generation) return;
      const definiteRejection = error.status >= 400 && error.status < 500;
      if (state.mode === "search" && !definiteRejection) {
        markUnknown(error.message);
      } else {
        state.busy = false;
        showError(error.message);
        setStatus("The operation did not produce a new result. Check the input or local connection and try again.", "Not completed", "error");
        if (!error.status || error.status === 403) {
          state.ready = false;
          setConnection(false);
          $("retry-button").hidden = false;
        }
        refreshControls();
      }
    }
  }

  async function cancelSearch() {
    if (!state.busy || !state.jobId || state.cancelling || state.reconnecting) return;
    const generation = state.generation;
    state.cancelling = true;
    state.unknown = false;
    clearPolling();
    refreshControls();
    setStatus("Cancellation requested. Waiting for the server to confirm the final state.", "Cancelling", "warning");
    try {
      const job = await api(`/api/search/${encodeURIComponent(state.jobId)}/cancel`, { method: "POST", body: {} });
      if (generation !== state.generation || !state.busy) return;
      applyJob(job, generation);
      schedulePoll(generation);
    } catch (error) {
      if (generation === state.generation && state.busy) markUnknown(error.message);
    }
  }

  async function retryConnection() {
    if (state.reconnecting) return;
    const generation = state.generation;
    state.reconnecting = true;
    refreshControls();
    try {
      await bootstrap();
      if (generation !== state.generation) return;
      if (state.busy && state.jobId) {
        state.unknown = false;
        await pollJob(generation);
      } else if (state.busy) {
        showError("The local connection is available, but the previous submission is still unconfirmed. Restart the local app before reloading this page to safely begin another search.");
        setStatus("Connection restored; the previous submission’s outcome is still unknown.", "Unknown", "warning");
      } else {
        clearError();
        $("retry-button").hidden = true;
        setStatus("Connected to the local server. Your configuration is ready to run.", "Ready");
      }
    } catch (error) {
      setConnection(false);
      showError(error.message);
    } finally {
      state.reconnecting = false;
      refreshControls();
    }
  }

  async function copyOutput() {
    const value = state.transformation?.output;
    if (!value) return;
    let copied = false;
    if (navigator.clipboard?.writeText) {
      try { await navigator.clipboard.writeText(value); copied = true; }
      catch { /* Fall back to a user-initiated local text selection. */ }
    }
    if (!copied) {
      const buffer = document.createElement("textarea");
      buffer.className = "clipboard-buffer";
      buffer.value = value;
      buffer.setAttribute("aria-label", "Output to copy");
      document.body.append(buffer);
      buffer.select();
      try { copied = document.execCommand("copy"); }
      catch { copied = false; }
      buffer.remove();
      $("copy-output").focus();
    }
    text("copy-output", copied ? "Copied" : "Select output to copy");
    if (!copied) {
      $("output-text").focus();
      window.getSelection()?.selectAllChildren($("output-text"));
    }
  }

  $("machine-form").addEventListener("submit", submit);
  $("mode-transform").addEventListener("click", () => setMode("transform"));
  $("mode-search").addEventListener("click", () => setMode("search"));
  $("sample-select").addEventListener("change", () => {
    $("sample-expectation").hidden = true;
    state.activeSample = null;
    showSampleDescription();
  });
  $("load-sample").addEventListener("click", loadSample);
  $("cancel-button").addEventListener("click", cancelSearch);
  $("retry-button").addEventListener("click", retryConnection);
  $("copy-output").addEventListener("click", copyOutput);
  $("trace-prev").addEventListener("click", () => renderTrace(state.traceIndex - 1));
  $("trace-next").addEventListener("click", () => renderTrace(state.traceIndex + 1));
  $("trace-step").addEventListener("input", () => renderTrace(Number($("trace-step").value) - 1));
  $("message-input").addEventListener("input", updateCount);
  $("machine-fields").addEventListener("input", (event) => {
    if (event.target.id === "sample-select" || state.busy) return;
    state.activeSample = null;
    $("sample-expectation").hidden = true;
    if (state.transformation) setStatus("Configuration edited. The displayed trace belongs to the settings shown under Settings used.", "Previous result", "warning");
    if (state.mode === "search" && state.lastJob) {
      const completed = state.lastJob.status === "complete";
      setStatus(completed ? "Configuration edited. The displayed search result belongs to the earlier settings and input shown below. Run a new search to use your edits." : "Configuration edited. The displayed progress belongs to the previous incomplete search. Run a new search to use your edits.", "Previous result", "warning");
      text("search-state-detail", completed ? "Retained result from the earlier search. Its settings and input are shown below." : "Retained progress from the previous incomplete search. No complete result is available.");
    }
  });
  $("strategy-input").addEventListener("change", () => {
    if (!state.lastJob && !state.busy) text("search-strategy", $("strategy-input").value === "early" ? "Early rejection" : "Baseline");
  });
  window.addEventListener("pagehide", clearPolling);
  bootstrap().catch((error) => {
    state.ready = false;
    setConnection(false, "Local server unavailable");
    showError(`${error.message} Keep the local app running, then check the connection.`);
    $("retry-button").hidden = false;
    setStatus("The workbench is waiting for its local server.", "Offline", "warning");
    refreshControls();
  });
})();
