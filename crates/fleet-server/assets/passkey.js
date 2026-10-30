"use strict";

const status = document.getElementById("status");
const form = document.getElementById("passkey-form");
const mode = document.body.dataset.mode;

function decode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)).buffer;
}

function encode(buffer) {
  let text = "";
  for (const byte of new Uint8Array(buffer)) {
    text += String.fromCharCode(byte);
  }
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function say(message) {
  status.textContent = message;
}

async function post(path, body, csrf) {
  const headers = { "content-type": "application/json" };
  if (csrf) {
    headers["x-csrf-token"] = csrf;
  }
  const response = await fetch(path, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("refused");
  }
  return response.json();
}

function creationOptions(options) {
  const key = options.publicKey;
  key.challenge = decode(key.challenge);
  key.user.id = decode(key.user.id);
  for (const item of key.excludeCredentials || []) {
    item.id = decode(item.id);
  }
  return options;
}

function requestOptions(options) {
  const key = options.publicKey;
  key.challenge = decode(key.challenge);
  for (const item of key.allowCredentials || []) {
    item.id = decode(item.id);
  }
  return options;
}

function registration(credential) {
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: encode(credential.response.attestationObject),
      clientDataJSON: encode(credential.response.clientDataJSON),
    },
    extensions: credential.getClientExtensionResults(),
  };
}

function assertion(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encode(response.authenticatorData),
      clientDataJSON: encode(response.clientDataJSON),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  };
}

async function register(startPath, finishPath, startBody, csrf) {
  const started = await post(startPath, startBody, csrf);
  const created = await navigator.credentials.create(creationOptions(started.options));
  await post(finishPath, { ceremony: started.ceremony, credential: registration(created) }, csrf);
}

async function run() {
  const username = document.getElementById("username");
  if (mode === "setup") {
    const code = decodeURIComponent(location.pathname.split("/").pop());
    await register("/passkey/setup/start", "/passkey/setup/finish", { code, username: username.value });
    location.assign("/account");
  } else if (mode === "login") {
    const started = await post("/passkey/login/start", { username: username.value });
    const got = await navigator.credentials.get(requestOptions(started.options));
    await post("/passkey/login/finish", { ceremony: started.ceremony, credential: assertion(got) });
    location.assign("/account");
  } else if (mode === "add") {
    const csrf = document.body.dataset.csrf;
    await register("/passkey/add/start", "/passkey/add/finish", {}, csrf);
    say("Passkey added.");
  }
}

if (form) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    say("Waiting for your authenticator.");
    run().catch(() => say("That did not work."));
  });
}
