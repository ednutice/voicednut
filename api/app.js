require('dotenv').config();
require('colors');

const express = require('express');
const ExpressWs = require('express-ws');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const { EnhancedGptService } = require('./routes/gpt');
const { StreamService } = require('./routes/stream');
const { TranscriptionService } = require('./routes/transcription');
const { TextToSpeechService } = require('./routes/tts');
const { recordingService } = require('./routes/recording');
const { EnhancedSmsService } = require('./routes/sms.js');
const Database = require('./db/db');
const { webhookService } = require('./routes/status');
const DynamicFunctionEngine = require('./functions/DynamicFunctionEngine');
const config = require('./config');
const { AwsConnectAdapter, AwsTtsAdapter, VonageVoiceAdapter } = require('./adapters');
const { v4: uuidv4 } = require('uuid');

const twilio = require('twilio');
const VoiceResponse = twilio.twiml.VoiceResponse;

// Console helpers with clean emoji prefixes (idempotent, minimal noise)
if (!console.__emojiWrapped) {
  const baseLog = console.log.bind(console);
  const baseWarn = console.warn.bind(console);
  const baseError = console.error.bind(console);
  console.log = (...args) => baseLog('📘', ...args);
  console.warn = (...args) => baseWarn('⚠️', ...args);
  console.error = (...args) => baseError('❌', ...args);
  console.__emojiWrapped = true;
}

const HMAC_HEADER_TIMESTAMP = 'x-api-timestamp';
const HMAC_HEADER_SIGNATURE = 'x-api-signature';
const HMAC_BYPASS_PATH_PREFIXES = ['/webhook/', '/incoming', '/aws/transcripts', '/connection', '/vonage/stream', '/aws/stream'];

function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => (item === undefined ? 'null' : stableStringify(item)));
    return `[${items.join(',')}]`;
  }
  const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort();
  const entries = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${entries.join(',')}}`;
}

function normalizeBodyForSignature(req) {
  const method = String(req.method || 'GET').toUpperCase();
  if (['GET', 'HEAD'].includes(method)) {
    return '';
  }
  const contentLength = Number(req.headers['content-length'] || 0);
  const hasBody = Number.isFinite(contentLength) && contentLength > 0;
  if (!req.body || Object.keys(req.body).length === 0) {
    return hasBody ? stableStringify(req.body || {}) : '';
  }
  return stableStringify(req.body);
}

function buildHmacPayload(req, timestamp) {
  const method = String(req.method || 'GET').toUpperCase();
  const path = req.originalUrl || req.url || '/';
  const body = normalizeBodyForSignature(req);
  return `${timestamp}.${method}.${path}.${body}`;
}

function clearDigitTimeout(callSid) {
  const timer = digitTimeouts.get(callSid);
  if (timer) {
    clearTimeout(timer);
    digitTimeouts.delete(callSid);
  }
}

function scheduleDigitTimeout(callSid, gptService = null, interactionCount = 0) {
  const exp = digitCollectionManager.expectations.get(callSid);
  if (!exp || !exp.timeout_s) return;

  clearDigitTimeout(callSid);

  const timer = setTimeout(async () => {
    const current = digitCollectionManager.expectations.get(callSid);
    if (!current) return;

    current.retries = (current.retries || 0) + 1;
    digitCollectionManager.expectations.set(callSid, current);

    const expectedText = `${current.min_digits || ''}${current.max_digits ? `-${current.max_digits}` : ''}`.replace(/-$/, '');
    const expectedLabel = expectedText ? `${expectedText} digit code` : 'the code';
    const prompt = current.retries > current.max_retries
      ? 'I could not verify the code. I will connect you to a specialist now.'
      : `I didn’t catch that. Please re-enter the ${expectedLabel} using your keypad.`;

    const personalityInfo = gptService?.personalityEngine?.getCurrentPersonality();
    const reply = {
      partialResponseIndex: null,
      partialResponse: prompt,
      personalityInfo,
      adaptationHistory: gptService?.personalityChanges?.slice(-3) || []
    };

    if (gptService) {
      gptService.emit('gptreply', reply, interactionCount);
      try {
        gptService.updateUserContext('digit_timeout', 'system', `Digit timeout retry ${current.retries}/${current.max_retries}`);
      } catch (_) {}
    }

    webhookService.addLiveEvent(callSid, `⏳ Awaiting digits retry ${current.retries}/${current.max_retries}`, { force: true });

    if (current.retries > current.max_retries) {
      digitCollectionManager.expectations.delete(callSid);
      clearDigitTimeout(callSid);
      await db.updateCallState(callSid, 'route_requested', { reason: 'digit_collection_timeout', via: 'auto' }).catch(() => {});
      return;
    }

    scheduleDigitTimeout(callSid, gptService, interactionCount + 1);
  }, (exp.timeout_s || 20) * 1000);

  digitTimeouts.set(callSid, timer);
}

function shouldBypassHmac(req) {
  const path = req.path || '';
  if (!path) return false;
  if (path.startsWith('/webhook/')) return true;
  return HMAC_BYPASS_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

function verifyHmacSignature(req) {
  const secret = config.apiAuth?.hmacSecret;
  if (!secret) {
    return { ok: true, skipped: true, reason: 'missing_secret' };
  }

  const timestampHeader = req.headers[HMAC_HEADER_TIMESTAMP];
  const signatureHeader = req.headers[HMAC_HEADER_SIGNATURE];

  if (!timestampHeader || !signatureHeader) {
    return { ok: false, reason: 'missing_headers' };
  }

  const timestamp = Number(timestampHeader);
  if (!Number.isFinite(timestamp)) {
    return { ok: false, reason: 'invalid_timestamp' };
  }

  const maxSkewMs = Number(config.apiAuth?.maxSkewMs || 300000);
  const now = Date.now();
  if (Math.abs(now - timestamp) > maxSkewMs) {
    return { ok: false, reason: 'timestamp_out_of_range' };
  }

  const payload = buildHmacPayload(req, String(timestampHeader));
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');

  try {
    const expectedBuf = Buffer.from(expected, 'hex');
    const providedBuf = Buffer.from(String(signatureHeader), 'hex');
    if (expectedBuf.length !== providedBuf.length) {
      return { ok: false, reason: 'invalid_signature' };
    }
    if (!crypto.timingSafeEqual(expectedBuf, providedBuf)) {
      return { ok: false, reason: 'invalid_signature' };
    }
  } catch (error) {
    return { ok: false, reason: 'invalid_signature' };
  }

  return { ok: true };
}

function getTwilioWebhookUrl(req) {
  if (!config.server?.hostname) {
    return null;
  }
  return `https://${config.server.hostname}${req.originalUrl}`;
}

function validateTwilioRequest(req) {
  const signature = req.headers['x-twilio-signature'];
  const authToken = config.twilio.authToken;
  const url = getTwilioWebhookUrl(req);
  if (!signature || !authToken || !url) {
    return false;
  }
  return twilio.validateRequest(authToken, signature, url, req.body);
}

function warnOnInvalidTwilioSignature(req, label = '') {
  const valid = validateTwilioRequest(req);
  if (!valid) {
    const path = label || req.originalUrl || req.path || 'unknown';
    console.warn(`⚠️ Twilio signature invalid for ${path}`);
  }
  return valid;
}

const app = express();
ExpressWs(app);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const apiLimiter = rateLimit({
  windowMs: config.server?.rateLimit?.windowMs || 60000,
  max: config.server?.rateLimit?.max || 300,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use((req, res, next) => {
  if (shouldBypassHmac(req)) {
    return next();
  }

  const verification = verifyHmacSignature(req);
  if (!verification.ok) {
    console.warn(`⚠️ Rejected request due to invalid HMAC (${verification.reason}) ${req.method} ${req.originalUrl}`);
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  return next();
});

app.use((req, res, next) => {
  if (shouldBypassHmac(req)) {
    return next();
  }
  return apiLimiter(req, res, next);
});

const PORT = config.server?.port || 3000;

// Enhanced call configurations with function context
const callConfigurations = new Map();
const activeCalls = new Map();
const callFunctionSystems = new Map(); // Store generated functions per call
const digitTimeouts = new Map();

let db;
const functionEngine = new DynamicFunctionEngine();
const smsService = new EnhancedSmsService();

// Lightweight digit collection manager for keypad/spoken entries
const digitCollectionManager = {
  expectations: new Map(), // callSid -> expectation
  setExpectation(callSid, params = {}) {
    this.expectations.set(callSid, {
      profile: params.profile || 'generic',
      min_digits: params.min_digits || 1,
      max_digits: params.max_digits || params.min_digits || 6,
      timeout_s: params.timeout_s || 20,
      max_retries: params.max_retries || 2,
      menu_options: params.menu_options || [],
      confirmation_style: params.confirmation_style || 'none',
      allow_spoken_fallback: params.allow_spoken_fallback !== false,
      mask_for_gpt: params.mask_for_gpt !== false,
      speak_confirmation: params.speak_confirmation || false,
      retries: 0,
      buffer: '',
      collected: [],
      last_masked: null
    });
  },
  recordDigits(callSid, digits = '') {
    if (!digits) return { accepted: false, reason: 'empty' };
    const exp = this.expectations.get(callSid);
    if (!exp) return { accepted: false, reason: 'no_expectation' };
    const result = { profile: exp.profile, mask_for_gpt: exp.mask_for_gpt };

    if (exp.profile === 'menu' && exp.menu_options.length) {
      const hit = exp.menu_options.find((o) => String(o.digit) === String(digits));
      if (hit) {
        result.digits = String(digits);
        result.len = result.digits.length;
        result.masked = result.digits;
        result.route = hit.route || hit.label || `menu_${digits}`;
        result.accepted = true;
      } else {
        result.accepted = false;
        result.reason = 'invalid_menu_option';
      }
      exp.collected.push(result.digits || digits);
      exp.last_masked = result.masked || result.digits;
      this.expectations.set(callSid, exp);
      return result;
    }

    exp.buffer = `${exp.buffer || ''}${String(digits)}`;
    const len = exp.buffer.length;
    const inRange = len >= exp.min_digits && len <= exp.max_digits;
    const tooLong = len > exp.max_digits;
    const masked = len <= 4 ? exp.buffer : `${'*'.repeat(Math.max(0, len - 4))}${exp.buffer.slice(-4)}`;

    Object.assign(result, {
      digits: exp.buffer,
      len,
      masked,
      accepted: inRange && !tooLong
    });

    if (tooLong) {
      result.accepted = false;
      result.reason = 'too_long';
      exp.buffer = '';
    } else if (!result.accepted) {
      result.reason = 'incomplete';
    }

    exp.collected.push(result.digits);
    exp.last_masked = masked;

    if (!result.accepted && result.reason !== 'incomplete') {
      exp.retries += 1;
      result.retries = exp.retries;
      if (exp.retries > exp.max_retries) {
        result.fallback = true;
      }
    } else {
      // reset buffer after successful collection
      exp.buffer = '';
    }

    this.expectations.set(callSid, exp);
    return result;
  }
};

async function handleCollectionResult(callSid, collection, gptService = null, interactionCount = 0) {
  if (!collection) return;
  const expectation = digitCollectionManager.expectations.get(callSid);
  const expectedText = expectation ? `${expectation.min_digits || ''}${expectation.max_digits ? `-${expectation.max_digits}` : ''}`.replace(/-$/, '') : '';
  const expectedLabel = expectedText ? `${expectedText} digit code` : 'the code';
  const payload = {
    profile: collection.profile,
    raw_digits: collection.digits,
    masked: collection.masked,
    len: collection.len,
    route: collection.route || null,
    accepted: !!collection.accepted,
    retries: collection.retries || 0,
    fallback: !!collection.fallback,
    reason: collection.reason || null
  };

  try {
    await db.updateCallState(callSid, 'digits_collected', {
      ...payload,
      masked_last4: collection.masked
    });
  } catch (err) {
    console.error('Error logging digits_collected:', err);
  }

  const personalityInfo = gptService?.personalityEngine?.getCurrentPersonality();
  const emitReply = (text) => {
    if (!gptService || !text) return;
    const reply = {
      partialResponseIndex: null,
      partialResponse: text,
      personalityInfo,
      adaptationHistory: gptService.personalityChanges?.slice(-3) || []
    };
    gptService.emit('gptreply', reply, interactionCount);
    try {
      gptService.updateUserContext('system', 'system', `Digit handling note: ${text}`);
    } catch (_) {}
  };

  if (collection.accepted) {
    clearDigitTimeout(callSid);
    digitCollectionManager.expectations.delete(callSid);
    switch (collection.profile) {
      case 'menu':
      case 'extension':
        if (collection.route) {
          webhookService.addLiveEvent(callSid, `➡️ Routing via menu: ${collection.route}`, { force: true });
          await db.updateCallState(callSid, 'route_requested', { reason: collection.route, via: 'menu' }).catch(() => {});
        }
        break;
      case 'account':
      case 'zip':
      case 'verification':
        webhookService.addLiveEvent(callSid, `✅ Digits captured (${collection.profile})`, { force: true });
        await db.updateCallState(callSid, 'identity_confirmed', {
          method: 'digits',
          note: `${collection.profile} digits confirmed (masked)`,
          masked: collection.masked
        }).catch(() => {});
        break;
      case 'amount': {
        const amountCents = Number(collection.digits);
        const dollars = (amountCents / 100).toFixed(2);
        webhookService.addLiveEvent(callSid, `💵 Amount entered: $${dollars}`, { force: true });
        await db.updateCallState(callSid, 'amount_captured', {
          amount_cents: amountCents,
          amount_display: `$${dollars}`
        }).catch(() => {});
        break;
      }
      case 'survey':
        webhookService.addLiveEvent(callSid, `📝 Survey response: ${collection.digits}`, { force: true });
        await db.updateCallState(callSid, 'survey_response', { rating: collection.digits }).catch(() => {});
        break;
      case 'callback_confirm':
        webhookService.addLiveEvent(callSid, `📞 Callback number confirmed (ending ${collection.masked.slice(-4)})`, { force: true });
        await db.updateCallState(callSid, 'callback_confirmed', {
          masked_last4: collection.masked,
          raw_digits: collection.digits
        }).catch(() => {});
        break;
      default:
        webhookService.addLiveEvent(callSid, `🔢 Digits captured (${collection.len})`, { force: true });
    }
    emitReply('Thanks, I received your code. One moment while I continue.');
  } else {
    webhookService.addLiveEvent(callSid, `⚠️ Invalid digits (${collection.len}); retry ${collection.retries}/${digitCollectionManager.expectations.get(callSid)?.max_retries || 0}`, { force: true });
    if (collection.fallback) {
      webhookService.addLiveEvent(callSid, `⏳ No valid digits; consider fallback/transfer`, { force: true });
      digitCollectionManager.expectations.delete(callSid);
      clearDigitTimeout(callSid);
      emitReply('I could not verify the code. I will connect you to a specialist now.');
      await db.updateCallState(callSid, 'route_requested', { reason: 'digit_collection_failed', via: 'auto' }).catch(() => {});
    } else {
      const prompts = [
        `That did not go through. Please re-enter the ${expectedLabel} using your keypad.`,
        `I could not read that. Enter the ${expectedLabel} again on your keypad, please.`,
        `Let’s try once more—type the ${expectedLabel} on your keypad now.`
      ];
      const prompt = prompts[Math.floor(Math.random() * prompts.length)];
      emitReply(prompt);
      scheduleDigitTimeout(callSid, gptService, interactionCount + 1);
    }
  }

  // Live console summary note for ops visibility
  const summary = collection.accepted
    ? collection.route
      ? `✅ Digits accepted • routed: ${collection.route}`
      : `✅ Digits accepted (${collection.len})`
    : collection.fallback
      ? `⚠️ Digits failed after retries`
      : `⚠️ Invalid digits (${collection.len}); retry ${collection.retries}/${digitCollectionManager.expectations.get(callSid)?.max_retries || 0}`;
  webhookService.addLiveEvent(callSid, summary, { force: true });
}

// Built-in telephony function templates to give GPT deterministic controls
const telephonyTools = [
  {
    type: 'function',
    function: {
      name: 'confirm_identity',
      description: 'Log that the caller has been identity-verified (do not include the code) and proceed to the next step.',
      parameters: {
        type: 'object',
        properties: {
          method: { type: 'string', enum: ['otp', 'pin', 'knowledge', 'other'], description: 'Verification method used.' },
          note: { type: 'string', description: 'Brief note about what was confirmed (no sensitive values).' }
        },
        required: ['method']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'route_to_agent',
      description: 'Escalate or transfer the call to a human/agent queue.',
      parameters: {
        type: 'object',
        properties: {
          reason: { type: 'string', description: 'Short reason for the transfer.' },
          priority: { type: 'string', enum: ['low', 'normal', 'high'], description: 'Transfer priority if applicable.' }
        },
        required: ['reason']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'collect_digits',
      description: 'Ask caller to enter digits on the keypad (e.g., OTP). Do not speak or repeat the digits.',
      parameters: {
        type: 'object',
        properties: {
          prompt: { type: 'string', description: 'Short instruction to the caller.' },
          min_digits: { type: 'integer', description: 'Minimum digits expected.', minimum: 1 },
          max_digits: { type: 'integer', description: 'Maximum digits expected.', minimum: 1 },
          profile: { type: 'string', enum: ['generic', 'verification', 'menu', 'account', 'extension', 'zip', 'amount', 'survey', 'callback_confirm'], description: 'Collection profile for downstream handling.' },
          menu_options: { type: 'array', description: 'For menu profile, array of {digit,label,route}.', items: { type: 'object', properties: { digit: { type: 'string' }, label: { type: 'string' }, route: { type: 'string' } } } },
          confirmation_style: { type: 'string', enum: ['none', 'last4', 'spoken_amount'], description: 'How to confirm receipt (masked, spoken summary only).' },
          timeout_s: { type: 'integer', description: 'Timeout in seconds before reprompt.', minimum: 3 },
          max_retries: { type: 'integer', description: 'Number of retries before fallback.', minimum: 0 },
          allow_spoken_fallback: { type: 'boolean', description: 'If true, allow spoken fallback after keypad timeout.' },
          mask_for_gpt: { type: 'boolean', description: 'If true (default), mask digits before sending to GPT/transcripts.' },
          speak_confirmation: { type: 'boolean', description: 'If true, GPT can verbally confirm receipt (without echoing digits).' }
        },
        required: ['prompt', 'min_digits', 'max_digits']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'play_disclosure',
      description: 'Play or read a required disclosure to the caller. Keep it concise.',
      parameters: {
        type: 'object',
        properties: {
          message: { type: 'string', description: 'Disclosure text to convey.' }
        },
        required: ['message']
      }
    }
  }
];

function buildTelephonyImplementations(callSid, gptService = null) {
  return {
    confirm_identity: async (args = {}) => {
      const payload = {
        status: 'acknowledged',
        method: args.method || 'unspecified',
        note: args.note || ''
      };
      try {
        await db.updateCallState(callSid, 'identity_confirmed', payload);
        webhookService.addLiveEvent(callSid, `✅ Identity confirmed (${payload.method})`, { force: true });
      } catch (err) {
        console.error('confirm_identity handler error:', err);
      }
      return payload;
    },
    route_to_agent: async (args = {}) => {
      const payload = {
        status: 'queued',
        reason: args.reason || 'unspecified',
        priority: args.priority || 'normal'
      };
      try {
        await db.updateCallState(callSid, 'route_requested', payload);
        webhookService.addLiveEvent(callSid, `📞 Routing to agent: ${payload.reason}`, { force: true });
      } catch (err) {
        console.error('route_to_agent handler error:', err);
      }
      return payload;
    },
    collect_digits: async (args = {}) => {
      const payload = {
        prompt: args.prompt || 'Please enter the digits now.',
        min_digits: args.min_digits || 1,
        max_digits: args.max_digits || args.min_digits || 6,
        profile: args.profile || 'generic',
        menu_options: args.menu_options || [],
        confirmation_style: args.confirmation_style || 'none',
        timeout_s: args.timeout_s || 20,
        max_retries: typeof args.max_retries === 'number' ? args.max_retries : 2,
        allow_spoken_fallback: args.allow_spoken_fallback !== false,
        mask_for_gpt: args.mask_for_gpt !== false,
        speak_confirmation: !!args.speak_confirmation
      };
      try {
        await db.updateCallState(callSid, 'digit_collection_requested', payload);
        webhookService.addLiveEvent(callSid, `🔢 Collect digits (${payload.profile}): ${payload.min_digits}-${payload.max_digits}`, { force: true });
        digitCollectionManager.setExpectation(callSid, payload);
        scheduleDigitTimeout(callSid, gptService, 0);
        if (gptService) {
          const instruction = `Please enter the ${payload.min_digits}-${payload.max_digits} digit code using your keypad. I will not repeat it back. ${payload.prompt}`;
          const reply = {
            partialResponseIndex: null,
            partialResponse: instruction,
            personalityInfo: gptService.personalityEngine.getCurrentPersonality(),
            adaptationHistory: gptService.personalityChanges?.slice(-3) || []
          };
          gptService.emit('gptreply', reply, 0);
          gptService.updateUserContext('digit_collection', 'system', `Collect digits requested (${payload.profile}): expecting ${payload.min_digits}-${payload.max_digits} digits. Prompt: ${payload.prompt}`);
        }
      } catch (err) {
        console.error('collect_digits handler error:', err);
      }
      return payload;
    },
    play_disclosure: async (args = {}) => {
      const payload = { message: args.message || '' };
      try {
        await db.updateCallState(callSid, 'disclosure_played', payload);
        webhookService.addLiveEvent(callSid, '📢 Disclosure played', { force: true });
      } catch (err) {
        console.error('play_disclosure handler error:', err);
      }
      return payload;
    }
  };
}

function applyTelephonyTools(gptService, callSid, baseTools = [], baseImpl = {}) {
  const combinedTools = [...baseTools, ...telephonyTools];
  const combinedImpl = { ...baseImpl, ...buildTelephonyImplementations(callSid, gptService) };
  gptService.setDynamicFunctions(combinedTools, combinedImpl);
}

function formatDurationForSms(seconds) {
  if (!seconds || Number.isNaN(seconds)) return '';
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (mins === 0) {
    return `${secs}s`;
  }
  return `${mins}m ${secs}s`;
}

function buildRecapSmsBody(call) {
  const name = call.customer_name ? ` with ${call.customer_name}` : '';
  const status = (call.status || call.twilio_status || 'completed').replace(/_/g, ' ');
  const duration = call.duration ? ` Duration: ${formatDurationForSms(call.duration)}.` : '';
  const rawSummary = (call.call_summary || '').replace(/\s+/g, ' ').trim();
  const summary = rawSummary ? rawSummary.slice(0, 180) : 'Call finished.';
  return `VoicedNut call recap${name}: ${summary} Status: ${status}.${duration}`;
}

const OTP_REGEX = /\b\d{4,8}\b/g;

function getOtpContext(text = '', callSid = null) {
  if (!text) {
    return {
      raw: text,
      maskedForGpt: text,
      maskedForLogs: text,
      otpDetected: false,
      codes: []
    };
  }
  const expectation = callSid ? digitCollectionManager.expectations.get(callSid) : null;
  const maskForGpt = expectation ? expectation.mask_for_gpt !== false : true;
  const codes = [...text.matchAll(OTP_REGEX)].map((m) => m[0]);
  const otpDetected = codes.length > 0;
  const masked = text.replace(OTP_REGEX, '******');
  return {
    raw: text,
    maskedForGpt: maskForGpt ? masked : text,
    maskedForLogs: masked,
    otpDetected,
    codes
  };
}

function maskOtpForExternal(text = '') {
  if (!text) return text;
  return text.replace(OTP_REGEX, '******');
}

function shouldCloseConversation(text = '') {
  const lower = String(text || '').toLowerCase();
  if (!lower) return false;
  return !!lower.match(/\b(thanks|thank you|bye|goodbye|appreciate|that.s all|that is all|have a good|bye bye)\b/);
}

const ADMIN_HEADER_NAME = 'x-admin-token';
const SUPPORTED_PROVIDERS = ['twilio', 'aws', 'vonage'];
let currentProvider = config.platform?.provider || 'twilio';
let storedProvider = currentProvider;
const awsContactMap = new Map();
const vonageCallMap = new Map();

let awsConnectAdapter = null;
let awsTtsAdapter = null;
let vonageVoiceAdapter = null;

const builtinPersonas = [
  {
    id: 'general',
    label: 'General',
    description: 'General voice call assistant',
    purposes: [{ id: 'general', label: 'General' }],
    default_purpose: 'general',
    default_emotion: 'neutral',
    default_urgency: 'normal',
    default_technical_level: 'general'
  }
];

function requireAdminToken(req, res, next) {
  const token = config.admin?.apiToken;
  if (!token) {
    return res.status(500).json({ success: false, error: 'Admin token not configured' });
  }
  const provided = req.headers[ADMIN_HEADER_NAME];
  if (!provided || provided !== token) {
    return res.status(403).json({ success: false, error: 'Admin token required' });
  }
  return next();
}

function getProviderReadiness() {
  return {
    twilio: !!(config.twilio.accountSid && config.twilio.authToken && config.twilio.fromNumber),
    aws: !!(config.aws.connect.instanceId && config.aws.connect.contactFlowId),
    vonage: !!(config.vonage.apiKey && config.vonage.apiSecret && config.vonage.applicationId && config.vonage.privateKey)
  };
}

function getAwsConnectAdapter() {
  if (!awsConnectAdapter) {
    awsConnectAdapter = new AwsConnectAdapter(config.aws);
  }
  return awsConnectAdapter;
}

function getVonageVoiceAdapter() {
  if (!vonageVoiceAdapter) {
    vonageVoiceAdapter = new VonageVoiceAdapter(config.vonage);
  }
  return vonageVoiceAdapter;
}

function getAwsTtsAdapter() {
  if (!awsTtsAdapter) {
    awsTtsAdapter = new AwsTtsAdapter(config.aws);
  }
  return awsTtsAdapter;
}

async function endCallForProvider(callSid) {
  const callConfig = callConfigurations.get(callSid);
  const provider = callConfig?.provider || currentProvider;

  if (provider === 'twilio') {
    const accountSid = config.twilio.accountSid;
    const authToken = config.twilio.authToken;
    if (!accountSid || !authToken) {
      throw new Error('Twilio credentials not configured');
    }
    const client = twilio(accountSid, authToken);
    await client.calls(callSid).update({ status: 'completed' });
    return;
  }

  if (provider === 'aws') {
    const contactId = callConfig?.provider_metadata?.contact_id;
    if (!contactId) {
      throw new Error('AWS contact id not available');
    }
    const awsAdapter = getAwsConnectAdapter();
    await awsAdapter.stopContact({ contactId });
    return;
  }

  if (provider === 'vonage') {
    const callUuid = callConfig?.provider_metadata?.vonage_uuid || callSid;
    const vonageAdapter = getVonageVoiceAdapter();
    await vonageAdapter.hangupCall(callUuid);
    return;
  }

  throw new Error(`Unsupported provider ${provider}`);
}

async function recordCallStatus(callSid, status, notificationType, extra = {}) {
  if (!callSid) return;
  await db.updateCallStatus(callSid, status, extra);
  const call = await db.getCall(callSid);
  if (call?.user_chat_id && notificationType) {
    await db.createEnhancedWebhookNotification(callSid, notificationType, call.user_chat_id);
  }
}

async function ensureAwsSession(callSid) {
  if (activeCalls.has(callSid)) {
    return activeCalls.get(callSid);
  }

  const callConfig = callConfigurations.get(callSid);
  const functionSystem = callFunctionSystems.get(callSid);
  if (!callConfig) {
    throw new Error(`Missing call configuration for ${callSid}`);
  }

  let gptService;
  if (functionSystem) {
    gptService = new EnhancedGptService(callConfig.prompt, callConfig.first_message);
    applyTelephonyTools(gptService, callSid, functionSystem.functions, functionSystem.implementations);
  } else {
    gptService = new EnhancedGptService(callConfig.prompt, callConfig.first_message);
    applyTelephonyTools(gptService, callSid);
  }

  gptService.setCallSid(callSid);
  gptService.setCustomerName(callConfig?.customer_name);
  gptService.setCallProfile(callConfig?.purpose || callConfig?.business_context?.purpose);
  const intentLine = `Call intent: ${callConfig?.template || 'general'} | purpose: ${callConfig?.purpose || 'general'} | business: ${callConfig?.business_context?.business_id || callConfig?.business_id || 'unspecified'}. Keep replies concise and on-task.`;
  gptService.setCallIntent(intentLine);

  const session = {
    startTime: new Date(),
    transcripts: [],
    gptService,
    callConfig,
    functionSystem,
    personalityChanges: [],
    interactionCount: 0
  };

  gptService.on('gptreply', async (gptReply, icount) => {
    const personalityInfo = gptReply.personalityInfo || {};

    webhookService.recordTranscriptTurn(callSid, 'agent', gptReply.partialResponse);
    webhookService.setLiveCallPhase(callSid, 'agent_responding').catch(() => {});

    try {
      await db.addTranscript({
        call_sid: callSid,
        speaker: 'ai',
        message: gptReply.partialResponse,
        interaction_count: icount,
        personality_used: personalityInfo.name || 'default',
        adaptation_data: JSON.stringify(gptReply.adaptationHistory || [])
      });

      await db.updateCallState(callSid, 'ai_responded', {
        message: gptReply.partialResponse,
        interaction_count: icount,
        personality: personalityInfo.name
      });
    } catch (dbError) {
      console.error('Database error adding AI transcript:', dbError);
    }

    try {
      const ttsAdapter = getAwsTtsAdapter();
      const { key } = await ttsAdapter.synthesizeToS3(gptReply.partialResponse);
      const contactId = callConfig?.provider_metadata?.contact_id;
      if (contactId) {
        const awsAdapter = getAwsConnectAdapter();
        await awsAdapter.enqueueAudioPlayback({
          contactId,
          audioKey: key
        });
        webhookService.setLiveCallPhase(callSid, 'agent_speaking').catch(() => {});
      }
    } catch (ttsError) {
      console.error('AWS TTS playback error:', ttsError);
    }
  });

  activeCalls.set(callSid, session);

  try {
    const firstMessage = callConfig.first_message || 'Hello!';
    const ttsAdapter = getAwsTtsAdapter();
    const { key } = await ttsAdapter.synthesizeToS3(firstMessage);
    const contactId = callConfig?.provider_metadata?.contact_id;
    if (contactId) {
      const awsAdapter = getAwsConnectAdapter();
      await awsAdapter.enqueueAudioPlayback({
        contactId,
        audioKey: key
      });
      webhookService.recordTranscriptTurn(callSid, 'agent', firstMessage);
      webhookService.setLiveCallPhase(callSid, 'agent_speaking').catch(() => {});
    }
  } catch (error) {
    console.error('AWS first message playback error:', error);
  }

  return session;
}

async function startServer() {
  try {
    console.log('🚀 Initializing Adaptive AI Call System...');

    // Initialize database first
    console.log('Initializing enhanced database...');
    db = new Database();
    await db.initialize();
    console.log('✅ Enhanced database initialized successfully');

    // Start webhook service after database is ready
    console.log('Starting enhanced webhook service...');
    webhookService.start(db);
    console.log('✅ Enhanced webhook service started');

    // Initialize function engine
    console.log('✅ Dynamic Function Engine ready');

    // Start HTTP server
    app.listen(PORT, () => {
      console.log(`✅ Enhanced Adaptive API server running on port ${PORT}`);
      console.log(`🎭 System ready - Personality Engine & Dynamic Functions active`);
      console.log(`📡 Enhanced webhook notifications enabled`);
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Enhanced WebSocket connection handler with dynamic functions
app.ws('/connection', (ws) => {
  console.log('New WebSocket connection established');
  
  try {
    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    let streamSid;
    let callSid;
    let callConfig = null;
    let callStartTime = null;
    let functionSystem = null;

    let gptService;
    let gptErrorCount = 0;
    const streamService = new StreamService(ws);
    const transcriptionService = new TranscriptionService();
    const ttsService = new TextToSpeechService({});
    // Prewarm TTS to reduce first-synthesis delay (silent)
    ttsService.generate({ partialResponseIndex: null, partialResponse: 'warming up' }, -1, { silent: true }).catch(() => {});
  
    let marks = [];
    let interactionCount = 0;
    let isInitialized = false;
  
    ws.on('message', async function message(data) {
      try {
        const msg = JSON.parse(data);
        const event = msg.event;
        
        if (event === 'start') {
          streamSid = msg.start.streamSid;
          callSid = msg.start.callSid;
          callStartTime = new Date();
          
          console.log(`Adaptive call started - SID: ${callSid}`);
          
          streamService.setStreamSid(streamSid);

          // Update database with enhanced tracking
          try {
            await db.updateCallStatus(callSid, 'started', {
              started_at: callStartTime.toISOString()
            });
            await db.updateCallState(callSid, 'stream_started', {
              stream_sid: streamSid,
              start_time: callStartTime.toISOString()
            });
            
            // Create webhook notification for stream start (internal tracking)
            const call = await db.getCall(callSid);
            if (call && call.user_chat_id) {
              await db.createEnhancedWebhookNotification(callSid, 'call_stream_started', call.user_chat_id);
            }
          } catch (dbError) {
            console.error('Database error on call start:', dbError);
          }

          // Get call configuration and function system
          callConfig = callConfigurations.get(callSid);
          functionSystem = callFunctionSystems.get(callSid);
          
          if (callConfig && functionSystem) {
            console.log(`Using adaptive configuration for ${functionSystem.context.industry} industry`);
            console.log(`Available functions: ${Object.keys(functionSystem.implementations).join(', ')}`);
            
            gptService = new EnhancedGptService(callConfig.prompt, callConfig.first_message);
            applyTelephonyTools(gptService, callSid, functionSystem.functions, functionSystem.implementations);
            
          } else {
            console.log(`Standard call detected: ${callSid}`);
            gptService = new EnhancedGptService();
            applyTelephonyTools(gptService, callSid);
          }
          
          gptService.setCallSid(callSid);
          gptService.setCustomerName(callConfig?.customer_name);
          gptService.setCallProfile(callConfig?.purpose || callConfig?.business_context?.purpose);
          const intentLine = `Call intent: ${callConfig?.template || 'general'} | purpose: ${callConfig?.purpose || 'general'} | business: ${callConfig?.business_context?.business_id || callConfig?.business_id || 'unspecified'}. Keep replies concise and on-task.`;
          gptService.setCallIntent(intentLine);

          let gptErrorCount = 0;

          // Set up GPT reply handler with personality tracking
          gptService.on('gptreply', async (gptReply, icount) => {
            const personalityInfo = gptReply.personalityInfo || {};
            console.log(`${personalityInfo.name || 'Default'} Personality: ${gptReply.partialResponse.substring(0, 50)}...`);
            webhookService.recordTranscriptTurn(callSid, 'agent', gptReply.partialResponse);
            webhookService.setLiveCallPhase(callSid, 'agent_responding').catch(() => {});
            
            // Save AI response to database with personality context
            try {
              await db.addTranscript({
                call_sid: callSid,
                speaker: 'ai',
                message: gptReply.partialResponse,
                interaction_count: icount,
                personality_used: personalityInfo.name || 'default',
                adaptation_data: JSON.stringify(gptReply.adaptationHistory || [])
              });
              
              await db.updateCallState(callSid, 'ai_responded', {
                message: gptReply.partialResponse,
                interaction_count: icount,
                personality: personalityInfo.name
              });
            } catch (dbError) {
              console.error('Database error adding AI transcript:', dbError);
            }
            
            ttsService.generate(gptReply, icount);
          });

          gptService.on('stall', (fillerText) => {
            webhookService.addLiveEvent(callSid, '⏳ One moment…', { force: true });
            try {
              ttsService.generate({ partialResponse: fillerText, personalityInfo: { name: 'filler' }, adaptationHistory: [] }, interactionCount);
            } catch (err) {
              console.error('Filler TTS error:', err);
            }
          });

          gptService.on('gpterror', async (err) => {
            gptErrorCount += 1;
            const message = err?.message || 'GPT error';
            webhookService.addLiveEvent(callSid, `⚠️ GPT error: ${message}`, { force: true });
            if (gptErrorCount >= 2) {
              const fallback = { partialResponseIndex: null, partialResponse: 'I am having trouble right now • I will reconnect you or end the call. Thank you.' };
              try {
                await db.addTranscript({
                  call_sid: callSid,
                  speaker: 'ai',
                  message: fallback.partialResponse,
                  interaction_count: interactionCount,
                  personality_used: 'fallback'
                });
              } catch (dbError) {
                console.error('Database error adding fallback transcript:', dbError);
              }
              try {
                await ttsService.generate(fallback, interactionCount);
              } catch (ttsErr) {
                console.error('Fallback TTS error:', ttsErr);
              }
            }
          });

          // Listen for personality changes
          gptService.on('personalityChanged', async (changeData) => {
            console.log(`Personality adapted: ${changeData.from} → ${changeData.to}`);
            console.log(`Reason: ${JSON.stringify(changeData.reason)}`.blue);
            
            // Log personality change to database
            try {
              await db.updateCallState(callSid, 'personality_changed', {
                from: changeData.from,
                to: changeData.to,
                reason: changeData.reason,
                interaction_count: interactionCount
              });
            } catch (dbError) {
              console.error('Database error logging personality change:', dbError);
            }
          });

          activeCalls.set(callSid, {
            startTime: callStartTime,
            transcripts: [],
            gptService,
            callConfig,
            functionSystem,
            personalityChanges: []
          });

          // Initialize call with recording
          try {
            await recordingService(ttsService, callSid);
            
            const firstMessage = callConfig ? 
              callConfig.first_message : 
              'Hello! what\'s your name and how can i help you today?';
            
            console.log(`First message (${functionSystem?.context.industry || 'default'}): ${firstMessage.substring(0, 50)}...`);
            
            try {
              await db.addTranscript({
                call_sid: callSid,
                speaker: 'ai',
                message: firstMessage,
                interaction_count: 0,
                personality_used: 'default'
              });
            } catch (dbError) {
              console.error('Database error adding initial transcript:', dbError);
            }
            
            await ttsService.generate({
              partialResponseIndex: null, 
              partialResponse: firstMessage
            }, 0);
            
            isInitialized = true;
            console.log('Adaptive call initialization complete');
            
          } catch (recordingError) {
            console.error('Recording service error:', recordingError);
            
            const firstMessage = callConfig ? 
              callConfig.first_message : 
              'Hello! what\'s your name and how can i help you today?';
            
            try {
              await db.addTranscript({
                call_sid: callSid,
                speaker: 'ai',
                message: firstMessage,
                interaction_count: 0,
                personality_used: 'default'
              });
            } catch (dbError) {
              console.error('Database error adding AI transcript:', dbError);
            }
            
            await ttsService.generate({
              partialResponseIndex: null, 
              partialResponse: firstMessage
            }, 0);
            
            isInitialized = true;
          }

          // Clean up old configurations
          const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
          for (const [sid, config] of callConfigurations.entries()) {
            if (new Date(config.created_at) < oneHourAgo) {
              callConfigurations.delete(sid);
              callFunctionSystems.delete(sid);
            }
          }

        } else if (event === 'media') {
          if (isInitialized && transcriptionService) {
            transcriptionService.send(msg.media.payload);
          }
        } else if (event === 'mark') {
          const label = msg.mark.name;
          marks = marks.filter(m => m !== msg.mark.name);
        } else if (event === 'dtmf') {
          const digits = msg?.dtmf?.digits || msg?.dtmf?.digit || '';
          if (digits) {
            webhookService.addLiveEvent(callSid, `🔢 Keypad: ${digits}`, { force: true });
            const collection = digitCollectionManager.recordDigits(callSid, digits);
            await handleCollectionResult(callSid, collection, gptService, interactionCount);
            if (collection.accepted && collection.route) {
              webhookService.addLiveEvent(callSid, `➡️ Routing via menu: ${collection.route}`, { force: true });
              await db.updateCallState(callSid, 'route_requested', { reason: collection.route, via: 'menu' }).catch(() => {});
            }
          }
        } else if (event === 'stop') {
          console.log(`Adaptive call stream ${streamSid} ended`.red);
          
          await handleCallEnd(callSid, callStartTime);
          
          // Clean up
          activeCalls.delete(callSid);
          if (callSid && callConfigurations.has(callSid)) {
            callConfigurations.delete(callSid);
            callFunctionSystems.delete(callSid);
            console.log(`Cleaned up adaptive configuration for call: ${callSid}`);
          }
        } else {
          console.log(`Unrecognized WS event for ${callSid || 'unknown'}: ${event || 'none'}`, msg);
        }
      } catch (messageError) {
        console.error('Error processing WebSocket message:', messageError);
      }
    });
  
    transcriptionService.on('utterance', async (text) => {
      if (text && text.trim().length > 0) {
        webhookService.setLiveCallPhase(callSid, 'user_speaking').catch(() => {});
      }
      if(marks.length > 0 && text?.length > 5) {
        console.log('Interruption detected, clearing stream'.red);
        ws.send(
          JSON.stringify({
            streamSid,
            event: 'clear',
          })
        );
      }
    });
  
    transcriptionService.on('transcription', async (text) => {
      if (!text || !gptService || !isInitialized) { 
        return; 
      }

      const otpContext = getOtpContext(text, callSid);
      console.log(`Customer: ${otpContext.maskedForLogs}`);

      // Save user transcript with enhanced context
      try {
        await db.addTranscript({
          call_sid: callSid,
          speaker: 'user',
          message: otpContext.raw,
          interaction_count: interactionCount
        });
        
        await db.updateCallState(callSid, 'user_spoke', {
          message: otpContext.raw,
          interaction_count: interactionCount,
          otp_detected: otpContext.otpDetected,
          last_collected_code: otpContext.codes?.slice(-1)[0] || null,
          collected_codes: otpContext.codes?.join(', ') || null
        });
      } catch (dbError) {
        console.error('Database error adding user transcript:', dbError);
      }
      
      webhookService.recordTranscriptTurn(callSid, 'user', otpContext.raw);
      if (otpContext.codes && otpContext.codes.length) {
        webhookService.addLiveEvent(callSid, `🔢 Code entered: ${otpContext.codes.join(', ')}`, { force: true });
        const collection = digitCollectionManager.recordDigits(callSid, otpContext.codes[otpContext.codes.length - 1]);
        await handleCollectionResult(callSid, collection, gptService, interactionCount);
      }

      if (!otpContext.maskedForGpt || !otpContext.maskedForGpt.trim()) {
        interactionCount += 1;
        return;
      }

      if (shouldCloseConversation(otpContext.maskedForGpt) && interactionCount >= 1) {
        gptService.updateUserContext('closing_hint', 'system', 'User indicated thanks/closing. Provide a brief, polite closing and end the call without asking more questions.');
        gptService.setPhase('closing');
      }
      
      // Process with adaptive personality and functions
      try {
        await gptService.completion(otpContext.maskedForGpt, interactionCount);
      } catch (gptError) {
        console.error('GPT completion error:', gptError);
        webhookService.addLiveEvent(callSid, '⚠️ GPT error, retrying', { force: true });
      }
      interactionCount += 1;
    });
    
    ttsService.on('speech', (responseIndex, audio, label, icount) => {
      webhookService.setLiveCallPhase(callSid, 'agent_speaking').catch(() => {});
      streamService.buffer(responseIndex, audio);
    });
  
    streamService.on('audiosent', (markLabel) => {
      marks.push(markLabel);
    });

    ws.on('close', () => {
      console.log(`WebSocket connection closed for adaptive call: ${callSid || 'unknown'}`);
      clearDigitTimeout(callSid);
    });

  } catch (err) {
    console.error('WebSocket handler error:', err);
  }
});

// Vonage websocket media handler (bidirectional PCM µ-law)
app.ws('/vonage/stream', (ws, req) => {
  try {
    const callSid = req.query?.callSid;
    if (!callSid) {
      ws.close();
      return;
    }

    let interactionCount = 0;
    const callConfig = callConfigurations.get(callSid);
    const functionSystem = callFunctionSystems.get(callSid);
    if (!callConfig) {
      ws.close();
      return;
    }

    const ttsService = new TextToSpeechService();
    ttsService.generate({ partialResponseIndex: null, partialResponse: 'warming up' }, -1, { silent: true }).catch(() => {});
    const transcriptionService = new TranscriptionService({
      encoding: 'mulaw',
      sampleRate: 8000
    });

    let gptService;
    if (functionSystem) {
      gptService = new EnhancedGptService(callConfig?.prompt, callConfig?.first_message);
      applyTelephonyTools(gptService, callSid, functionSystem.functions, functionSystem.implementations);
    } else {
      gptService = new EnhancedGptService(callConfig?.prompt, callConfig?.first_message);
      applyTelephonyTools(gptService, callSid);
    }

    gptService.setCallSid(callSid);
    gptService.setCustomerName(callConfig?.customer_name);
    gptService.setCallProfile(callConfig?.purpose || callConfig?.business_context?.purpose);
    const intentLine = `Call intent: ${callConfig?.template || 'general'} | purpose: ${callConfig?.purpose || 'general'} | business: ${callConfig?.business_context?.business_id || callConfig?.business_id || 'unspecified'}. Keep replies concise and on-task.`;
    gptService.setCallIntent(intentLine);

    activeCalls.set(callSid, {
      startTime: new Date(),
      transcripts: [],
      gptService,
      callConfig,
      functionSystem,
      personalityChanges: [],
      ws
    });

    gptService.on('gptreply', async (gptReply, icount) => {
      webhookService.recordTranscriptTurn(callSid, 'agent', gptReply.partialResponse);
      webhookService.setLiveCallPhase(callSid, 'agent_responding').catch(() => {});
      try {
        await db.addTranscript({
          call_sid: callSid,
          speaker: 'ai',
          message: gptReply.partialResponse,
          interaction_count: icount,
          personality_used: gptReply.personalityInfo?.name || 'default',
          adaptation_data: JSON.stringify(gptReply.adaptationHistory || [])
        });
        await db.updateCallState(callSid, 'ai_responded', {
          message: gptReply.partialResponse,
          interaction_count: icount
        });
      } catch (dbError) {
        console.error('Database error adding AI transcript:', dbError);
      }

      await ttsService.generate(gptReply, icount);
    });

    gptService.on('stall', (fillerText) => {
      webhookService.addLiveEvent(callSid, '⏳ One moment…', { force: true });
      try {
        ttsService.generate({ partialResponse: fillerText, personalityInfo: { name: 'filler' }, adaptationHistory: [] }, interactionCount);
      } catch (err) {
        console.error('Filler TTS error:', err);
      }
    });

    gptService.on('gpterror', async (err) => {
      gptErrorCount += 1;
      const message = err?.message || 'GPT error';
      webhookService.addLiveEvent(callSid, `⚠️ GPT error: ${message}`, { force: true });
      if (gptErrorCount >= 2) {
        const fallback = { partialResponseIndex: null, partialResponse: 'I am having trouble right now • I will reconnect you or end the call. Thank you.' };
        try {
          await ttsService.generate(fallback, interactionCount);
        } catch (ttsErr) {
          console.error('Fallback TTS error:', ttsErr);
        }
      }
    });

    ttsService.on('speech', (responseIndex, audio) => {
      webhookService.setLiveCallPhase(callSid, 'agent_speaking').catch(() => {});
      try {
        const buffer = Buffer.from(audio, 'base64');
        ws.send(buffer);
      } catch (error) {
        console.error('Vonage websocket send error:', error);
      }
    });

    transcriptionService.on('utterance', (text) => {
      if (text && text.trim().length > 0) {
        webhookService.setLiveCallPhase(callSid, 'user_speaking').catch(() => {});
      }
    });

    transcriptionService.on('transcription', async (text) => {
      if (!text) return;
      const otpContext = getOtpContext(text, callSid);
      try {
        await db.addTranscript({
          call_sid: callSid,
          speaker: 'user',
          message: otpContext.raw,
          interaction_count: interactionCount
        });
        await db.updateCallState(callSid, 'user_spoke', {
          message: otpContext.raw,
          interaction_count: interactionCount,
          otp_detected: otpContext.otpDetected,
          last_collected_code: otpContext.codes?.slice(-1)[0] || null,
          collected_codes: otpContext.codes?.join(', ') || null
        });
      } catch (dbError) {
        console.error('Database error adding user transcript:', dbError);
      }
      webhookService.recordTranscriptTurn(callSid, 'user', otpContext.raw);
      if (otpContext.codes && otpContext.codes.length) {
        webhookService.addLiveEvent(callSid, `🔢 Code entered: ${otpContext.codes.join(', ')}`, { force: true });
        const collection = digitCollectionManager.recordDigits(callSid, otpContext.codes[otpContext.codes.length - 1]);
        await handleCollectionResult(callSid, collection, gptService, interactionCount);
      }
      if (!otpContext.maskedForGpt || !otpContext.maskedForGpt.trim()) {
        interactionCount += 1;
        return;
      }
      if (shouldCloseConversation(otpContext.maskedForGpt) && interactionCount >= 1) {
        gptService.updateUserContext('closing_hint', 'system', 'User indicated thanks/closing. Provide a brief, polite closing and end the call without asking more questions.');
        gptService.setPhase('closing');
      }
      try {
        await gptService.completion(otpContext.maskedForGpt, interactionCount);
      } catch (gptError) {
        console.error('GPT completion error:', gptError);
        webhookService.addLiveEvent(callSid, '⚠️ GPT error, retrying', { force: true });
      }
      interactionCount += 1;
    });

    ws.on('message', (data) => {
      if (!data) return;
      if (Buffer.isBuffer(data)) {
        transcriptionService.sendBuffer(data);
        return;
      }
      const str = data.toString();
      try {
        const parsed = JSON.parse(str);
        if (parsed?.event === 'websocket:closed') {
          ws.close();
        }
      } catch {
        // ignore non-JSON
      }
    });

    ws.on('close', async () => {
      const session = activeCalls.get(callSid);
      if (session?.startTime) {
        await handleCallEnd(callSid, session.startTime);
      }
      activeCalls.delete(callSid);
      clearDigitTimeout(callSid);
    });

    // Send first message once stream is ready
    if (callConfig?.first_message) {
      ttsService.generate({ partialResponseIndex: null, partialResponse: callConfig.first_message }, 0);
      webhookService.recordTranscriptTurn(callSid, 'agent', callConfig.first_message);
    }
  } catch (error) {
    console.error('Vonage websocket error:', error);
    ws.close();
  }
});

// AWS websocket media handler (external audio forwarder -> Deepgram -> GPT -> Polly)
app.ws('/aws/stream', (ws, req) => {
  try {
    const callSid = req.query?.callSid;
    const contactId = req.query?.contactId;
    if (!callSid || !contactId) {
      ws.close();
      return;
    }

    const callConfig = callConfigurations.get(callSid);
    if (!callConfig) {
      ws.close();
      return;
    }

    if (!callConfig.provider_metadata) {
      callConfig.provider_metadata = {};
    }
    if (!callConfig.provider_metadata.contact_id) {
      callConfig.provider_metadata.contact_id = contactId;
    }
    awsContactMap.set(contactId, callSid);

    const sampleRate = Number(req.query?.sampleRate) || 16000;
    const encoding = req.query?.encoding || 'pcm';

    const transcriptionService = new TranscriptionService({
      encoding: encoding,
      sampleRate: sampleRate
    });

    const sessionPromise = ensureAwsSession(callSid);
    let interactionCount = 0;

    transcriptionService.on('utterance', (text) => {
      if (text && text.trim().length > 0) {
        webhookService.setLiveCallPhase(callSid, 'user_speaking').catch(() => {});
      }
    });

    transcriptionService.on('transcription', async (text) => {
      if (!text) return;
      const session = await sessionPromise;
      const otpContext = getOtpContext(text, callSid);
      try {
        await db.addTranscript({
          call_sid: callSid,
          speaker: 'user',
          message: otpContext.raw,
          interaction_count: interactionCount
        });
        await db.updateCallState(callSid, 'user_spoke', {
          message: otpContext.raw,
          interaction_count: interactionCount,
          otp_detected: otpContext.otpDetected,
          last_collected_code: otpContext.codes?.slice(-1)[0] || null,
          collected_codes: otpContext.codes?.join(', ') || null
        });
      } catch (dbError) {
        console.error('Database error adding user transcript:', dbError);
      }

      webhookService.recordTranscriptTurn(callSid, 'user', otpContext.raw);
      if (otpContext.codes && otpContext.codes.length) {
        webhookService.addLiveEvent(callSid, `🔢 Code entered: ${otpContext.codes.join(', ')}`, { force: true });
        const collection = digitCollectionManager.recordDigits(callSid, otpContext.codes[otpContext.codes.length - 1]);
        if (collection.accepted && collection.route) {
          webhookService.addLiveEvent(callSid, `➡️ Routing via menu: ${collection.route}`, { force: true });
          await db.updateCallState(callSid, 'route_requested', { reason: collection.route, via: 'menu' }).catch(() => {});
        }
        await handleCollectionResult(callSid, collection, session.gptService, interactionCount);
      }

      if (shouldCloseConversation(otpContext.maskedForGpt) && interactionCount >= 1) {
        session.gptService.updateUserContext('closing_hint', 'system', 'User indicated thanks/closing. Provide a brief, polite closing and end the call without asking more questions.');
        session.gptService.setPhase('closing');
      }

      try {
        await session.gptService.completion(otpContext.maskedForGpt, interactionCount);
      } catch (gptError) {
        console.error('GPT completion error:', gptError);
        webhookService.addLiveEvent(callSid, '⚠️ GPT error, retrying', { force: true });
      }
      interactionCount += 1;
    });

    ws.on('message', (data) => {
      if (!data) return;
      if (Buffer.isBuffer(data)) {
        transcriptionService.sendBuffer(data);
        return;
      }
      const str = data.toString();
      try {
        const payload = JSON.parse(str);
        if (payload?.audio) {
          transcriptionService.send(payload.audio);
        }
      } catch {
        // ignore non-JSON text frames
      }
    });

    ws.on('close', async () => {
      const session = activeCalls.get(callSid);
      if (session?.startTime) {
        await handleCallEnd(callSid, session.startTime);
      }
      activeCalls.delete(callSid);
    });

    recordCallStatus(callSid, 'in-progress', 'call_in_progress').catch(() => {});
  } catch (error) {
    console.error('AWS websocket error:', error);
    ws.close();
  }
});

// Enhanced call end handler with adaptation analytics
async function handleCallEnd(callSid, callStartTime) {
  try {
    const callEndTime = new Date();
    const duration = Math.round((callEndTime - callStartTime) / 1000);
    digitCollectionManager.expectations.delete(callSid);
    clearDigitTimeout(callSid);

    const transcripts = await db.getCallTranscripts(callSid);
    const maskedTranscripts = transcripts.map((entry) => ({
      ...entry,
      message: maskOtpForExternal(entry.message)
    }));
    const summary = generateCallSummary(transcripts, duration);
    
    // Get personality adaptation data
    const callSession = activeCalls.get(callSid);
    let adaptationAnalysis = {};
    
    if (callSession && callSession.gptService) {
      const conversationAnalysis = callSession.gptService.getConversationAnalysis();
      adaptationAnalysis = {
        personalityChanges: conversationAnalysis.personalityChanges,
        finalPersonality: conversationAnalysis.currentPersonality,
        adaptationEffectiveness: conversationAnalysis.personalityChanges / Math.max(conversationAnalysis.totalInteractions / 10, 1),
        businessContext: callSession.functionSystem?.context || {}
      };
    }
    
    await db.updateCallStatus(callSid, 'completed', {
      ended_at: callEndTime.toISOString(),
      duration: duration,
      call_summary: summary.summary,
      ai_analysis: JSON.stringify({...summary.analysis, adaptation: adaptationAnalysis})
    });

    await db.updateCallState(callSid, 'call_ended', {
      end_time: callEndTime.toISOString(),
      duration: duration,
      total_interactions: transcripts.length,
      personality_adaptations: adaptationAnalysis.personalityChanges || 0
    });

    const callDetails = await db.getCall(callSid);
    
    // Create enhanced webhook notification for completion
    if (callDetails && callDetails.user_chat_id) {
      await db.createEnhancedWebhookNotification(callSid, 'call_completed', callDetails.user_chat_id);
      
      // Schedule transcript notification with delay
      setTimeout(async () => {
        try {
          await db.createEnhancedWebhookNotification(callSid, 'call_transcript', callDetails.user_chat_id);
        } catch (transcriptError) {
          console.error('Error creating transcript notification:', transcriptError);
        }
      }, 2000);
    }

    console.log(`Enhanced adaptive call ${callSid} completed`);
    console.log(`Duration: ${duration}s | Messages: ${transcripts.length} | Adaptations: ${adaptationAnalysis.personalityChanges || 0}`);
    if (adaptationAnalysis.finalPersonality) {
      console.log(`Final personality: ${adaptationAnalysis.finalPersonality}`);
    }

    // Log service health
    await db.logServiceHealth('call_system', 'call_completed', {
      call_sid: callSid,
      duration: duration,
      interactions: transcripts.length,
      adaptations: adaptationAnalysis.personalityChanges || 0
    });

  } catch (error) {
    console.error('Error handling enhanced adaptive call end:', error);
    
    // Log error to service health
    try {
      await db.logServiceHealth('call_system', 'error', {
        operation: 'handle_call_end',
        call_sid: callSid,
        error: error.message
      });
    } catch (logError) {
      console.error('Failed to log service health error:', logError);
    }
  }
}

function generateCallSummary(transcripts, duration) {
  if (!transcripts || transcripts.length === 0) {
    return {
      summary: 'No conversation recorded',
      analysis: { total_messages: 0, user_messages: 0, ai_messages: 0 }
    };
  }

  const userMessages = transcripts.filter(t => t.speaker === 'user');
  const aiMessages = transcripts.filter(t => t.speaker === 'ai');
  
  const analysis = {
    total_messages: transcripts.length,
    user_messages: userMessages.length,
    ai_messages: aiMessages.length,
    duration_seconds: duration,
    conversation_turns: Math.max(userMessages.length, aiMessages.length)
  };

  const summary = `Enhanced adaptive call completed with ${transcripts.length} messages over ${Math.round(duration/60)} minutes. ` +
    `User spoke ${userMessages.length} times, AI responded ${aiMessages.length} times.`;

  return { summary, analysis };
}

// Incoming endpoint used by Twilio to connect the call to our websocket stream
app.post('/incoming', (req, res) => {
  try {
    warnOnInvalidTwilioSignature(req, '/incoming');
    if (!config.server?.hostname) {
      return res.status(500).send('Server hostname not configured');
    }
    const response = new VoiceResponse();
    const connect = response.connect();
    // Request both audio + DTMF events from Twilio Media Streams
    connect.stream({ url: `wss://${config.server.hostname}/connection`, track: 'both_tracks' });

    res.type('text/xml');
    res.end(response.toString());
  } catch (err) {
    console.log(err);
    res.status(500).send('Error');
  }
});

// Telegram callback webhook (live console actions)
app.post('/webhook/telegram', async (req, res) => {
  try {
    const update = req.body;
    res.status(200).send('OK');

    if (!update) return;
    const cb = update.callback_query;
    if (!cb?.data) return;

    const parts = cb.data.split(':');
    const prefix = parts[0];
    const action = prefix === 'lc' ? parts[1] : null;
    const callSid = prefix === 'lc' ? parts[2] : parts[1];
    if (!prefix || !callSid || (prefix === 'lc' && !action)) {
      webhookService.answerCallbackQuery(cb.id, 'Unsupported action').catch(() => {});
      return;
    }

    if (prefix === 'recap') {
      try {
        const callRecord = await db.getCall(callSid).catch(() => null);
        const chatId = cb.message?.chat?.id;
        if (callRecord?.user_chat_id && chatId && String(callRecord.user_chat_id) !== String(chatId)) {
          webhookService.answerCallbackQuery(cb.id, 'Not authorized for this call').catch(() => {});
          return;
        }

        const recapAction = parts[1];
        if (recapAction === 'skip') {
          webhookService.answerCallbackQuery(cb.id, 'Skipped').catch(() => {});
          return;
        }

        if (recapAction === 'sms') {
          if (!callRecord?.phone_number) {
            webhookService.answerCallbackQuery(cb.id, 'No phone number on record').catch(() => {});
            return;
          }

          const smsBody = buildRecapSmsBody(callRecord);
          try {
            await smsService.sendSMS(callRecord.phone_number, smsBody);
            webhookService.answerCallbackQuery(cb.id, 'Recap sent via SMS').catch(() => {});
            await webhookService.sendTelegramMessage(chatId, '📩 Recap sent via SMS to the customer.');
          } catch (smsError) {
            webhookService.answerCallbackQuery(cb.id, 'Failed to send SMS').catch(() => {});
            await webhookService.sendTelegramMessage(chatId, `❌ Failed to send recap SMS: ${smsError.message || smsError}`);
          }
          return;
        }
      } catch (error) {
        webhookService.answerCallbackQuery(cb.id, 'Error handling recap').catch(() => {});
      }
      return;
    }

    const callRecord = await db.getCall(callSid).catch(() => null);
    const chatId = cb.message?.chat?.id;
    if (callRecord?.user_chat_id && chatId && String(callRecord.user_chat_id) !== String(chatId)) {
      webhookService.answerCallbackQuery(cb.id, 'Not authorized for this call').catch(() => {});
      return;
    }

    if (prefix === 'tr') {
      webhookService.answerCallbackQuery(cb.id, 'Sending transcript...').catch(() => {});
      await webhookService.sendFullTranscript(callSid, chatId, cb.message?.message_id);
      return;
    }

    if (prefix === 'rca') {
      webhookService.answerCallbackQuery(cb.id, 'Fetching recording…').catch(() => {});
      try {
        await db.updateCallState(callSid, 'recording_access_requested', {
          at: new Date().toISOString()
        });
      } catch (stateError) {
        console.error('Failed to log recording access request:', stateError);
      }
      await webhookService.sendTelegramMessage(chatId, '🎧 Recording is being prepared. You will receive it here if available.');
      return;
    }

    if (action === 'rec') {
      webhookService.lockConsoleButtons(callSid, 'Recording…');
      try {
        await db.updateCallState(callSid, 'recording_requested', { at: new Date().toISOString() });
        webhookService.addLiveEvent(callSid, '⏺ Recording requested', { force: true });
        webhookService.answerCallbackQuery(cb.id, 'Recording toggled').catch(() => {});
      } catch (e) {
        webhookService.answerCallbackQuery(cb.id, `Failed: ${e.message}`.slice(0, 180)).catch(() => {});
      }
      setTimeout(() => webhookService.unlockConsoleButtons(callSid), 1200);
      return;
    }

    if (action === 'end') {
      webhookService.lockConsoleButtons(callSid, 'Ending…');
      try {
        await endCallForProvider(callSid);
        webhookService.setLiveCallPhase(callSid, 'ended').catch(() => {});
        webhookService.answerCallbackQuery(cb.id, 'Ending call...').catch(() => {});
      } catch (e) {
        webhookService.answerCallbackQuery(cb.id, `Failed: ${e.message}`.slice(0, 180)).catch(() => {});
        webhookService.unlockConsoleButtons(callSid);
      }
      setTimeout(() => webhookService.unlockConsoleButtons(callSid), 1500);
      return;
    }

    if (action === 'xfer') {
      if (!config.twilio.transferNumber) {
        webhookService.answerCallbackQuery(cb.id, 'Transfer not configured').catch(() => {});
        return;
      }
      webhookService.lockConsoleButtons(callSid, 'Transferring…');
      try {
        const transferCall = require('./functions/transferCall');
        await transferCall({ callSid });
        webhookService.markToolInvocation(callSid, 'transferCall').catch(() => {});
        webhookService.answerCallbackQuery(cb.id, 'Transferring...').catch(() => {});
      } catch (e) {
        webhookService.answerCallbackQuery(cb.id, `Transfer failed: ${e.message}`.slice(0, 180)).catch(() => {});
        webhookService.unlockConsoleButtons(callSid);
      }
      setTimeout(() => webhookService.unlockConsoleButtons(callSid), 2000);
      return;
    }
  } catch (error) {
    try { res.status(200).send('OK'); } catch {}
    console.error('Telegram webhook error:', error);
  }
});

app.get('/webhook/vonage/answer', (req, res) => {
  const callSid = req.query.callSid;
  const wsUrl = `wss://${config.server.hostname}/vonage/stream?callSid=${callSid}`;

  res.json([
    {
      action: 'connect',
      endpoint: [
        {
          type: 'websocket',
          uri: wsUrl,
          'content-type': 'audio/pcmu;rate=8000'
        }
      ]
    }
  ]);
});

app.post('/webhook/vonage/event', async (req, res) => {
  try {
    const { uuid, status, duration } = req.body || {};
    const callSid = req.query.callSid || (uuid ? vonageCallMap.get(uuid) : null) || uuid;

    const statusMap = {
      started: { status: 'initiated', notification: 'call_initiated' },
      ringing: { status: 'ringing', notification: 'call_ringing' },
      answered: { status: 'answered', notification: 'call_answered' },
      completed: { status: 'completed', notification: 'call_completed' },
      busy: { status: 'busy', notification: 'call_busy' },
      failed: { status: 'failed', notification: 'call_failed' },
      timeout: { status: 'no-answer', notification: 'call_no_answer' },
      cancelled: { status: 'canceled', notification: 'call_canceled' }
    };

    const mapped = statusMap[String(status || '').toLowerCase()];
    if (callSid && mapped) {
      await recordCallStatus(callSid, mapped.status, mapped.notification, {
        duration: duration ? parseInt(duration, 10) : undefined
      });
      if (mapped.status === 'completed') {
        const session = activeCalls.get(callSid);
        if (session?.startTime) {
          await handleCallEnd(callSid, session.startTime);
        }
        activeCalls.delete(callSid);
      }
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('Vonage webhook error:', error);
    res.status(200).send('OK');
  }
});

app.post('/webhook/aws/status', async (req, res) => {
  try {
    const { contactId, status, duration, callSid } = req.body || {};
    const resolvedCallSid = callSid || (contactId ? awsContactMap.get(contactId) : null);
    if (!resolvedCallSid) {
      return res.status(200).send('OK');
    }

    const normalized = String(status || '').toLowerCase();
    const map = {
      initiated: { status: 'initiated', notification: 'call_initiated' },
      connected: { status: 'answered', notification: 'call_answered' },
      ended: { status: 'completed', notification: 'call_completed' },
      failed: { status: 'failed', notification: 'call_failed' },
      no_answer: { status: 'no-answer', notification: 'call_no_answer' },
      busy: { status: 'busy', notification: 'call_busy' }
    };
    const mapped = map[normalized];
    if (mapped) {
      await recordCallStatus(resolvedCallSid, mapped.status, mapped.notification, {
        duration: duration ? parseInt(duration, 10) : undefined
      });
      if (mapped.status === 'completed') {
        const session = activeCalls.get(resolvedCallSid);
        if (session?.startTime) {
          await handleCallEnd(resolvedCallSid, session.startTime);
        }
        activeCalls.delete(resolvedCallSid);
      }
    }

    res.status(200).send('OK');
  } catch (error) {
    console.error('AWS status webhook error:', error);
    res.status(200).send('OK');
  }
});

app.post('/aws/transcripts', async (req, res) => {
  try {
    const { callSid, transcript, isPartial } = req.body || {};
    if (!callSid || !transcript) {
      return res.status(400).json({ success: false, error: 'callSid and transcript required' });
    }
    if (isPartial) {
      return res.status(200).json({ success: true });
    }
    const session = await ensureAwsSession(callSid);
    await db.addTranscript({
      call_sid: callSid,
      speaker: 'user',
      message: transcript,
      interaction_count: session.interactionCount
    });
    await db.updateCallState(callSid, 'user_spoke', {
      message: transcript,
      interaction_count: session.interactionCount
    });
    session.gptService.completion(transcript, session.interactionCount);
    session.interactionCount += 1;
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('AWS transcript webhook error:', error);
    res.status(500).json({ success: false, error: 'Failed to ingest transcript' });
  }
});

// Provider status/update endpoints (admin only)
app.get('/admin/provider', requireAdminToken, async (req, res) => {
  const readiness = getProviderReadiness();

  res.json({
    provider: currentProvider,
    stored_provider: storedProvider,
    supported_providers: SUPPORTED_PROVIDERS,
    twilio_ready: readiness.twilio,
    aws_ready: readiness.aws,
    vonage_ready: readiness.vonage
  });
});

app.post('/admin/provider', requireAdminToken, async (req, res) => {
  const { provider } = req.body || {};
  if (!provider || !SUPPORTED_PROVIDERS.includes(provider)) {
    return res.status(400).json({ success: false, error: 'Unsupported provider' });
  }
  const readiness = getProviderReadiness();
  if (!readiness[provider]) {
    return res.status(400).json({ success: false, error: `Provider ${provider} is not configured` });
  }
  const normalized = provider.toLowerCase();
  const changed = normalized !== currentProvider;
  currentProvider = normalized;
  storedProvider = normalized;
  return res.json({ success: true, provider: currentProvider, changed });
});

// Personas list for bot selection
app.get('/api/personas', async (req, res) => {
  res.json({
    success: true,
    builtin: builtinPersonas,
    custom: []
  });
});

// Call template endpoints for bot template management
app.get('/api/call-templates', async (req, res) => {
  try {
    const templates = await db.getCallTemplates();
    res.json({ success: true, templates });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch call templates' });
  }
});

app.get('/api/call-templates/:id', async (req, res) => {
  try {
    const templateId = Number(req.params.id);
    if (Number.isNaN(templateId)) {
      return res.status(400).json({ success: false, error: 'Invalid template id' });
    }
    const template = await db.getCallTemplateById(templateId);
    if (!template) {
      return res.status(404).json({ success: false, error: 'Template not found' });
    }
    res.json({ success: true, template });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch call template' });
  }
});

app.post('/api/call-templates', async (req, res) => {
  try {
    const { name, first_message } = req.body || {};
    if (!name || !first_message) {
      return res.status(400).json({ success: false, error: 'name and first_message are required' });
    }
    const id = await db.createCallTemplate(req.body);
    const template = await db.getCallTemplateById(id);
    res.status(201).json({ success: true, template });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to create call template' });
  }
});

app.put('/api/call-templates/:id', async (req, res) => {
  try {
    const templateId = Number(req.params.id);
    if (Number.isNaN(templateId)) {
      return res.status(400).json({ success: false, error: 'Invalid template id' });
    }
    const updated = await db.updateCallTemplate(templateId, req.body || {});
    if (!updated) {
      return res.status(404).json({ success: false, error: 'Template not found' });
    }
    const template = await db.getCallTemplateById(templateId);
    res.json({ success: true, template });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to update call template' });
  }
});

app.delete('/api/call-templates/:id', async (req, res) => {
  try {
    const templateId = Number(req.params.id);
    if (Number.isNaN(templateId)) {
      return res.status(400).json({ success: false, error: 'Invalid template id' });
    }
    const deleted = await db.deleteCallTemplate(templateId);
    if (!deleted) {
      return res.status(404).json({ success: false, error: 'Template not found' });
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to delete call template' });
  }
});

app.post('/api/call-templates/:id/clone', async (req, res) => {
  try {
    const templateId = Number(req.params.id);
    if (Number.isNaN(templateId)) {
      return res.status(400).json({ success: false, error: 'Invalid template id' });
    }
    const existing = await db.getCallTemplateById(templateId);
    if (!existing) {
      return res.status(404).json({ success: false, error: 'Template not found' });
    }
    const payload = {
      ...existing,
      name: req.body?.name || `${existing.name} Copy`
    };
    delete payload.id;
    const newId = await db.createCallTemplate(payload);
    const template = await db.getCallTemplateById(newId);
    res.status(201).json({ success: true, template });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to clone call template' });
  }
});

// Enhanced outbound call endpoint with dynamic function generation
app.post('/outbound-call', async (req, res) => {
  try {
    const {
      number,
      prompt,
      first_message,
      user_chat_id,
      customer_name,
      business_id,
      template,
      template_id,
      purpose,
      emotion,
      urgency,
      technical_level,
      voice_model
    } = req.body;

    if (!number || !prompt || !first_message) {
      return res.status(400).json({
        error: 'Missing required fields: number, prompt, and first_message are required'
      });
    }

    if (!number.match(/^\+[1-9]\d{1,14}$/)) {
      return res.status(400).json({
        error: 'Invalid phone number format. Use E.164 format (e.g., +1234567890)'
      });
    }

    if (!config.server?.hostname) {
      return res.status(500).json({
        error: 'Server hostname not configured'
      });
    }

    console.log('Generating adaptive function system for call...'.blue);
    
    // Generate dynamic functions based on the prompt
    const functionSystem = functionEngine.generateAdaptiveFunctionSystem(prompt, first_message);
    
    console.log(`Generated ${functionSystem.functions.length} functions for ${functionSystem.context.industry} industry`);

    let callId;
    let callStatus = 'queued';
    let providerMetadata = {};

    if (currentProvider === 'twilio') {
      const accountSid = config.twilio.accountSid;
      const authToken = config.twilio.authToken;
      const fromNumber = config.twilio.fromNumber;

      if (!accountSid || !authToken || !fromNumber) {
        return res.status(500).json({
          error: 'Twilio credentials not configured'
        });
      }

      const client = twilio(accountSid, authToken);
      const call = await client.calls.create({
        url: `https://${config.server.hostname}/incoming`,
        to: number,
        from: fromNumber,
        statusCallback: `https://${config.server.hostname}/webhook/call-status`,
        statusCallbackEvent: ['initiated', 'ringing', 'answered', 'completed', 'busy', 'no-answer', 'canceled', 'failed'],
        statusCallbackMethod: 'POST'
      });
      callId = call.sid;
      callStatus = call.status || 'queued';
    } else if (currentProvider === 'aws') {
      const awsAdapter = getAwsConnectAdapter();
      callId = uuidv4();
      const response = await awsAdapter.startOutboundCall({
        destinationPhoneNumber: number,
        clientToken: callId,
        attributes: {
          CALL_SID: callId,
          FIRST_MESSAGE: first_message
        }
      });
      providerMetadata = { contact_id: response.ContactId };
      if (response.ContactId) {
        awsContactMap.set(response.ContactId, callId);
      }
      callStatus = 'queued';
    } else if (currentProvider === 'vonage') {
      const vonageAdapter = getVonageVoiceAdapter();
      callId = uuidv4();
      const answerUrl = config.vonage.voice.answerUrl ||
        `https://${config.server.hostname}/webhook/vonage/answer?callSid=${callId}`;
      const eventUrl = config.vonage.voice.eventUrl ||
        `https://${config.server.hostname}/webhook/vonage/event?callSid=${callId}`;
      const response = await vonageAdapter.createOutboundCall({
        to: number,
        callSid: callId,
        answerUrl,
        eventUrl
      });
      const vonageUuid = response?.uuid;
      providerMetadata = { vonage_uuid: vonageUuid };
      if (vonageUuid) {
        vonageCallMap.set(vonageUuid, callId);
      }
      callStatus = response?.status || 'queued';
    } else {
      return res.status(400).json({ error: `Unsupported provider ${currentProvider}` });
    }

    const callConfig = {
      prompt: prompt,
      first_message: first_message,
      created_at: new Date().toISOString(),
      user_chat_id: user_chat_id,
      customer_name: customer_name || null,
      provider: currentProvider,
      provider_metadata: providerMetadata,
      business_context: functionSystem.context,
      function_count: functionSystem.functions.length,
      purpose: purpose || null,
      business_id: business_id || null,
      template: template || null,
      template_id: template_id || null,
      emotion: emotion || null,
      urgency: urgency || null,
      technical_level: technical_level || null,
      voice_model: voice_model || null,
      collection_profile: req.body?.collection_profile || null,
      collection_expected_length: req.body?.collection_expected_length || null,
      collection_menu_options: req.body?.collection_menu_options || [],
      collection_timeout_s: req.body?.collection_timeout_s || null,
      collection_max_retries: req.body?.collection_max_retries || null,
      collection_mask_for_gpt: req.body?.collection_mask_for_gpt,
      collection_speak_confirmation: req.body?.collection_speak_confirmation
    };
    
    callConfigurations.set(callId, callConfig);
    
    // Store the generated function system for this call
    callFunctionSystems.set(callId, functionSystem);

    // Save call to database with enhanced metadata
    try {
      await db.createCall({
        call_sid: callId,
        phone_number: number,
        prompt: prompt,
        first_message: first_message,
        user_chat_id: user_chat_id,
        business_context: JSON.stringify(functionSystem.context),
        generated_functions: JSON.stringify(functionSystem.functions.map(f => f.function.name))
      });
      await db.updateCallState(callId, 'call_created', {
        customer_name: customer_name || null,
        business_id: business_id || null,
        template: template || null,
        template_id: template_id || null,
        purpose: purpose || null,
        emotion: emotion || null,
        urgency: urgency || null,
        technical_level: technical_level || null,
        voice_model: voice_model || null,
        provider: currentProvider,
        provider_metadata: providerMetadata,
        collection_profile: req.body?.collection_profile || null,
        collection_expected_length: req.body?.collection_expected_length || null,
        collection_menu_options: req.body?.collection_menu_options || [],
        collection_timeout_s: req.body?.collection_timeout_s || null,
        collection_max_retries: req.body?.collection_max_retries || null,
        collection_mask_for_gpt: req.body?.collection_mask_for_gpt,
        collection_speak_confirmation: req.body?.collection_speak_confirmation
      });

      // Create initial webhook notification
      if (user_chat_id) {
        await db.createEnhancedWebhookNotification(callId, 'call_initiated', user_chat_id);
      }

      console.log(`Enhanced adaptive call created: ${callId} to ${number}`);
      console.log(`Business context: ${functionSystem.context.industry} - ${functionSystem.context.businessType}`);
      
    } catch (dbError) {
      console.error('Database error:', dbError);
    }

    res.json({
      success: true,
      call_sid: callId,
      to: number,
      status: callStatus,
      provider: currentProvider,
      business_context: functionSystem.context,
      generated_functions: functionSystem.functions.length,
      function_types: functionSystem.functions.map(f => f.function.name),
      enhanced_webhooks: true
    });

  } catch (error) {
    console.error('Error creating enhanced adaptive outbound call:', error);
    res.status(500).json({
      error: 'Failed to create outbound call',
      details: error.message
    });
  }
});

// Enhanced webhook endpoint for call status updates

app.post('/webhook/call-status', async (req, res) => {
  try {
    const { 
      CallSid, 
      CallStatus, 
      Duration, 
      From, 
      To, 
      CallDuration,
      AnsweredBy,
      ErrorCode,
      ErrorMessage,
      DialCallDuration // This is key for detecting actual answer vs no-answer
    } = req.body;
    warnOnInvalidTwilioSignature(req, '/webhook/call-status');

    console.log(`Fixed Webhook: Call ${CallSid} status: ${CallStatus}`.blue);
    console.log(`Debug Info:`);
    console.log(`Duration: ${Duration || 'N/A'}`);
    console.log(`CallDuration: ${CallDuration || 'N/A'}`);
    console.log(`DialCallDuration: ${DialCallDuration || 'N/A'}`);
    console.log(`AnsweredBy: ${AnsweredBy || 'N/A'}`);
    
    // Get call details from database
    const call = await db.getCall(CallSid);
    if (!call) {
      console.warn(`Webhook received for unknown call: ${CallSid}`);
      res.status(200).send('OK');
      return;
    }

    // Enhanced logic for determining actual call outcome
    let notificationType = null;
    const rawStatus = String(CallStatus || '').toLowerCase();
    let actualStatus = rawStatus || 'unknown';
    
    // Special handling for "completed" status - check if it was actually answered
    if (actualStatus === 'completed') {
      const duration = parseInt(Duration || CallDuration || DialCallDuration || 0);
      const priorStatus = String(call.status || '').toLowerCase();
      const hasAnswerEvidence =
        !!call.started_at ||
        ['answered', 'in-progress', 'completed'].includes(priorStatus);
      
      console.log(`Analyzing completed call: Duration = ${duration}s`);
      
      // If call completed but duration is very short (< 3 seconds), it's likely no-answer
      // unless we already recorded an answer signal
      if ((duration === 0 || duration < 3) && !hasAnswerEvidence) {
        console.log(`Short duration detected (${duration}s) - treating as no-answer`.red);
        actualStatus = 'no-answer';
        notificationType = 'call_no_answer';
      } else if (AnsweredBy === 'machine_start' && duration < 10 && !hasAnswerEvidence) {
        console.log(`Voicemail detected with short duration - treating as no-answer`.red);
        actualStatus = 'no-answer';
        notificationType = 'call_no_answer';
      } else {
        console.log(`Valid call duration (${duration}s) - confirmed answered`);
        actualStatus = 'completed';
        notificationType = 'call_completed';
      }
    } else {
      // Handle other statuses normally
      switch (actualStatus) {
        case 'queued':
        case 'initiated':
          notificationType = 'call_initiated';
          break;
        case 'ringing':
          notificationType = 'call_ringing';
          break;
        case 'in-progress':
          notificationType = 'call_in_progress';
          break;
        case 'answered':
          notificationType = 'call_answered';
          break;
        case 'busy':
          notificationType = 'call_busy';
          break;
        case 'no-answer':
          notificationType = 'call_no_answer';
          break;
        case 'failed':
          notificationType = 'call_failed';
          break;
        case 'canceled':
          notificationType = 'call_canceled';
          break;
        default:
          console.warn(`Unknown call status: ${CallStatus}`);
          notificationType = `call_${actualStatus}`;
      }
    }

    console.log(`Final determination: ${CallStatus} → ${actualStatus} → ${notificationType}`);

    // Update call status in database with enhanced data
    const updateData = {
      duration: parseInt(Duration || CallDuration || DialCallDuration || 0),
      twilio_status: CallStatus,
      answered_by: AnsweredBy,
      error_code: ErrorCode,
      error_message: ErrorMessage
    };

    if (actualStatus === 'ringing') {
      try {
        await db.updateCallState(CallSid, 'ringing', { at: new Date().toISOString() });
      } catch (stateError) {
        console.error('Failed to record ringing state:', stateError);
      }
    }

    // Calculate ring duration for no-answer cases
    if (actualStatus === 'no-answer' && call.created_at) {
      let ringStart = null;
      try {
        const ringState = await db.getLatestCallState(CallSid, 'ringing');
        ringStart = ringState?.at || ringState?.timestamp || null;
      } catch (stateError) {
        console.error('Failed to load ringing state:', stateError);
      }

      const now = new Date();
      const callStart = new Date(call.created_at);
      const ringStartTime = ringStart ? new Date(ringStart) : callStart;
      const ringDuration = Math.round((now - ringStartTime) / 1000);
      updateData.ring_duration = ringDuration;
      if (!updateData.duration || updateData.duration < ringDuration) {
        updateData.duration = ringDuration;
      }
      console.log(`Calculated ring duration: ${ringDuration}s`);
    }

    // Set timestamps based on actual status (not original CallStatus)
    if (['in-progress', 'answered'].includes(actualStatus) && !call.started_at) {
      updateData.started_at = new Date().toISOString();
    } else if (['completed', 'no-answer', 'failed', 'busy', 'canceled'].includes(actualStatus) && !call.ended_at) {
      updateData.ended_at = new Date().toISOString();
    }

    await db.updateCallStatus(CallSid, actualStatus, updateData);

    // Create enhanced webhook notification with corrected status
    if (call.user_chat_id && notificationType) {
      try {
        await db.createEnhancedWebhookNotification(CallSid, notificationType, call.user_chat_id);
        console.log(`📨 Created corrected ${notificationType} notification for call ${CallSid}`);

        if (['completed', 'no-answer', 'failed', 'busy', 'canceled'].includes(actualStatus)) {
          await db.createEnhancedWebhookNotification(CallSid, 'call_recap', call.user_chat_id);
        }
        
        // Log the correction if we changed the status
        if (actualStatus !== CallStatus.toLowerCase()) {
          await db.logServiceHealth('webhook_system', 'status_corrected', {
            call_sid: CallSid,
            original_status: CallStatus,
            corrected_status: actualStatus,
            duration: updateData.duration,
            reason: 'Short duration analysis'
          });
        }
      } catch (notificationError) {
        console.error('Error creating enhanced webhook notification:', notificationError);
      }
    }
    
    // Log comprehensive status update
    console.log(`Fixed webhook processed: ${CallSid} -> ${CallStatus} (corrected to: ${actualStatus})`);
    if (updateData.duration) {
      const minutes = Math.floor(updateData.duration / 60);
      const seconds = updateData.duration % 60;
      console.log(`Call metrics: ${minutes}:${String(seconds).padStart(2, '0')} duration`);
    }

    // Log to service health with correction info
    await db.logServiceHealth('webhook_system', 'status_received', {
      call_sid: CallSid,
      original_status: CallStatus,
      final_status: actualStatus,
      duration: updateData.duration,
      answered_by: AnsweredBy,
      correction_applied: actualStatus !== CallStatus.toLowerCase()
    });
    
    res.status(200).send('OK');
    
  } catch (error) {
    console.error('Error processing fixed call status webhook:', error);
    
    // Log error to service health
    try {
      await db.logServiceHealth('webhook_system', 'error', {
        operation: 'process_webhook',
        error: error.message,
        call_sid: req.body.CallSid
      });
    } catch (logError) {
      console.error('Failed to log webhook error:', logError);
    }
    
    res.status(200).send('OK');
  }
});


// Enhanced API endpoints with adaptation analytics

// Get call details with enhanced personality and function analytics
app.get('/api/calls/:callSid', async (req, res) => {
  try {
    const { callSid } = req.params;
    
    const call = await db.getCall(callSid);
    if (!call) {
      return res.status(404).json({ error: 'Call not found' });
    }

    const transcripts = await db.getCallTranscripts(callSid);
    
    // Parse adaptation data
    let adaptationData = {};
    try {
      if (call.ai_analysis) {
        const analysis = JSON.parse(call.ai_analysis);
        adaptationData = analysis.adaptation || {};
      }
    } catch (e) {
      console.error('Error parsing adaptation data:', e);
    }

    // Get webhook notifications for this call
    const webhookNotifications = await new Promise((resolve, reject) => {
      db.db.all(
        `SELECT * FROM webhook_notifications WHERE call_sid = ? ORDER BY created_at DESC`,
        [callSid],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });
    
    res.json({
      call,
      transcripts: maskedTranscripts,
      transcript_count: maskedTranscripts.length,
      adaptation_analytics: adaptationData,
      business_context: call.business_context ? JSON.parse(call.business_context) : null,
      webhook_notifications: webhookNotifications,
      enhanced_features: true
    });
  } catch (error) {
    console.error('Error fetching enhanced adaptive call details:', error);
    res.status(500).json({ error: 'Failed to fetch call details' });
  }
});

// Enhanced call status endpoint with real-time metrics
app.get('/api/calls/:callSid/status', async (req, res) => {
  try {
    const { callSid } = req.params;
    
    const call = await db.getCall(callSid);
    if (!call) {
      return res.status(404).json({ error: 'Call not found' });
    }

    // Get recent call states for detailed progress tracking
    const recentStates = await new Promise((resolve, reject) => {
      db.db.all(
        `SELECT state, data, timestamp FROM call_states 
         WHERE call_sid = ? 
         ORDER BY timestamp DESC 
         LIMIT 10`,
        [callSid],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });

    // Get enhanced webhook notification status
    const notificationStatus = await new Promise((resolve, reject) => {
      db.db.all(
        `SELECT notification_type, status, created_at, sent_at, delivery_time_ms, error_message 
         FROM webhook_notifications 
         WHERE call_sid = ? 
         ORDER BY created_at DESC`,
        [callSid],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });

    // Calculate enhanced call timing metrics
    let timingMetrics = {};
    if (call.created_at) {
      const now = new Date();
      const created = new Date(call.created_at);
      timingMetrics.total_elapsed = Math.round((now - created) / 1000);
      
      if (call.started_at) {
        const started = new Date(call.started_at);
        timingMetrics.time_to_answer = Math.round((started - created) / 1000);
      }
      
      if (call.ended_at) {
        const ended = new Date(call.ended_at);
        timingMetrics.call_duration = call.duration || Math.round((ended - new Date(call.started_at || call.created_at)) / 1000);
      }

      // Calculate ring duration if available
      if (call.ring_duration) {
        timingMetrics.ring_duration = call.ring_duration;
      }
    }

    res.json({
      call: {
        ...call,
        timing_metrics: timingMetrics
      },
      recent_states: recentStates,
      notification_status: notificationStatus,
      webhook_service_status: webhookService.getCallStatusStats(),
      enhanced_tracking: true
    });
    
  } catch (error) {
    console.error('Error fetching enhanced call status:', error);
    res.status(500).json({ error: 'Failed to fetch call status' });
  }
});

// Manual notification trigger endpoint (for testing)
app.post('/api/calls/:callSid/notify', async (req, res) => {
  try {
    const { callSid } = req.params;
    const { status, user_chat_id } = req.body;
    
    if (!status || !user_chat_id) {
      return res.status(400).json({ 
        error: 'Both status and user_chat_id are required' 
      });
    }

    const call = await db.getCall(callSid);
    if (!call) {
      return res.status(404).json({ error: 'Call not found' });
    }

    // Send immediate enhanced notification
    const success = await webhookService.sendImmediateStatus(callSid, status, user_chat_id);
    
    if (success) {
      res.json({ 
        success: true, 
        message: `Enhanced manual notification sent: ${status}`,
        call_sid: callSid,
        enhanced: true
      });
    } else {
      res.status(500).json({ 
        success: false, 
        error: 'Failed to send enhanced notification' 
      });
    }
    
  } catch (error) {
    console.error('Error sending enhanced manual notification:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to send notification',
      details: error.message 
    });
  }
});

// Get enhanced adaptation analytics dashboard data
app.get('/api/analytics/adaptations', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const calls = await db.getCallsWithTranscripts(limit);
    
    const analyticsData = {
      total_calls: calls.length,
      calls_with_adaptations: 0,
      total_adaptations: 0,
      personality_usage: {},
      industry_breakdown: {},
      adaptation_triggers: {},
      enhanced_features: true
    };

    calls.forEach(call => {
      try {
        if (call.ai_analysis) {
          const analysis = JSON.parse(call.ai_analysis);
          if (analysis.adaptation && analysis.adaptation.personalityChanges > 0) {
            analyticsData.calls_with_adaptations++;
            analyticsData.total_adaptations += analysis.adaptation.personalityChanges;
            
            // Track final personality usage
            const finalPersonality = analysis.adaptation.finalPersonality;
            if (finalPersonality) {
              analyticsData.personality_usage[finalPersonality] = 
                (analyticsData.personality_usage[finalPersonality] || 0) + 1;
            }
            
            // Track industry usage
            const industry = analysis.adaptation.businessContext?.industry;
            if (industry) {
              analyticsData.industry_breakdown[industry] = 
                (analyticsData.industry_breakdown[industry] || 0) + 1;
            }
          }
        }
      } catch (e) {
        // Skip calls with invalid analysis data
      }
    });

    analyticsData.adaptation_rate = analyticsData.total_calls > 0 ? 
      (analyticsData.calls_with_adaptations / analyticsData.total_calls * 100).toFixed(1) : 0;
    
    analyticsData.avg_adaptations_per_call = analyticsData.calls_with_adaptations > 0 ? 
      (analyticsData.total_adaptations / analyticsData.calls_with_adaptations).toFixed(1) : 0;

    res.json(analyticsData);
  } catch (error) {
    console.error('Error fetching enhanced adaptation analytics:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Enhanced notification analytics endpoint
app.get('/api/analytics/notifications', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const hours = parseInt(req.query.hours) || 24;
    
    const notificationStats = await new Promise((resolve, reject) => {
      db.db.all(`
        SELECT 
          notification_type,
          status,
          COUNT(*) as count,
          AVG(CASE 
            WHEN sent_at IS NOT NULL AND created_at IS NOT NULL 
            THEN (julianday(sent_at) - julianday(created_at)) * 86400 
            ELSE NULL 
          END) as avg_delivery_time_seconds,
          AVG(delivery_time_ms) as avg_delivery_time_ms
        FROM webhook_notifications 
        WHERE created_at >= datetime('now', '-${hours} hours')
        GROUP BY notification_type, status
        ORDER BY notification_type, status
      `, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });

    const recentNotifications = await new Promise((resolve, reject) => {
      db.db.all(`
        SELECT 
          wn.*,
          c.phone_number,
          c.status as call_status,
          c.twilio_status
        FROM webhook_notifications wn
        LEFT JOIN calls c ON wn.call_sid = c.call_sid
        WHERE wn.created_at >= datetime('now', '-${hours} hours')
        ORDER BY wn.created_at DESC
        LIMIT ${limit}
      `, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });

    // Calculate enhanced summary metrics
    const totalNotifications = notificationStats.reduce((sum, stat) => sum + stat.count, 0);
    const successfulNotifications = notificationStats
      .filter(stat => stat.status === 'sent')
      .reduce((sum, stat) => sum + stat.count, 0);
    
    const successRate = totalNotifications > 0 ? 
      ((successfulNotifications / totalNotifications) * 100).toFixed(1) : 0;

    const avgDeliveryTime = notificationStats
      .filter(stat => stat.avg_delivery_time_seconds !== null)
      .reduce((sum, stat, _, arr) => {
        return sum + (stat.avg_delivery_time_seconds / arr.length);
      }, 0);

    // Get notification metrics from database
    const notificationMetrics = await db.getNotificationAnalytics(Math.ceil(hours / 24));

    res.json({
      summary: {
        total_notifications: totalNotifications,
        successful_notifications: successfulNotifications,
        success_rate_percent: parseFloat(successRate),
        average_delivery_time_seconds: avgDeliveryTime.toFixed(2),
        time_period_hours: hours,
        enhanced_tracking: true
      },
      notification_breakdown: notificationStats,
      recent_notifications: recentNotifications,
      historical_metrics: notificationMetrics,
      webhook_service_health: await webhookService.healthCheck()
    });
    
  } catch (error) {
    console.error('Error fetching enhanced notification analytics:', error);
    res.status(500).json({ 
      error: 'Failed to fetch notification analytics',
      details: error.message 
    });
  }
});

// Generate functions for a given prompt (testing endpoint)
app.post('/api/generate-functions', async (req, res) => {
  try {
    const { prompt, first_message } = req.body;
    
    if (!prompt || !first_message) {
      return res.status(400).json({ error: 'Both prompt and first_message are required' });
    }

    const functionSystem = functionEngine.generateAdaptiveFunctionSystem(prompt, first_message);
    
    res.json({
      success: true,
      business_context: functionSystem.context,
      functions: functionSystem.functions,
      function_count: functionSystem.functions.length,
      analysis: functionEngine.getBusinessAnalysis(),
      enhanced: true
    });
  } catch (error) {
    console.error('Error generating enhanced functions:', error);
    res.status(500).json({ error: 'Failed to generate functions' });
  }
});

// Enhanced health endpoint with comprehensive system status
app.get('/health', async (req, res) => {
  try {
    const calls = await db.getCallsWithTranscripts(1);
    const webhookHealth = await webhookService.healthCheck();
    const callStats = webhookService.getCallStatusStats();
    const notificationMetrics = await db.getNotificationAnalytics(1);
    
    // Check service health logs
    const recentHealthLogs = await new Promise((resolve, reject) => {
      db.db.all(`
        SELECT service_name, status, COUNT(*) as count
        FROM service_health_logs 
        WHERE timestamp >= datetime('now', '-1 hour')
        GROUP BY service_name, status
        ORDER BY service_name
      `, (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });
    
    res.json({ 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      enhanced_features: true,
      services: {
        database: {
          connected: true,
          recent_calls: calls.length
        },
        webhook_service: webhookHealth,
        call_tracking: callStats,
        notification_system: {
          total_today: notificationMetrics.total_notifications,
          success_rate: notificationMetrics.overall_success_rate + '%',
          avg_delivery_time: notificationMetrics.breakdown.length > 0 ? 
            notificationMetrics.breakdown[0].avg_delivery_time + 'ms' : 'N/A'
        }
      },
      active_calls: callConfigurations.size,
      adaptation_engine: {
        available_templates: functionEngine ? functionEngine.getBusinessAnalysis().availableTemplates.length : 0,
        active_function_systems: callFunctionSystems.size
      },
      system_health: recentHealthLogs
    });
  } catch (error) {
    console.error('Enhanced health check error:', error);
    res.status(500).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      enhanced_features: true,
      error: error.message,
      services: {
        database: {
          connected: false,
          error: error.message
        },
        webhook_service: {
          status: 'error',
          reason: 'Database connection failed'
        }
      }
    });
  }
});

// Enhanced system maintenance endpoint
app.post('/api/system/cleanup', async (req, res) => {
  try {
    const { days_to_keep = 30 } = req.body;
    
    console.log(`Starting enhanced system cleanup (keeping ${days_to_keep} days)...`);
    
    const cleanedRecords = await db.cleanupOldRecords(days_to_keep);
    
    // Log cleanup operation
    await db.logServiceHealth('system_maintenance', 'cleanup_completed', {
      records_cleaned: cleanedRecords,
      days_kept: days_to_keep
    });
    
    res.json({
      success: true,
      records_cleaned: cleanedRecords,
      days_kept: days_to_keep,
      timestamp: new Date().toISOString(),
      enhanced: true
    });
    
  } catch (error) {
    console.error('Error during enhanced system cleanup:', error);
    
    await db.logServiceHealth('system_maintenance', 'cleanup_failed', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'System cleanup failed',
      details: error.message
    });
  }
});

// Basic calls list endpoint
app.get('/api/calls', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 50); // Max 50 calls
    const offset = parseInt(req.query.offset) || 0;
    
    console.log(`Fetching calls list: limit=${limit}, offset=${offset}`);
    
    // Get calls from database using the new method
    const calls = await db.getRecentCalls(limit, offset);
    const totalCount = await db.getCallsCount();

    // Format the response with enhanced data
    const formattedCalls = calls.map(call => ({
      ...call,
      transcript_count: call.transcript_count || 0,
      created_date: new Date(call.created_at).toLocaleDateString(),
      duration_formatted: call.duration ? 
        `${Math.floor(call.duration/60)}:${String(call.duration%60).padStart(2,'0')}` : 
        'N/A',
      // Parse JSON fields safely
      business_context: call.business_context ? 
        (() => { try { return JSON.parse(call.business_context); } catch { return null; } })() : 
        null,
      generated_functions: call.generated_functions ?
        (() => { try { return JSON.parse(call.generated_functions); } catch { return []; } })() :
        []
    }));

    res.json({
      success: true,
      calls: formattedCalls,
      pagination: {
        total: totalCount,
        limit: limit,
        offset: offset,
        has_more: offset + limit < totalCount
      },
      enhanced_features: true
    });

  } catch (error) {
    console.error('Error fetching calls list:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch calls list',
      details: error.message
    });
  }
});

// Enhanced calls list endpoint with filters
app.get('/api/calls/list', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);
    const offset = parseInt(req.query.offset) || 0;
    const status = req.query.status; // Filter by status
    const phone = req.query.phone; // Filter by phone number
    const dateFrom = req.query.date_from; // Filter by date range
    const dateTo = req.query.date_to;

    let whereClause = '';
    let queryParams = [];
    
    // Build dynamic where clause
    const conditions = [];
    
    if (status) {
      conditions.push('c.status = ?');
      queryParams.push(status);
    }
    
    if (phone) {
      conditions.push('c.phone_number LIKE ?');
      queryParams.push(`%${phone}%`);
    }
    
    if (dateFrom) {
      conditions.push('c.created_at >= ?');
      queryParams.push(dateFrom);
    }
    
    if (dateTo) {
      conditions.push('c.created_at <= ?');
      queryParams.push(dateTo);
    }
    
    if (conditions.length > 0) {
      whereClause = 'WHERE ' + conditions.join(' AND ');
    }

    const query = `
      SELECT 
        c.*,
        COUNT(t.id) as transcript_count,
        GROUP_CONCAT(DISTINCT t.speaker) as speakers,
        MIN(t.timestamp) as conversation_start,
        MAX(t.timestamp) as conversation_end
      FROM calls c
      LEFT JOIN transcripts t ON c.call_sid = t.call_sid
      ${whereClause}
      GROUP BY c.call_sid
      ORDER BY c.created_at DESC
      LIMIT ? OFFSET ?
    `;

    queryParams.push(limit, offset);
    
    const calls = await new Promise((resolve, reject) => {
      db.db.all(query, queryParams, (err, rows) => {
        if (err) {
          console.error('Database error in enhanced calls query:', err);
          reject(err);
        } else {
          resolve(rows || []);
        }
      });
    });

    // Get filtered count
    const countQuery = `SELECT COUNT(*) as count FROM calls c ${whereClause}`;
    const totalCount = await new Promise((resolve, reject) => {
      db.db.get(countQuery, queryParams.slice(0, -2), (err, row) => {
        if (err) {
          console.error('Database error counting filtered calls:', err);
          resolve(0);
        } else {
          resolve(row?.count || 0);
        }
      });
    });

    // Enhanced formatting
    const enhancedCalls = calls.map(call => {
      const hasConversation = call.speakers && call.speakers.includes('user') && call.speakers.includes('ai');
      const conversationDuration = call.conversation_start && call.conversation_end ?
        Math.round((new Date(call.conversation_end) - new Date(call.conversation_start)) / 1000) : 0;

      return {
        call_sid: call.call_sid,
        phone_number: call.phone_number,
        status: call.status,
        twilio_status: call.twilio_status,
        created_at: call.created_at,
        started_at: call.started_at,
        ended_at: call.ended_at,
        duration: call.duration,
        transcript_count: call.transcript_count || 0,
        has_conversation: hasConversation,
        conversation_duration: conversationDuration,
        call_summary: call.call_summary,
        user_chat_id: call.user_chat_id,
        // Enhanced metadata
        business_context: call.business_context ? 
          (() => { try { return JSON.parse(call.business_context); } catch { return null; } })() : null,
        generated_functions_count: call.generated_functions ?
          (() => { try { return JSON.parse(call.generated_functions).length; } catch { return 0; } })() : 0,
        // Formatted fields
        created_date: new Date(call.created_at).toLocaleDateString(),
        created_time: new Date(call.created_at).toLocaleTimeString(),
        duration_formatted: call.duration ? 
          `${Math.floor(call.duration/60)}:${String(call.duration%60).padStart(2,'0')}` : 'N/A',
        status_icon: getStatusIcon(call.status),
        enhanced: true
      };
    });

    res.json({
      success: true,
      calls: enhancedCalls,
      filters: {
        status,
        phone,
        date_from: dateFrom,
        date_to: dateTo
      },
      pagination: {
        total: totalCount,
        limit: limit,
        offset: offset,
        has_more: offset + limit < totalCount,
        current_page: Math.floor(offset / limit) + 1,
        total_pages: Math.ceil(totalCount / limit)
      },
      enhanced_features: true
    });

  } catch (error) {
    console.error('Error in enhanced calls list:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch enhanced calls list',
      details: error.message
    });
  }
});

// Helper function for status icons
function getStatusIcon(status) {
  const icons = {
    'completed': '✅',
    'no-answer': '📶',
    'busy': '📞',
    'failed': '❌',
    'canceled': '🎫',
    'in-progress': '🔄',
    'ringing': '📲'
  };
  return icons[status] || '❓';
}

// Add calls analytics endpoint
app.get('/api/calls/analytics', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const dateFrom = new Date(Date.now() - (days * 24 * 60 * 60 * 1000)).toISOString();

    // Get comprehensive analytics
    const analytics = await new Promise((resolve, reject) => {
      const queries = {
        // Total calls in period
        totalCalls: `SELECT COUNT(*) as count FROM calls WHERE created_at >= ?`,
        
        // Calls by status
        statusBreakdown: `
          SELECT status, COUNT(*) as count 
          FROM calls 
          WHERE created_at >= ? 
          GROUP BY status 
          ORDER BY count DESC
        `,
        
        // Average call duration
        avgDuration: `
          SELECT AVG(duration) as avg_duration 
          FROM calls 
          WHERE created_at >= ? AND duration > 0
        `,
        
        // Success rate (completed calls with conversation)
        successRate: `
          SELECT 
            COUNT(CASE WHEN c.status = 'completed' AND t.transcript_count > 0 THEN 1 END) as successful,
            COUNT(*) as total
          FROM calls c
          LEFT JOIN (
            SELECT call_sid, COUNT(*) as transcript_count 
            FROM transcripts 
            WHERE speaker = 'user' 
            GROUP BY call_sid
          ) t ON c.call_sid = t.call_sid
          WHERE c.created_at >= ?
        `,
        
        // Daily call volume
        dailyVolume: `
          SELECT 
            DATE(created_at) as date,
            COUNT(*) as calls,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed
          FROM calls 
          WHERE created_at >= ? 
          GROUP BY DATE(created_at) 
          ORDER BY date DESC
        `
      };

      const results = {};
      let completed = 0;
      const total = Object.keys(queries).length;

      for (const [key, query] of Object.entries(queries)) {
        db.db.all(query, [dateFrom], (err, rows) => {
          if (err) {
            console.error(`Analytics query error for ${key}:`, err);
            results[key] = null;
          } else {
            results[key] = rows;
          }
          
          completed++;
          if (completed === total) {
            resolve(results);
          }
        });
      }
    });

    // Process analytics data
    const processedAnalytics = {
      period: {
        days: days,
        from: dateFrom,
        to: new Date().toISOString()
      },
      summary: {
        total_calls: analytics.totalCalls?.[0]?.count || 0,
        average_duration: analytics.avgDuration?.[0]?.avg_duration ? 
          Math.round(analytics.avgDuration[0].avg_duration) : 0,
        success_rate: analytics.successRate?.[0] ? 
          Math.round((analytics.successRate[0].successful / analytics.successRate[0].total) * 100) : 0
      },
      status_breakdown: analytics.statusBreakdown || [],
      daily_volume: analytics.dailyVolume || [],
      enhanced_features: true
    };

    res.json(processedAnalytics);

  } catch (error) {
    console.error('Error fetching call analytics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch analytics',
      details: error.message
    });
  }
});

// Search calls endpoint
app.get('/api/calls/search', async (req, res) => {
  try {
    const query = req.query.q;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    
    if (!query || query.length < 2) {
      return res.status(400).json({
        success: false,
        error: 'Search query must be at least 2 characters'
      });
    }

    // Search in calls and transcripts
    const searchResults = await new Promise((resolve, reject) => {
      const searchQuery = `
        SELECT DISTINCT
          c.*,
          COUNT(t.id) as transcript_count,
          GROUP_CONCAT(t.message, ' ') as conversation_text
        FROM calls c
        LEFT JOIN transcripts t ON c.call_sid = t.call_sid
        WHERE 
          c.phone_number LIKE ? OR
          c.call_summary LIKE ? OR
          c.prompt LIKE ? OR
          c.first_message LIKE ? OR
          t.message LIKE ?
        GROUP BY c.call_sid
        ORDER BY c.created_at DESC
        LIMIT ?
      `;
      
      const searchTerm = `%${query}%`;
      const params = [searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, limit];
      
      db.db.all(searchQuery, params, (err, rows) => {
        if (err) {
          console.error('Search query error:', err);
          reject(err);
        } else {
          resolve(rows || []);
        }
      });
    });

    const formattedResults = searchResults.map(call => ({
      call_sid: call.call_sid,
      phone_number: call.phone_number,
      status: call.status,
      created_at: call.created_at,
      duration: call.duration,
      transcript_count: call.transcript_count || 0,
      call_summary: call.call_summary,
      // Highlight matching text (basic implementation)
      matching_text: call.conversation_text ?
        `${maskOtpForExternal(call.conversation_text).substring(0, 200)}...` : null,
      created_date: new Date(call.created_at).toLocaleDateString(),
      duration_formatted: call.duration ? 
        `${Math.floor(call.duration/60)}:${String(call.duration%60).padStart(2,'0')}` : 'N/A'
    }));

    res.json({
      success: true,
      query: query,
      results: formattedResults,
      result_count: formattedResults.length,
      enhanced_search: true
    });

  } catch (error) {
    console.error('Error in call search:', error);
    res.status(500).json({
      success: false,
      error: 'Search failed',
      details: error.message
    });
  }
});

// SMS webhook endpoints
app.post('/webhook/sms', async (req, res) => {
    try {
        warnOnInvalidTwilioSignature(req, '/webhook/sms');
        const { From, Body, MessageSid, SmsStatus } = req.body;

        console.log(`SMS webhook: ${From} -> ${Body}`);

        // Handle incoming SMS with AI
        const result = await smsService.handleIncomingSMS(From, Body, MessageSid);

        // Save to database if needed
        if (db) {
            await db.saveSMSMessage({
                message_sid: MessageSid,
                from_number: From,
                body: Body,
                status: SmsStatus,
                direction: 'inbound',
                ai_response: result.ai_response,
                response_message_sid: result.message_sid
            });
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('SMS webhook error:', error);
        res.status(500).send('Error');
    }
});

app.post('/webhook/sms-status', async (req, res) => {
    try {
        warnOnInvalidTwilioSignature(req, '/webhook/sms-status');
        const { MessageSid, MessageStatus, ErrorCode, ErrorMessage } = req.body;

        console.log(`SMS status update: ${MessageSid} -> ${MessageStatus}`);

        if (db) {
            await db.updateSMSStatus(MessageSid, {
                status: MessageStatus,
                error_code: ErrorCode,
                error_message: ErrorMessage,
                updated_at: new Date()
            });
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('SMS status webhook error:', error);
        res.status(500).send('OK'); // Return OK to prevent retries
    }
});

// Send single SMS endpoint
app.post('/api/sms/send', async (req, res) => {
    try {
        const { to, message, from, user_chat_id } = req.body;

        if (!to || !message) {
            return res.status(400).json({
                success: false,
                error: 'Phone number and message are required'
            });
        }

        // Validate phone number format
        if (!to.match(/^\+[1-9]\d{1,14}$/)) {
            return res.status(400).json({
                success: false,
                error: 'Invalid phone number format. Use E.164 format (e.g., +1234567890)'
            });
        }

        const result = await smsService.sendSMS(to, message, from);

        // Save to database
        if (db) {
            await db.saveSMSMessage({
                message_sid: result.message_sid,
                to_number: to,
                from_number: result.from,
                body: message,
                status: result.status,
                direction: 'outbound',
                user_chat_id: user_chat_id
            });

            // Create webhook notification
            if (user_chat_id) {
                await db.createEnhancedWebhookNotification(
                    result.message_sid,
                    'sms_sent',
                    user_chat_id
                );
            }
        }

        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        console.error('❌ SMS send error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send SMS',
            details: error.message
        });
    }
});

// Send bulk SMS endpoint
app.post('/api/sms/bulk', async (req, res) => {
    try {
        const { recipients, message, options = {}, user_chat_id } = req.body;

        if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'Recipients array is required and must not be empty'
            });
        }

        if (!message) {
            return res.status(400).json({
                success: false,
                error: 'Message is required'
            });
        }

        if (recipients.length > 100) {
            return res.status(400).json({
                success: false,
                error: 'Maximum 100 recipients per bulk send'
            });
        }

        const result = await smsService.sendBulkSMS(recipients, message, options);

        // Log bulk operation
        if (db) {
            await db.logBulkSMSOperation({
                total_recipients: result.total,
                successful: result.successful,
                failed: result.failed,
                message: message,
                user_chat_id: user_chat_id,
                timestamp: new Date()
            });
        }

        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        console.error('❌ Bulk SMS error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send bulk SMS',
            details: error.message
        });
    }
});

// Schedule SMS endpoint
app.post('/api/sms/schedule', async (req, res) => {
    try {
        const { to, message, scheduled_time, options = {} } = req.body;

        if (!to || !message || !scheduled_time) {
            return res.status(400).json({
                success: false,
                error: 'Phone number, message, and scheduled_time are required'
            });
        }

        const scheduledDate = new Date(scheduled_time);
        if (scheduledDate <= new Date()) {
            return res.status(400).json({
                success: false,
                error: 'Scheduled time must be in the future'
            });
        }

        const result = await smsService.scheduleSMS(to, message, scheduled_time, options);

        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        console.error('❌ SMS schedule error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to schedule SMS',
            details: error.message
        });
    }
});

// SMS templates endpoint
app.get('/api/sms/templates', async (req, res) => {
    try {
        const { template_name, variables } = req.query;

        if (template_name) {
            try {
                const parsedVariables = variables ? JSON.parse(variables) : {};
                const template = smsService.getTemplate(template_name, parsedVariables);

                res.json({
                    success: true,
                    template_name,
                    template,
                    variables: parsedVariables
                });
            } catch (templateError) {
                res.status(400).json({
                    success: false,
                    error: templateError.message
                });
            }
        } else {
            // Return available templates
            res.json({
                success: true,
                available_templates: [
                    'welcome', 'appointment_reminder', 'verification', 'order_update',
                    'payment_reminder', 'promotional', 'customer_service', 'survey'
                ]
            });
        }
    } catch (error) {
        console.error('❌ SMS templates error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get templates'
        });
    }
});

// Get SMS messages from database for conversation view
app.get('/api/sms/messages/conversation/:phone', async (req, res) => {
    try {
        const { phone } = req.params;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);

        if (!phone) {
            return res.status(400).json({
                success: false,
                error: 'Phone number is required'
            });
        }

        const messages = await db.getSMSConversation(phone, limit);

        res.json({
            success: true,
            phone: phone,
            messages: messages,
            message_count: messages.length
        });

    } catch (error) {
        console.error('❌ Error fetching SMS conversation from database:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch conversation',
            details: error.message
        });
    }
});

// Get recent SMS messages from database
app.get('/api/sms/messages/recent', async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 10, 50);
        const offset = parseInt(req.query.offset) || 0;

        const messages = await db.getSMSMessages(limit, offset);

        res.json({
            success: true,
            messages: messages,
            count: messages.length,
            limit: limit,
            offset: offset
        });

    } catch (error) {
        console.error('❌ Error fetching recent SMS messages:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch recent messages',
            details: error.message
        });
    }
});

// Get SMS database statistics
app.get('/api/sms/database-stats', async (req, res) => {
    try {
        const hours = parseInt(req.query.hours) || 24;
        const dateFrom = new Date(Date.now() - (hours * 60 * 60 * 1000)).toISOString();

        // Get comprehensive SMS statistics from database
        const stats = await new Promise((resolve, reject) => {
            const queries = {
                // Total messages
                totalMessages: `SELECT COUNT(*) as count FROM sms_messages`,
                
                // Messages by direction
                messagesByDirection: `
                    SELECT direction, COUNT(*) as count 
                    FROM sms_messages 
                    GROUP BY direction
                `,
                
                // Messages by status
                messagesByStatus: `
                    SELECT status, COUNT(*) as count 
                    FROM sms_messages 
                    GROUP BY status
                    ORDER BY count DESC
                `,
                
                // Recent messages
                recentMessages: `
                    SELECT * FROM sms_messages 
                    WHERE created_at >= ?
                    ORDER BY created_at DESC 
                    LIMIT 5
                `,
                
                // Bulk operations
                bulkOperations: `SELECT COUNT(*) as count FROM bulk_sms_operations`,
                
                // Recent bulk operations
                recentBulkOps: `
                    SELECT * FROM bulk_sms_operations 
                    WHERE created_at >= ?
                    ORDER BY created_at DESC 
                    LIMIT 3
                `
            };

            const results = {};
            let completed = 0;
            const total = Object.keys(queries).length;

            for (const [key, query] of Object.entries(queries)) {
                const params = ['recentMessages', 'recentBulkOps'].includes(key) ? [dateFrom] : [];
                
                db.db.all(query, params, (err, rows) => {
                    if (err) {
                        console.error(`SMS stats query error for ${key}:`, err);
                        results[key] = key.includes('recent') ? [] : [{ count: 0 }];
                    } else {
                        results[key] = rows || [];
                    }
                    
                    completed++;
                    if (completed === total) {
                        resolve(results);
                    }
                });
            }
        });

        // Process the statistics
        const processedStats = {
            total_messages: stats.totalMessages[0]?.count || 0,
            sent_messages: stats.messagesByDirection.find(d => d.direction === 'outbound')?.count || 0,
            received_messages: stats.messagesByDirection.find(d => d.direction === 'inbound')?.count || 0,
            delivered_count: stats.messagesByStatus.find(s => s.status === 'delivered')?.count || 0,
            failed_count: stats.messagesByStatus.find(s => s.status === 'failed')?.count || 0,
            pending_count: stats.messagesByStatus.find(s => s.status === 'pending')?.count || 0,
            bulk_operations: stats.bulkOperations[0]?.count || 0,
            recent_messages: stats.recentMessages || [],
            recent_bulk_operations: stats.recentBulkOps || [],
            status_breakdown: stats.messagesByStatus || [],
            direction_breakdown: stats.messagesByDirection || [],
            time_period_hours: hours
        };

        // Calculate success rate
        const totalSent = processedStats.sent_messages;
        const delivered = processedStats.delivered_count;
        processedStats.success_rate = totalSent > 0 ? 
            Math.round((delivered / totalSent) * 100) : 0;

        res.json({
            success: true,
            ...processedStats
        });

    } catch (error) {
        console.error('❌ Error fetching SMS database statistics:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch database statistics',
            details: error.message
        });
    }
});

// Get SMS status by message SID
app.get('/api/sms/status/:messageSid', async (req, res) => {
    try {
        const { messageSid } = req.params;

        const message = await new Promise((resolve, reject) => {
            db.db.get(
                `SELECT * FROM sms_messages WHERE message_sid = ?`,
                [messageSid],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });

        if (!message) {
            return res.status(404).json({
                success: false,
                error: 'Message not found'
            });
        }

        res.json({
            success: true,
            message: message
        });

    } catch (error) {
        console.error('❌ Error fetching SMS status:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch message status',
            details: error.message
        });
    }
});

// Enhanced SMS templates endpoint with better error handling
app.get('/api/sms/templates/:templateName?', async (req, res) => {
    try {
        const { templateName } = req.params;
        const { variables } = req.query;

        // Built-in templates (fallback)
        const builtInTemplates = {
            welcome: 'Welcome to our service! We\'re excited to have you aboard. Reply HELP for assistance or STOP to unsubscribe.',
            appointment_reminder: 'Reminder: You have an appointment on {date} at {time}. Reply CONFIRM to confirm or RESCHEDULE to change.',
            verification: 'Your verification code is: {code}. This code will expire in 10 minutes. Do not share this code with anyone.',
            order_update: 'Order #{order_id} update: {status}. Track your order at {tracking_url}',
            payment_reminder: 'Payment reminder: Your payment of {amount} is due on {due_date}. Pay now: {payment_url}',
            promotional: '🎉 Special offer just for you! {offer_text} Use code {promo_code}. Valid until {expiry_date}. Reply STOP to opt out.',
            customer_service: 'Thanks for contacting us! We\'ve received your message and will respond within 24 hours. For urgent matters, call {phone}.',
            survey: 'How was your experience with us? Rate us 1-5 stars by replying with a number. Your feedback helps us improve!'
        };

        if (templateName) {
            // Get specific template
            if (!builtInTemplates[templateName]) {
                return res.status(404).json({
                    success: false,
                    error: `Template '${templateName}' not found`
                });
            }

            let template = builtInTemplates[templateName];
            let parsedVariables = {};

            // Parse and apply variables if provided
            if (variables) {
                try {
                    parsedVariables = JSON.parse(variables);
                    
                    // Replace variables in template
                    for (const [key, value] of Object.entries(parsedVariables)) {
                        template = template.replace(new RegExp(`{${key}}`, 'g'), value);
                    }
                } catch (parseError) {
                    console.error('Error parsing template variables:', parseError);
                    // Continue with template without variable substitution
                }
            }

            res.json({
                success: true,
                template_name: templateName,
                template: template,
                original_template: builtInTemplates[templateName],
                variables: parsedVariables
            });

        } else {
            // Get list of available templates
            res.json({
                success: true,
                available_templates: Object.keys(builtInTemplates),
                template_count: Object.keys(builtInTemplates).length
            });
        }

    } catch (error) {
        console.error('❌ Error handling SMS templates:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to process template request',
            details: error.message
        });
    }
});

// SMS webhook delivery status notifications (enhanced)
app.post('/webhook/sms-delivery', async (req, res) => {
    try {
        const { MessageSid, MessageStatus, ErrorCode, ErrorMessage, To, From } = req.body;

        console.log(`📱 SMS Delivery Status: ${MessageSid} -> ${MessageStatus}`);

        // Update message status in database
        if (db) {
            await db.updateSMSStatus(MessageSid, {
                status: MessageStatus,
                error_code: ErrorCode,
                error_message: ErrorMessage
            });

            // Get the original message to find user_chat_id for notification
            const message = await new Promise((resolve, reject) => {
                db.db.get(
                    `SELECT * FROM sms_messages WHERE message_sid = ?`,
                    [MessageSid],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    }
                );
            });

            // Create webhook notification if user_chat_id exists
            if (message && message.user_chat_id) {
                const notificationType = MessageStatus === 'delivered' ? 'sms_delivered' :
                                       MessageStatus === 'failed' ? 'sms_failed' :
                                       `sms_${MessageStatus}`;

                await db.createEnhancedWebhookNotification(
                    MessageSid,
                    notificationType,
                    message.user_chat_id,
                    MessageStatus === 'failed' ? 'high' : 'normal'
                );

                console.log(`📨 Created ${notificationType} notification for user ${message.user_chat_id}`);
            }
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('❌ SMS delivery webhook error:', error);
        res.status(200).send('OK'); // Always return 200 to prevent retries
    }
});

// Get SMS statistics
app.get('/api/sms/stats', async (req, res) => {
  try {
    const stats = smsService.getStatistics();
    const activeConversations = smsService.getActiveConversations();
    
    res.json({
      success: true,
      statistics: stats,
      active_conversations: activeConversations.slice(0, 20), // Last 20 conversations
      sms_service_enabled: true
    });
    
  } catch (error) {
    console.error('❌ SMS stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get SMS statistics'
    });
  }
});

// Bulk SMS status endpoint
app.get('/api/sms/bulk/status', async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 10, 50);
        const hours = parseInt(req.query.hours) || 24;
        const dateFrom = new Date(Date.now() - (hours * 60 * 60 * 1000)).toISOString();

        const bulkOperations = await new Promise((resolve, reject) => {
            db.db.all(`
                SELECT * FROM bulk_sms_operations 
                WHERE created_at >= ?
                ORDER BY created_at DESC 
                LIMIT ?
            `, [dateFrom, limit], (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows || []);
                }
            });
        });

        // Get summary statistics
        const summary = bulkOperations.reduce((acc, op) => {
            acc.totalOperations += 1;
            acc.totalRecipients += op.total_recipients;
            acc.totalSuccessful += op.successful;
            acc.totalFailed += op.failed;
            return acc;
        }, {
            totalOperations: 0,
            totalRecipients: 0,
            totalSuccessful: 0,
            totalFailed: 0
        });

        summary.successRate = summary.totalRecipients > 0 ? 
            Math.round((summary.totalSuccessful / summary.totalRecipients) * 100) : 0;

        res.json({
            success: true,
            summary: summary,
            operations: bulkOperations,
            time_period_hours: hours
        });

    } catch (error) {
        console.error('❌ Error fetching bulk SMS status:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch bulk SMS status',
            details: error.message
        });
    }
});

// SMS analytics dashboard endpoint
app.get('/api/sms/analytics', async (req, res) => {
    try {
        const days = parseInt(req.query.days) || 7;
        const dateFrom = new Date(Date.now() - (days * 24 * 60 * 60 * 1000)).toISOString();

        const analytics = await new Promise((resolve, reject) => {
            const queries = {
                // Daily message volume
                dailyVolume: `
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as total,
                        COUNT(CASE WHEN direction = 'outbound' THEN 1 END) as sent,
                        COUNT(CASE WHEN direction = 'inbound' THEN 1 END) as received,
                        COUNT(CASE WHEN status = 'delivered' THEN 1 END) as delivered,
                        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
                    FROM sms_messages 
                    WHERE created_at >= ?
                    GROUP BY DATE(created_at) 
                    ORDER BY date DESC
                `,
                
                // Hourly distribution
                hourlyDistribution: `
                    SELECT 
                        strftime('%H', created_at) as hour,
                        COUNT(*) as count
                    FROM sms_messages 
                    WHERE created_at >= ?
                    GROUP BY strftime('%H', created_at)
                    ORDER BY hour
                `,
                
                // Top phone numbers (anonymized)
                topNumbers: `
                    SELECT 
                        SUBSTR(COALESCE(to_number, from_number), 1, 6) || 'XXXX' as phone_prefix,
                        COUNT(*) as message_count
                    FROM sms_messages 
                    WHERE created_at >= ?
                    GROUP BY SUBSTR(COALESCE(to_number, from_number), 1, 6)
                    ORDER BY message_count DESC 
                    LIMIT 10
                `,
                
                // Error analysis
                errorAnalysis: `
                    SELECT 
                        error_code,
                        error_message,
                        COUNT(*) as count
                    FROM sms_messages 
                    WHERE created_at >= ? AND error_code IS NOT NULL
                    GROUP BY error_code, error_message
                    ORDER BY count DESC
                    LIMIT 10
                `
            };

            const results = {};
            let completed = 0;
            const total = Object.keys(queries).length;

            for (const [key, query] of Object.entries(queries)) {
                db.db.all(query, [dateFrom], (err, rows) => {
                    if (err) {
                        console.error(`SMS analytics query error for ${key}:`, err);
                        results[key] = [];
                    } else {
                        results[key] = rows || [];
                    }
                    
                    completed++;
                    if (completed === total) {
                        resolve(results);
                    }
                });
            }
        });

        // Calculate summary metrics
        const summary = {
            total_messages: 0,
            total_sent: 0,
            total_received: 0,
            total_delivered: 0,
            total_failed: 0,
            delivery_rate: 0,
            error_rate: 0
        };

        analytics.dailyVolume.forEach(day => {
            summary.total_messages += day.total;
            summary.total_sent += day.sent;
            summary.total_received += day.received;
            summary.total_delivered += day.delivered;
            summary.total_failed += day.failed;
        });

        if (summary.total_sent > 0) {
            summary.delivery_rate = Math.round((summary.total_delivered / summary.total_sent) * 100);
            summary.error_rate = Math.round((summary.total_failed / summary.total_sent) * 100);
        }

        res.json({
            success: true,
            period: {
                days: days,
                from: dateFrom,
                to: new Date().toISOString()
            },
            summary: summary,
            daily_volume: analytics.dailyVolume,
            hourly_distribution: analytics.hourlyDistribution,
            top_numbers: analytics.topNumbers,
            error_analysis: analytics.errorAnalysis,
            enhanced_analytics: true
        });

    } catch (error) {
        console.error('❌ Error fetching SMS analytics:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch SMS analytics',
            details: error.message
        });
    }
});

// SMS search endpoint
app.get('/api/sms/search', async (req, res) => {
    try {
        const query = req.query.q;
        const limit = Math.min(parseInt(req.query.limit) || 20, 50);
        const direction = req.query.direction; // 'inbound', 'outbound', or null for all
        const status = req.query.status; // message status filter

        if (!query || query.length < 2) {
            return res.status(400).json({
                success: false,
                error: 'Search query must be at least 2 characters'
            });
        }

        let whereClause = `WHERE (body LIKE ? OR to_number LIKE ? OR from_number LIKE ?)`;
        let queryParams = [`%${query}%`, `%${query}%`, `%${query}%`];

        if (direction) {
            whereClause += ` AND direction = ?`;
            queryParams.push(direction);
        }

        if (status) {
            whereClause += ` AND status = ?`;
            queryParams.push(status);
        }

        queryParams.push(limit);

        const searchResults = await new Promise((resolve, reject) => {
            const searchQuery = `
                SELECT * FROM sms_messages 
                ${whereClause}
                ORDER BY created_at DESC
                LIMIT ?
            `;

            db.db.all(searchQuery, queryParams, (err, rows) => {
                if (err) {
                    console.error('SMS search query error:', err);
                    reject(err);
                } else {
                    resolve(rows || []);
                }
            });
        });

        // Format results for display
        const formattedResults = searchResults.map(msg => ({
            message_sid: msg.message_sid,
            phone: msg.to_number || msg.from_number,
            direction: msg.direction,
            status: msg.status,
            body: msg.body,
            created_at: msg.created_at,
            created_date: new Date(msg.created_at).toLocaleDateString(),
            created_time: new Date(msg.created_at).toLocaleTimeString(),
            // Highlight matching text (basic implementation)
            highlighted_body: msg.body.replace(
                new RegExp(query, 'gi'), 
                `**${query}**`
            ),
            error_info: msg.error_code ? {
                code: msg.error_code,
                message: msg.error_message
            } : null
        }));

        res.json({
            success: true,
            query: query,
            filters: { direction, status },
            results: formattedResults,
            result_count: formattedResults.length,
            enhanced_search: true
        });

    } catch (error) {
        console.error('❌ Error in SMS search:', error);
        res.status(500).json({
            success: false,
            error: 'Search failed',
            details: error.message
        });
    }
});

// Export SMS data endpoint
app.get('/api/sms/export', async (req, res) => {
    try {
        const format = req.query.format || 'json'; // 'json' or 'csv'
        const days = parseInt(req.query.days) || 30;
        const dateFrom = new Date(Date.now() - (days * 24 * 60 * 60 * 1000)).toISOString();

        const messages = await new Promise((resolve, reject) => {
            db.db.all(`
                SELECT 
                    message_sid,
                    to_number,
                    from_number,
                    body,
                    status,
                    direction,
                    created_at,
                    updated_at,
                    error_code,
                    error_message,
                    ai_response
                FROM sms_messages 
                WHERE created_at >= ?
                ORDER BY created_at DESC
            `, [dateFrom], (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows || []);
                }
            });
        });

        if (format === 'csv') {
            // Generate CSV
            const csvHeaders = [
                'Message SID', 'To Number', 'From Number', 'Message Body', 
                'Status', 'Direction', 'Created At', 'Updated At', 
                'Error Code', 'Error Message', 'AI Response'
            ];

            let csvContent = csvHeaders.join(',') + '\n';
            
            messages.forEach(msg => {
                const row = [
                    msg.message_sid || '',
                    msg.to_number || '',
                    msg.from_number || '',
                    `"${(msg.body || '').replace(/"/g, '""')}"`, // Escape quotes
                    msg.status || '',
                    msg.direction || '',
                    msg.created_at || '',
                    msg.updated_at || '',
                    msg.error_code || '',
                    `"${(msg.error_message || '').replace(/"/g, '""')}"`,
                    `"${(msg.ai_response || '').replace(/"/g, '""')}"`
                ];
                csvContent += row.join(',') + '\n';
            });

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="sms-export-${new Date().toISOString().split('T')[0]}.csv"`);
            res.send(csvContent);

        } else {
            // Return JSON
            res.json({
                success: true,
                export_info: {
                    total_messages: messages.length,
                    date_range: {
                        from: dateFrom,
                        to: new Date().toISOString()
                    },
                    exported_at: new Date().toISOString()
                },
                messages: messages
            });
        }

    } catch (error) {
        console.error('❌ Error exporting SMS data:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to export SMS data',
            details: error.message
        });
    }
});

// SMS system health check
app.get('/api/sms/health', async (req, res) => {
    try {
        const health = {
            timestamp: new Date().toISOString(),
            status: 'healthy',
            services: {
                database: { status: 'unknown' },
                twilio: { status: 'unknown' },
                sms_service: { status: 'unknown' }
            },
            statistics: {
                active_conversations: 0,
                scheduled_messages: 0,
                recent_messages: 0
            }
        };

        // Check database connectivity
        try {
            const dbTest = await new Promise((resolve, reject) => {
                db.db.get('SELECT COUNT(*) as count FROM sms_messages LIMIT 1', (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            
            health.services.database.status = 'healthy';
            health.services.database.message_count = dbTest.count;
        } catch (dbError) {
            health.services.database.status = 'unhealthy';
            health.services.database.error = dbError.message;
            health.status = 'degraded';
        }

        // Check SMS service if available
        try {
            if (smsService) {
                const stats = smsService.getStatistics();
                health.services.sms_service.status = 'healthy';
                health.statistics.active_conversations = stats.active_conversations;
                health.statistics.scheduled_messages = stats.scheduled_messages;
            } else {
                health.services.sms_service.status = 'not_initialized';
            }
        } catch (smsError) {
            health.services.sms_service.status = 'unhealthy';
            health.services.sms_service.error = smsError.message;
        }

        // Check recent activity
        try {
            const recentCount = await new Promise((resolve, reject) => {
                const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
                db.db.get(
                    'SELECT COUNT(*) as count FROM sms_messages WHERE created_at >= ?',
                    [oneHourAgo],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row.count || 0);
                    }
                );
            });
            
            health.statistics.recent_messages = recentCount;
        } catch (recentError) {
            console.warn('Could not get recent message count:', recentError);
        }

        // Check Twilio connectivity (basic check)
        try {
            if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
                health.services.twilio.status = 'configured';
                health.services.twilio.account_sid = process.env.TWILIO_ACCOUNT_SID.substring(0, 8) + '...';
            } else {
                health.services.twilio.status = 'not_configured';
                health.status = 'degraded';
            }
        } catch (twilioError) {
            health.services.twilio.status = 'error';
            health.services.twilio.error = twilioError.message;
        }

        res.json(health);

    } catch (error) {
        console.error('❌ SMS health check error:', error);
        res.status(500).json({
            timestamp: new Date().toISOString(),
            status: 'unhealthy',
            error: 'Health check failed',
            details: error.message
        });
    }
});

// Clean up old SMS conversations (manual trigger)
app.post('/api/sms/cleanup-conversations', async (req, res) => {
    try {
        if (!smsService) {
            return res.status(500).json({
                success: false,
                error: 'SMS service not initialized'
            });
        }

        const maxAgeHours = parseInt(req.body.max_age_hours) || 24;
        const cleaned = smsService.cleanupOldConversations(maxAgeHours);

        res.json({
            success: true,
            cleaned_count: cleaned,
            max_age_hours: maxAgeHours,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('❌ Error cleaning up SMS conversations:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to cleanup conversations',
            details: error.message
        });
    }
});

// Start scheduled message processor
setInterval(() => {
    smsService.processScheduledMessages().catch(error => {
        console.error('❌ Scheduled SMS processing error:', error);
    });
}, 60000); // Check every minute

// Cleanup old conversations every hour
setInterval(() => {
    smsService.cleanupOldConversations(24); // Keep conversations for 24 hours
}, 60 * 60 * 1000);

startServer();

// Enhanced graceful shutdown with comprehensive cleanup
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down enhanced adaptive system gracefully...');
  
  try {
    // Log shutdown start
    await db.logServiceHealth('system', 'shutdown_initiated', {
      active_calls: callConfigurations.size,
      tracked_calls: callFunctionSystems.size
    });
    
    // Stop services
    webhookService.stop();
    callConfigurations.clear();
    callFunctionSystems.clear();
    
    // Log successful shutdown
    await db.logServiceHealth('system', 'shutdown_completed', {
      timestamp: new Date().toISOString()
    });
    
    await db.close();
    console.log('✅ Enhanced adaptive system shutdown complete');
  } catch (shutdownError) {
    console.error('❌ Error during shutdown:', shutdownError);
  }
  
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\nShutting down enhanced adaptive system gracefully...');
  
  try {
    // Log shutdown start
    await db.logServiceHealth('system', 'shutdown_initiated', {
      active_calls: callConfigurations.size,
      tracked_calls: callFunctionSystems.size,
      reason: 'SIGTERM'
    });
    
    // Stop services
    webhookService.stop();
    callConfigurations.clear();
    callFunctionSystems.clear();
    
    // Log successful shutdown
    await db.logServiceHealth('system', 'shutdown_completed', {
      timestamp: new Date().toISOString()
    });
    
    await db.close();
    console.log('Enhanced adaptive system shutdown complete');
  } catch (shutdownError) {
    console.error('Error during shutdown:', shutdownError);
  }
  
  process.exit(0);
});
