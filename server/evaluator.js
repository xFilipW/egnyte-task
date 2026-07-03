import { ZxcvbnFactory, Options } from '@zxcvbn-ts/core'
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common'
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en'

/**
 * Password strength evaluator.
 *
 * Design goals (regulated industries: HIPAA / FedRAMP / NIST SP 800-63B):
 *  - Favour LENGTH over arbitrary composition rules. NIST 800-63B explicitly
 *    recommends against forced complexity (e.g. "must contain a symbol") and
 *    instead recommends long passphrases + screening against weak/known values.
 *  - Screen against dictionary words, keyboard patterns, sequences, repeats and
 *    l33t-speak variations. We delegate this to zxcvbn, an adversarial estimator
 *    that models how a real attacker guesses, rather than counting character
 *    classes.
 *  - Screen against user-specific context (username, email) so that
 *    "o.kenobi@jedi-council.com" / "okenobi" cannot be reused as the password.
 *  - Return an attacker-oriented answer: how long would this survive different
 *    real-world attack scenarios, plus actionable feedback.
 *
 * The evaluator is a PURE function of its inputs. It never logs, stores, or
 * transmits the password. That responsibility stays here so the transport layer
 * (server/index.js) can remain thin.
 */

// NIST SP 800-63B: minimum 8, and systems SHOULD allow at least 64 characters.
const POLICY = {
  minLength: 8,
  recommendedLength: 12,
  maxLength: 128,
  // Below this zxcvbn score (0-4) we consider the password unacceptable for a
  // security-conscious deployment. Score 3 == "safely unguessable: moderate
  // protection from offline slow-hash scenario (10^10 guesses)".
  minAcceptableScore: 3,
}

const SCORE_LABELS = ['very-weak', 'weak', 'fair', 'strong', 'very-strong']

let zxcvbnInstance = null

/**
 * zxcvbn needs its dictionaries loaded once per process. We build the factory
 * lazily and memoise it so the module is cheap to import and safe to call from
 * anywhere.
 */
function getZxcvbn() {
  if (zxcvbnInstance) return zxcvbnInstance
  const options = new Options()
  options.setOptions({
    dictionary: {
      ...zxcvbnCommonPackage.dictionary,
      ...zxcvbnEnPackage.dictionary,
    },
    graphs: zxcvbnCommonPackage.adjacencyGraphs,
    translations: zxcvbnEnPackage.translations,
  })
  zxcvbnInstance = new ZxcvbnFactory(options)
  return zxcvbnInstance
}

/**
 * Build the list of user-specific tokens an attacker would obviously try:
 * the username, the email, and the email local-part / domain fragments.
 * zxcvbn penalises any password derived from these.
 */
function buildUserInputs({ username, email }) {
  const inputs = new Set()
  const add = (value) => {
    if (typeof value !== 'string') return
    const trimmed = value.trim()
    if (trimmed) inputs.add(trimmed)
  }

  add(username)
  add(email)

  if (typeof email === 'string' && email.includes('@')) {
    const [localPart, domain] = email.split('@')
    add(localPart)
    if (localPart) {
      // e.g. "o.kenobi" -> "o", "kenobi"
      localPart.split(/[._\-+]/).forEach(add)
    }
    if (domain) {
      // strip TLD: "jedi-council.com" -> "jedi-council", "jedi", "council"
      const domainNoTld = domain.split('.').slice(0, -1).join('.')
      add(domainNoTld)
      domainNoTld.split(/[.\-_]/).forEach(add)
    }
  }

  return [...inputs].filter(Boolean)
}

function containsAny(password, tokens) {
  const lower = password.toLowerCase()
  return tokens.some((token) => token.length >= 3 && lower.includes(token.toLowerCase()))
}

function humanizeSeconds(seconds) {
  if (seconds === Infinity) return 'centuries'
  if (seconds < 1) return 'instantly'
  const units = [
    ['century', 'centuries', 100 * 365 * 24 * 3600],
    ['year', 'years', 365 * 24 * 3600],
    ['month', 'months', 30 * 24 * 3600],
    ['day', 'days', 24 * 3600],
    ['hour', 'hours', 3600],
    ['minute', 'minutes', 60],
    ['second', 'seconds', 1],
  ]
  for (const [singular, plural, size] of units) {
    if (seconds >= size) {
      const value = Math.round(seconds / size)
      if (singular === 'century' && value >= 100) return 'centuries'
      return `${value} ${value === 1 ? singular : plural}`
    }
  }
  return 'instantly'
}

/**
 * Evaluate a single credential set.
 *
 * @param {object} input
 * @param {string} input.password  - required
 * @param {string} [input.username]
 * @param {string} [input.email]
 * @returns {object} structured assessment (no secret material included)
 */
export function evaluatePassword({ password, username = '', email = '' } = {}) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('password is required and must be a non-empty string')
  }

  const zxcvbn = getZxcvbn()
  const userInputs = buildUserInputs({ username, email })
  const result = zxcvbn.check(password, userInputs)

  const length = password.length
  const score = result.score // 0..4

  // --- Policy gate (hard requirements independent of the score) ---------------
  const checks = []
  const addCheck = (id, label, passed, severity = 'required') =>
    checks.push({ id, label, passed, severity })

  addCheck(
    'min_length',
    `At least ${POLICY.minLength} characters`,
    length >= POLICY.minLength,
  )
  addCheck(
    'recommended_length',
    `${POLICY.recommendedLength}+ characters recommended`,
    length >= POLICY.recommendedLength,
    'recommended',
  )
  addCheck(
    'max_length',
    `No longer than ${POLICY.maxLength} characters`,
    length <= POLICY.maxLength,
  )
  addCheck(
    'no_personal_info',
    'Does not contain your username or email',
    !containsAny(password, userInputs),
  )
  addCheck(
    'not_common',
    'Not a common, breached, or easily guessed password',
    score >= 2 && !result.feedback.warning,
    'required',
  )
  addCheck(
    'strength_score',
    `Resists offline attacks (strength >= ${POLICY.minAcceptableScore}/4)`,
    score >= POLICY.minAcceptableScore,
  )

  const failedRequired = checks.filter((c) => c.severity === 'required' && !c.passed)
  const acceptable = failedRequired.length === 0

  const ct = result.crackTimes

  return {
    acceptable,
    score,
    scorePercent: Math.round((score / 4) * 100),
    label: SCORE_LABELS[score],
    guesses: result.guesses,
    guessesLog10: Number(result.guessesLog10.toFixed(2)),
    // Time to crack under four realistic attack scenarios.
    crackTime: {
      offlineFastHashing: {
        seconds: ct.offlineFastHashingXPerSecond.seconds,
        display: humanizeSeconds(ct.offlineFastHashingXPerSecond.seconds),
      },
      offlineSlowHashing: {
        seconds: ct.offlineSlowHashingXPerSecond.seconds,
        display: humanizeSeconds(ct.offlineSlowHashingXPerSecond.seconds),
      },
      onlineNoThrottling: {
        seconds: ct.onlineNoThrottlingXPerSecond.seconds,
        display: humanizeSeconds(ct.onlineNoThrottlingXPerSecond.seconds),
      },
      onlineThrottled: {
        seconds: ct.onlineThrottlingXPerHour.seconds,
        display: humanizeSeconds(ct.onlineThrottlingXPerHour.seconds),
      },
    },
    policy: {
      passed: acceptable,
      minAcceptableScore: POLICY.minAcceptableScore,
      checks,
    },
    feedback: {
      warning: result.feedback.warning || null,
      suggestions: result.feedback.suggestions || [],
    },
    meta: {
      length,
      calcTimeMs: result.calcTime,
      engine: 'zxcvbn-ts',
      standard: 'NIST SP 800-63B',
      evaluatedAt: new Date().toISOString(),
    },
  }
}

export { POLICY, SCORE_LABELS }
