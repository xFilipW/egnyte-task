// Presentation helpers mapping the backend's 0-4 score to UI copy and colours.

export const STRENGTH_META = {
  0: { label: 'Very weak', bar: 'bg-red-500', text: 'text-red-600 dark:text-red-400', ring: 'bg-red-500/10' },
  1: { label: 'Weak', bar: 'bg-orange-500', text: 'text-orange-600 dark:text-orange-400', ring: 'bg-orange-500/10' },
  2: { label: 'Fair', bar: 'bg-amber-500', text: 'text-amber-600 dark:text-amber-400', ring: 'bg-amber-500/10' },
  3: { label: 'Strong', bar: 'bg-lime-500', text: 'text-lime-600 dark:text-lime-400', ring: 'bg-lime-500/10' },
  4: { label: 'Very strong', bar: 'bg-emerald-500', text: 'text-emerald-600 dark:text-emerald-400', ring: 'bg-emerald-500/10' },
}

export const CRACK_SCENARIOS = [
  {
    key: 'onlineThrottled',
    title: 'Online, throttled',
    hint: '100 guesses / hour — a login form with rate limiting.',
  },
  {
    key: 'onlineNoThrottling',
    title: 'Online, unthrottled',
    hint: '10 guesses / second — a misconfigured endpoint.',
  },
  {
    key: 'offlineSlowHashing',
    title: 'Offline, slow hash',
    hint: '10K/s — leaked database hashed with bcrypt/argon2.',
  },
  {
    key: 'offlineFastHashing',
    title: 'Offline, fast hash',
    hint: '10B/s — leaked database hashed with fast MD5/SHA-1.',
  },
]
